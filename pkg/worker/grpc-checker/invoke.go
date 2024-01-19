package grpccheckerhelper

import (
	"context"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"strings"
	"time"
)

type RequestSupplier func(proto.Message) error

type InvokeResponse struct {
	Status       string
	MessageRPC   string
	Error        error
	ResolveTs    float64
	ConnectTs    float64
	RespTrailers metadata.MD
}

func DynamicInvokeRPC(ctx context.Context, source DescriptorSource, ch grpcdynamic.Channel, methodName string, headers []string, handler *DefaultEventHandler, requestData RequestSupplier) InvokeResponse {
	rsp := InvokeResponse{
		Status:     checkStatusFail,
		MessageRPC: "",
		Error:      nil,
	}
	rspRslv := func(req InvokeResponse) InvokeResponse {
		req.ResolveTs = float64(time.Since(handler.ConnectStart)) / float64(time.Millisecond)
		return req
	}
	md := MetadataFromHeaders(headers)

	svc, mth := parseSymbol(methodName)
	if svc == "" || mth == "" {
		rsp.Status = checkStatusFail
		rsp.Error = fmt.Errorf("given method name %q is not in expected format: 'service/method' or 'service.method'", methodName)
		return rspRslv(rsp)
	}

	dsc, err := source.FindSymbol(svc)
	if err != nil {
		rsp.Status = checkStatusErr
		errStatus, hasStatus := status.FromError(err)
		switch {
		case hasStatus && isNotFoundError(err):
			rsp.Error = status.Errorf(errStatus.Code(), "target server does not expose service %q: %s", svc, errStatus.Message())
			return rspRslv(rsp)
		case hasStatus:
			rsp.Error = status.Errorf(errStatus.Code(), "failed to query for service descriptor %q: %s", svc, errStatus.Message())
			return rspRslv(rsp)
		case isNotFoundError(err):
			rsp.Error = fmt.Errorf("target server does not expose service %q", svc)
			return rspRslv(rsp)
		}
		rsp.Error = fmt.Errorf("failed to query for service descriptor %q: %v", svc, err)
		return rspRslv(rsp)
	}
	sd, ok := dsc.(*desc.ServiceDescriptor)
	if !ok {
		rsp.Error = fmt.Errorf("target server does not expose service %q", svc)
		return rspRslv(rsp)
	}

	mtd := sd.FindMethodByName(mth)
	if mtd == nil {
		rsp.Error = fmt.Errorf("service %q does not include a method named %q", svc, mth)
		return rspRslv(rsp)
	}
	_, err = GetDescriptorText(mtd, nil)
	if err != nil {
		rsp.Status = checkStatusErr
		rsp.Error = fmt.Errorf("failed to get descriptor text: %v", err)
		return rspRslv(rsp)
	}

	var ext dynamic.ExtensionRegistry
	alreadyFetched := map[string]bool{}
	if err = fetchAllExtensions(source, &ext, mtd.GetInputType(), alreadyFetched); err != nil {
		rsp.Status = checkStatusErr
		rsp.Error = fmt.Errorf("error resolving server extensions for message %s: %v", mtd.GetInputType().GetFullyQualifiedName(), err)
		return rspRslv(rsp)
	}
	if err = fetchAllExtensions(source, &ext, mtd.GetOutputType(), alreadyFetched); err != nil {
		rsp.Status = checkStatusErr
		rsp.Error = fmt.Errorf("error resolving server extensions for message %s: %v", mtd.GetOutputType().GetFullyQualifiedName(), err)
		return rspRslv(rsp)
	}

	msgFactory := dynamic.NewMessageFactoryWithExtensionRegistry(&ext)
	req := msgFactory.NewMessage(mtd.GetInputType())

	ctx = metadata.NewOutgoingContext(ctx, md)

	stub := grpcdynamic.NewStubWithMessageFactory(ch, msgFactory)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if mtd.IsClientStreaming() && mtd.IsServerStreaming() || mtd.IsClientStreaming() || mtd.IsServerStreaming() {
		rsp.Error = fmt.Errorf("method %q is a streaming RPC, but this command does not support streaming RPCs", mtd.GetFullyQualifiedName())
		return rspRslv(rsp)
	}

	err = requestData(req)
	if err != nil && err != io.EOF {
		rsp.Status = checkStatusErr
		rsp.Error = fmt.Errorf("error getting request data: %v", err)
		return rspRslv(rsp)
	}
	if err != io.EOF {
		err := requestData(req)
		if err == nil {
			rsp.Status = checkStatusFail
			rsp.Error = fmt.Errorf("method %q is a unary RPC, but request data contained more than 1 message", mtd.GetFullyQualifiedName())
			return rspRslv(rsp)
		} else if err != io.EOF {
			rsp.Error = fmt.Errorf("error getting request data: %v", err)
			return rspRslv(rsp)
		}
	}

	// Now we can actually invoke the RPC!
	rsp.ConnectTs = float64(time.Since(handler.ConnectStart)) / float64(time.Millisecond)
	resolveStart := time.Now()

	var respHeaders metadata.MD
	var respTrailers metadata.MD
	resp, err := stub.InvokeRpc(ctx, mtd, req, grpc.Trailer(&respTrailers), grpc.Header(&respHeaders))
	stat, ok := status.FromError(err)
	rsp.RespTrailers = respTrailers
	if !ok {
		rsp.Status = checkStatusErr
		rsp.ResolveTs = float64(time.Since(resolveStart)) / float64(time.Millisecond)
		rsp.Error = fmt.Errorf("grpc call for %q failed: %v", mtd.GetFullyQualifiedName(), err)
		return rsp
	}

	if stat.Code() == codes.OK {
		msg, fErr := handler.Formatter(resp)
		rsp.ResolveTs = float64(time.Since(resolveStart)) / float64(time.Millisecond)
		rsp.MessageRPC = msg
		rsp.Error = fErr
		rsp.Status = checkStatusOk
		if fErr != nil {
			rsp.Status = checkStatusErr
		}
		return rsp
	}
	return rsp
}

type notFoundError string

func notFound(kind, name string) error {
	return notFoundError(fmt.Sprintf("%s not found: %s", kind, name))
}

func (e notFoundError) Error() string {
	return string(e)
}

func isNotFoundError(err error) bool {
	if grpcreflect.IsElementNotFoundError(err) {
		return true
	}
	_, ok := err.(notFoundError)
	return ok
}

func parseSymbol(svcAndMethod string) (string, string) {
	pos := strings.LastIndex(svcAndMethod, "/")
	if pos < 0 {
		pos = strings.LastIndex(svcAndMethod, ".")
		if pos < 0 {
			return "", ""
		}
	}
	return svcAndMethod[:pos], svcAndMethod[pos+1:]
}
