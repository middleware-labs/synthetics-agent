package worker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	reflectpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
)

func buildCredentials(skipVerify bool, caCerts, clientCert, clientKey, serverName string) (credentials.TransportCredentials, error) {
	var cfg tls.Config

	if clientCert != "" && clientKey != "" {
		keyPair, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls client cert/key pair. error=%v", err)
		}
		cfg.Certificates = []tls.Certificate{keyPair}
	}

	if skipVerify {
		cfg.InsecureSkipVerify = true
	} else if caCerts != "" {
		// override system roots
		rootCAs := x509.NewCertPool()
		pem, err := os.ReadFile(caCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to load root CA certificates from file (%s) error=%v", caCerts, err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no root CA certs parsed from file %s", caCerts)
		}
		cfg.RootCAs = rootCAs
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	return credentials.NewTLS(&cfg), nil
}

func expandGRPCError(err error, c SyntheticsModelCustom) error {
	if stat, ok := status.FromError(err); ok && stat.Code() == codes.Unimplemented {
		return fmt.Errorf("error: this server does not implement the : %s", stat.Message())
	} else if stat, ok := status.FromError(err); ok && stat.Code() == codes.DeadlineExceeded {
		return fmt.Errorf("timeout: health rpc did not complete within %v", time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)
	} else if stat.Code() != codes.OK {
		return fmt.Errorf("error: rpc failed, status is not OK %+v", err)
	}
	return err
}

func processError(err error, c SyntheticsModelCustom, timers map[string]float64) {
	assertions := make([]map[string]string, 0)
	for _, a := range c.Request.Assertions.GRPC.Cases {
		assertions = append(assertions, map[string]string{
			"status": string(reqStatusFail),
			"reason": "previous step failed",
			"actual": "N/A",
			"type":   a.Type,
		})
	}

	resultStr, _ := json.Marshal(assertions)
	attrs := pcommon.NewMap()
	attrs.PutStr("assertions", string(resultStr))
	FinishCheckRequest(c, string(reqStatusError), err.Error(), timers, attrs)
}

// check type grpc health
func processGRPCHealthCheck(ctx context.Context, conn *grpc.ClientConn,
	c SyntheticsModelCustom, timers map[string]float64) error {
	var respHeaders metadata.MD
	var respTrailers metadata.MD

	rpcCtx, rpcCancel := context.WithTimeout(ctx, time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)
	defer rpcCancel()
	md := metadata.MD{}
	for _, v := range c.Request.GRPCPayload.Metadata {
		md.Set(v.Name, v.Value)
	}

	rpcCtx = metadata.NewOutgoingContext(rpcCtx, md)

	rpcStart := time.Now()
	resp, err := healthpb.NewHealthClient(conn).Check(rpcCtx, &healthpb.HealthCheckRequest{Service: ""},
		grpc.Header(&respHeaders), grpc.Trailer(&respTrailers))
	timers["duration"] = timeInMs(time.Since(rpcStart))
	if err != nil {
		return expandGRPCError(err, c)
	}

	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("service unhealthy (responded with %q)", resp.GetStatus().String())
	}
	return nil
}

// check type grpc behaviour
func processGRPCBehaviourCheck(ctx context.Context, conn *grpc.ClientConn,
	c SyntheticsModelCustom, timers map[string]float64) (metadata.MD, error) {
	var respHeaders metadata.MD
	var respTrailers metadata.MD
	rpcStart := time.Now()

	ty := c.Request.GRPCPayload.ServiceDefinition
	_start := time.Now()

	svc, mth := parseSymbol(c.Request.GRPCPayload.MethodSelection) // "helloworld.Greeter/SayHello"

	var fsd *desc.FileDescriptor
	if ty == "reflection" {
		rpcCtx, _ := context.WithTimeout(ctx, time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)
		refClient := grpcreflect.NewClientV1Alpha(rpcCtx, reflectpb.NewServerReflectionClient(conn))

		clientSymbol, err := refClient.FileContainingSymbol(svc)
		if err != nil {
			return respTrailers, fmt.Errorf("reflection method not found: %v", err)
		} else {
			fsd = clientSymbol
		}
	} else {
		f, _ := os.CreateTemp(os.TempDir(), "proto_file.proto")
		_, _ = f.Write([]byte(c.Request.GRPCPayload.ProtoFileContent))
		_ = f.Close()

		p := protoparse.Parser{
			InferImportPaths:      false,
			IncludeSourceCodeInfo: false,
		}

		fds, err := p.ParseFiles(f.Name())
		if err != nil {
			return respTrailers, fmt.Errorf("could not parse given files: %v", err)
		}

		if len(fds) == 0 {
			return respTrailers, fmt.Errorf("no file descriptor found")
		}

		if len(fds) > 0 {
			fsd = fds[0]
		}
	}

	for _, fSrv := range fsd.GetServices() {
		fmt.Printf("ServiceName: %s\n", fSrv.GetFullyQualifiedName())
		for _, mtd := range fSrv.GetMethods() {
			fmt.Printf("Method: %s\n", mtd.GetFullyQualifiedName())
		}
	}

	dsc := fsd.FindSymbol(svc)

	if dsc == nil {
		timers["duration"] = timeInMs(time.Since(_start))
		return respTrailers, fmt.Errorf("service not found %s", svc)
	} else {
		sd, ok := dsc.(*desc.ServiceDescriptor)
		if !ok {
			return respTrailers, fmt.Errorf("symbol %q is not a service", svc)
		}
		mtd := sd.FindMethodByName(mth)
		if mtd == nil {
			return respTrailers, fmt.Errorf("service %q does not include a method named %q", svc, mth)
		} else {
			timers["duration_resolve"] = timeInMs(time.Since(rpcStart))

			var ext dynamic.ExtensionRegistry
			msgFactory := dynamic.NewMessageFactoryWithExtensionRegistry(&ext)

			if mtd.IsClientStreaming() || mtd.IsServerStreaming() {
				return respTrailers, fmt.Errorf("streaming grpc calls are not supported")
			} else {
				rdr := strings.NewReader(c.Request.GRPCPayload.Message)
				var msg json.RawMessage
				deErr := json.NewDecoder(rdr).Decode(&msg)
				if deErr != nil {
					return respTrailers, fmt.Errorf("json decode failed %v", deErr)
				} else {
					unmarshaler := jsonpb.Unmarshaler{AllowUnknownFields: true}
					req := msgFactory.NewMessage(mtd.GetInputType())

					uErr := unmarshaler.Unmarshal(bytes.NewReader(msg), req)
					if uErr != nil {
						return respTrailers, fmt.Errorf("unmarshaler.Unmarshal failed %v", uErr)
					}

					rpcStart = time.Now()

					stub := grpcdynamic.NewStubWithMessageFactory(conn, msgFactory)
					resp, ivErr := stub.InvokeRpc(ctx, mtd, req,
						grpc.Trailer(&respTrailers), grpc.Header(&respHeaders))

					if ivErr != nil {
						return respTrailers, expandGRPCError(ivErr, c)
					}

					jsm := jsonpb.Marshaler{Indent: "  "}
					_, mErr := jsm.MarshalToString(resp)
					timers["duration"] = timeInMs(time.Since(rpcStart))
					if mErr != nil {
						return respTrailers, fmt.Errorf("resp msg decode failed %v", mErr)
					}

				}
			}
		}
	}

	return respTrailers, nil
}

func CheckGrpcRequest(c SyntheticsModelCustom) {
	timers := map[string]float64{
		"duration":            0,
		"duration_connection": 0,
		"duration_resolve":    0,
	}
	assertions := make([]map[string]string, 0)

	ctx, _ := context.WithCancel(context.Background())

	opts := make([]grpc.DialOption, 0)

	if c.Request.GRPCPayload.Certificate != "" && c.Request.GRPCPayload.PrivateKey != "" {
		cred, err := buildCredentials(c.Request.GRPCPayload.IgnoreServerCertificateError, "", c.Request.GRPCPayload.Certificate, c.Request.GRPCPayload.PrivateKey, "")
		if err != nil {
			newErr := fmt.Errorf("failed to initialize tls credentials: %v", err)
			processError(newErr, c, timers)
			return
		}
		opts = append(opts, grpc.WithTransportCredentials(cred))
	} else {
		/*roots, err := x509.SystemCertPool()
		if err != nil {
			log.Printf("root certificates error  %v", roots)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:            roots,
			InsecureSkipVerify: true,
		})))*/

		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opts = append(opts,
		grpc.WithCompressor(grpc.NewGZIPCompressor()),
		grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
	)

	_start := time.Now()

	dialCtx, _ := context.WithTimeout(ctx, time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)

	conn, err := grpc.DialContext(dialCtx, c.Endpoint+":"+c.Request.Port, opts...)
	if err != nil {
		newErr := fmt.Errorf("did not connect: %v", err)
		processError(newErr, c, timers)
		return
	}

	defer conn.Close()

	timers["duration_connection"] = timeInMs(time.Since(_start))

	var respStr string
	var respTrailers metadata.MD

	if c.Request.GRPCPayload.CheckType == "health" {
		err = processGRPCHealthCheck(ctx, conn, c, timers)
	} else {
		respTrailers, err = processGRPCBehaviourCheck(ctx, conn, c, timers)
	}

	if err != nil {
		processError(err, c, timers)
		return
	}

	for _, assert := range c.Request.Assertions.GRPC.Cases {
		ck := map[string]string{
			"type":   assert.Type,
			"status": "PASS",
			"reason": "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") +
				" " + fmt.Sprintf("%v", assert.Config.Value),
		}

		switch assert.Type {
		case "response_time":
			ck["actual"] = fmt.Sprintf("%v", timers["duration"])
			if !assertInt(int64(timers["duration"]), assert) {
				ck["status"] = "FAIL"
				err = fmt.Errorf("duration did not match with condition")
			}
			assertions = append(assertions, ck)

		case "grpc_response":
			ck["actual"] = respStr
			if !assertString(respStr, assert) {
				ck["status"] = "FAIL"
				err = fmt.Errorf("response message didn't matched with condition")
			}
			assertions = append(assertions, ck)

		case "grpc_metadata":
			actual := strings.Join(respTrailers.Get(assert.Config.Target), "\n")
			ck["actual"] = actual
			if !assertString(actual, assert) {
				ck["status"] = "FAIL"
				err = fmt.Errorf("metadata message did not match with condition")
			}
			assertions = append(assertions, ck)
		}
	}

	status := reqStatusOK
	message := ""
	if err != nil {
		status = reqStatusFail
		message = err.Error()
	}
	resultStr, _ := json.Marshal(assertions)

	attrs := pcommon.NewMap()
	attrs.PutStr("assertions", string(resultStr))

	FinishCheckRequest(c, string(status), message, timers, attrs)
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
