package grpcchecker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

type GRPCClientDialOptions struct {
	ctx          context.Context
	target       string
	timeoutSec   float64
	keepaliveSec float64
	maxMsgSize   int
	creds        credentials.TransportCredentials
	network      string // tcp or unix
}

var (
	checkStatusOk   = "OK"
	checkStatusFail = "FAIL"
	checkStatusErr  = "ERROR"
)

func blockingDial(ctx context.Context, network, address string, creds credentials.TransportCredentials, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	result := make(chan interface{}, 1)

	writeResult := func(res interface{}) {
		select {
		case result <- res:
		default:
		}
	}

	if creds != nil {
		creds = &errSignalingCreds{
			TransportCredentials: creds,
			writeResult:          writeResult,
		}
	}
	dialer := func(ctx context.Context, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			writeResult(err)
		}
		return conn, err
	}

	go func() {
		opts = append([]grpc.DialOption{grpc.FailOnNonTempDialError(true)}, opts...)
		opts = append(opts, grpc.WithBlock(), grpc.WithContextDialer(dialer))

		if creds == nil {
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		} else {
			opts = append(opts, grpc.WithTransportCredentials(creds))
		}
		conn, err := grpc.DialContext(ctx, address, opts...)
		var res interface{}
		if err != nil {
			res = err
		} else {
			res = conn
		}
		writeResult(res)
	}()

	select {
	case res := <-result:
		if conn, ok := res.(*grpc.ClientConn); ok {
			return conn, nil
		}
		return nil, res.(error)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func grpcClient(arg GRPCClientDialOptions) (*grpc.ClientConn, error) {
	dialTime := 10 * time.Second
	if arg.timeoutSec > 0 {
		dialTime = time.Duration(arg.timeoutSec * float64(time.Second))
	}
	ctx, cancel := context.WithTimeout(arg.ctx, dialTime)
	defer cancel()
	var opts []grpc.DialOption
	if arg.keepaliveSec > 0 {
		timeout := time.Duration(arg.keepaliveSec * float64(time.Second))
		opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    timeout,
			Timeout: timeout,
		}))
	}
	if arg.maxMsgSize > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(arg.maxMsgSize)))
	}
	network := "tcp"
	if arg.network != "" {
		network = arg.network
	}
	cc, err := blockingDial(ctx, network, arg.target, arg.creds, opts...)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

func buildTlsCredentials(caCerts, clientCert, clientKey, serverName string) (credentials.TransportCredentials, error) {
	var cfg tls.Config

	if clientCert != "" && clientKey != "" {
		keyPair, err := tls.X509KeyPair([]byte(clientCert),
			[]byte(clientKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load tls client cert/key pair. error=%v", err)
		}
		cfg.Certificates = []tls.Certificate{keyPair}
	}

	if caCerts != "" {
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

type CheckerOptions struct {
	Ctx                   context.Context
	IgnoreCert            bool
	Certificate           string
	PrivateKey            string
	Target                string
	Reflection            bool
	ServiceMethodSymbol   string
	ServiceRequestMessage string
	TimeoutSec            int
	ProtoFileContent      string
	Metadata              []string
}
type CheckerResponse struct {
	Error        error
	Status       string
	MessageRPC   string
	ConnTs       float64
	InvokeTs     float64
	Reflections  map[string]interface{}
	RespTrailers metadata.MD
}

func RequestRPC(ckr CheckerOptions) CheckerResponse {
	_start := time.Now()
	ctx := ckr.Ctx
	var creds credentials.TransportCredentials
	if !ckr.IgnoreCert {
		createCred, credErr := buildTlsCredentials(
			"",
			ckr.Certificate,
			ckr.PrivateKey,
			"",
		)
		if credErr != nil {
			return CheckerResponse{
				Error:  credErr,
				Status: checkStatusErr,
				ConnTs: float64(time.Since(_start)) / float64(time.Millisecond),
			}
		}
		creds = createCred
	}

	argDial := GRPCClientDialOptions{
		ctx:        ckr.Ctx,
		target:     ckr.Target,
		timeoutSec: float64(ckr.TimeoutSec),
		creds:      creds,
		network:    "tcp",
	}

	var cc *grpc.ClientConn
	var descSource DescriptorSource
	var refClient *grpcreflect.Client
	var fileSource DescriptorSource

	if ckr.ProtoFileContent != "" {
		var err error
		fileSource, err = DescriptorSourceFromProtoFileContent(ckr.ProtoFileContent)
		if err != nil {
			return CheckerResponse{
				Error:  err,
				Status: checkStatusErr,
				ConnTs: float64(time.Since(_start)) / float64(time.Millisecond),
			}
		}
	}

	addlHeaders := make([]string, 0)
	reflHeaders := make([]string, 0)
	rpcHeaders := make([]string, 0)
	if len(ckr.Metadata) > 0 {
		rpcHeaders = ckr.Metadata
	}

	md := MetadataFromHeaders(append(addlHeaders, reflHeaders...))
	refCtx := metadata.NewOutgoingContext(ctx, md)
	cc, dialErr := grpcClient(argDial)
	if dialErr != nil {
		return CheckerResponse{
			Error:  dialErr,
			Status: checkStatusErr,
			ConnTs: float64(time.Since(_start)) / float64(time.Millisecond),
		}
	}

	refClient = grpcreflect.NewClientAuto(refCtx, cc)
	reflSource := DescriptorSourceFromServer(ctx, refClient)
	if fileSource != nil {
		descSource = CompositeSource{reflSource, fileSource}
	} else {
		descSource = reflSource
	}

	reset := func() {
		if refClient != nil {
			refClient.Reset()
			refClient = nil
		}
		if cc != nil {
			cc.Close()
			cc = nil
		}
	}
	defer reset()

	cts := float64(time.Since(_start)) / float64(time.Millisecond)

	if ckr.Reflection {
		reflections := make(map[string]interface{}, 0)
		listSvc, _ := refClient.ListServices()
		for _, svc := range listSvc {
			fc, _ := refClient.FileContainingSymbol(svc)
			for _, fSrv := range fc.GetServices() {
				for _, mtd := range fSrv.GetMethods() {
					if strings.Contains(fSrv.GetFullyQualifiedName(), "grpc.reflection.") {
						continue
					}
					methodKey := fmt.Sprintf("%s/%s", fSrv.GetFullyQualifiedName(), mtd.GetName())
					fieldParams := make(map[string]interface{})
					method := fSrv.FindMethodByName(mtd.GetName())
					inputType := method.GetInputType()
					if inputType != nil {
						for _, field := range inputType.GetFields() {
							fieldParams[field.GetName()] = field.GetDefaultValue()
						}
					}
					reflections[methodKey] = fieldParams
				}
			}
		}
		return CheckerResponse{
			Status:      checkStatusOk,
			ConnTs:      cts,
			Reflections: reflections,
		}
	}

	if ckr.ServiceMethodSymbol == "" {

		_, err := descSource.FindSymbol(ckr.ServiceMethodSymbol)
		if err != nil {
			return CheckerResponse{
				Error:  fmt.Errorf("failed to resolve symbol %s", ckr.ServiceMethodSymbol),
				Status: checkStatusErr,
				ConnTs: cts,
			}
		}

		return CheckerResponse{
			Error:  fmt.Errorf("service method symbol is required"),
			Status: checkStatusFail,
			ConnTs: cts,
		}
	}

	var messageReader *strings.Reader
	if ckr.ServiceRequestMessage != "" {
		messageReader = strings.NewReader(fmt.Sprintf("%s", ckr.ServiceRequestMessage))
	}

	options := FormatOptions{
		EmitJSONDefaultFields: false,
		IncludeTextSeparator:  true,
		AllowUnknownFields:    false,
	}
	rf, formatter, err := RequestParserAndFormatter("json", descSource, messageReader, options)
	if err != nil {
		return CheckerResponse{
			Error:  fmt.Errorf("failed to construct request parser and formatter for %q: %v", "json", err),
			Status: checkStatusErr,
			ConnTs: cts,
		}
	}

	h := &DefaultEventHandler{
		Out:            os.Stdout,
		Formatter:      formatter,
		VerbosityLevel: 0,
	}

	rsp := dynamicInvokeRPC(ctx, descSource, cc, ckr.ServiceMethodSymbol, append(addlHeaders, rpcHeaders...), h, rf.Next)

	return CheckerResponse{
		Error:        rsp.Error,
		Status:       rsp.Status,
		ConnTs:       cts,
		InvokeTs:     rsp.InvokeTs,
		MessageRPC:   rsp.MessageRPC,
		RespTrailers: rsp.RespTrailers,
	}
}

type CompositeSource struct {
	reflection DescriptorSource
	file       DescriptorSource
}

func (cs CompositeSource) ListServices() ([]string, error) {
	return cs.reflection.ListServices()
}

func (cs CompositeSource) FindSymbol(fullyQualifiedName string) (desc.Descriptor, error) {
	d, err := cs.reflection.FindSymbol(fullyQualifiedName)
	if err == nil {
		return d, nil
	}
	return cs.file.FindSymbol(fullyQualifiedName)
}

func (cs CompositeSource) AllExtensionsForType(typeName string) ([]*desc.FieldDescriptor, error) {
	exts, err := cs.reflection.AllExtensionsForType(typeName)
	if err != nil {
		// On error fall back to file source
		return cs.file.AllExtensionsForType(typeName)
	}
	// Track the tag numbers from the reflection source
	tags := make(map[int32]bool)
	for _, ext := range exts {
		tags[ext.GetNumber()] = true
	}
	fileExts, err := cs.file.AllExtensionsForType(typeName)
	if err != nil {
		return exts, nil
	}
	for _, ext := range fileExts {
		// Prioritize extensions found via reflection
		if !tags[ext.GetNumber()] {
			exts = append(exts, ext)
		}
	}
	return exts, nil
}
