package grpcchecker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/grpcreflect"
	"github.com/middleware-labs/synthetics-agent/pkg/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"net"
	"os"
	"strings"
	"time"
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

func RequestRPC(c worker.SyntheticCheck) error {
	ctx, cnlFnc := context.WithCancel(context.Background())
	defer cnlFnc()

	var creds credentials.TransportCredentials
	if !c.Request.GRPCPayload.IgnoreServerCertificateError {
		createCred, credErr := buildTlsCredentials(
			"",
			c.Request.GRPCPayload.Certificate,
			c.Request.GRPCPayload.PrivateKey,
			"",
		)
		if credErr != nil {
			return credErr
		}
		creds = createCred
	}

	argDial := GRPCClientDialOptions{
		ctx:        ctx,
		target:     fmt.Sprintf("%s:%s", c.Endpoint, c.Request.Port),
		timeoutSec: float64(c.Expect.ResponseTimeLessThen),
		creds:      creds,
		network:    "tcp",
	}

	var cc *grpc.ClientConn
	var descSource DescriptorSource
	var refClient *grpcreflect.Client
	var fileSource DescriptorSource

	if c.Request.GRPCPayload.ProtoFileContent != "" {
		var err error
		fileSource, err = DescriptorSourceFromProtoFileContent(c.Request.GRPCPayload.ProtoFileContent)
		if err != nil {
			return err
		}
	}
	symbol := c.Request.GRPCPayload.MethodSelection
	addlHeaders := make([]string, 0)
	reflHeaders := make([]string, 0)
	rpcHeaders := make([]string, 0)
	for _, v := range c.Request.GRPCPayload.Metadata {
		rpcHeaders = append(rpcHeaders, fmt.Sprintf("%s: %s", v.Name, v.Value))
	}

	md := MetadataFromHeaders(append(addlHeaders, reflHeaders...))
	refCtx := metadata.NewOutgoingContext(ctx, md)
	cc, dialErr := grpcClient(argDial)
	if dialErr != nil {
		return dialErr
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

	reflectionResults := make(map[string]interface{}, 0)
	if c.Request.GRPCPayload.ServiceDefinition == "reflection" {
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
					reflectionResults[methodKey] = fieldParams
				}
			}
		}
		fmt.Printf("reflectionResults--->%+v\n", reflectionResults)
	} else {
		rdrProtoCnt := strings.NewReader(fmt.Sprintf("%s", c.Request.GRPCPayload.Message))

		options := FormatOptions{
			EmitJSONDefaultFields: false,
			IncludeTextSeparator:  true,
			AllowUnknownFields:    false,
		}
		rf, formatter, err := RequestParserAndFormatter("json", descSource, rdrProtoCnt, options)
		if err != nil {
			return fmt.Errorf("failed to construct request parser and formatter for %q: %v", "json", err)
		}

		h := &DefaultEventHandler{
			Out:            os.Stdout,
			Formatter:      formatter,
			VerbosityLevel: 0,
		}

		rsp := dynamicInvokeRPC(ctx, descSource, cc, symbol, append(addlHeaders, rpcHeaders...), h, rf.Next)
		fmt.Println("rsp.Status--->", rsp.Status)
		fmt.Println("rsp.MessageRPC--->", rsp.MessageRPC)
		fmt.Println("rsp.Error--->", rsp.Error)
	}

	return nil
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
