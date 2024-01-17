package grpccheckerhelper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jhump/protoreflect/desc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

var (
	checkStatusOk   = "OK"
	checkStatusFail = "FAIL"
	checkStatusErr  = "ERROR"
)
type ClientDialOptions struct {
	Target        string
	TimeoutSec    float64
	KeepaliveSec  float64
	MaxMsgSize    int
	Network       string // tcp or unix
	CertsCA       string
	Certificate   string
	PrivateKey    string
	ServerNameTLS string
	IgnoreCert    bool
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
func BuildCredentialsTLS(caCerts, clientCert, clientKey, serverName string) (credentials.TransportCredentials, error) {
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
func NewClientGRPC(ctx context.Context, arg ClientDialOptions) (*grpc.ClientConn, error) {
	dialTime := 10 * time.Second
	network := "tcp"
	if arg.TimeoutSec > 0 {
		dialTime = time.Duration(arg.TimeoutSec * float64(time.Second))
	}
	ctx, cancel := context.WithTimeout(ctx, dialTime)
	defer cancel()
	var opts []grpc.DialOption
	if arg.KeepaliveSec > 0 {
		timeout := time.Duration(arg.KeepaliveSec * float64(time.Second))
		opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    timeout,
			Timeout: timeout,
		}))
	}
	if arg.MaxMsgSize > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(arg.MaxMsgSize)))
	}
	if arg.Network != "" {
		network = arg.Network
	}

	var creds credentials.TransportCredentials
	if !arg.IgnoreCert {
		createCred, credErr := BuildCredentialsTLS( arg.CertsCA, arg.Certificate, arg.PrivateKey, arg.ServerNameTLS )
		if credErr != nil {
			return nil, credErr
		}
		creds = createCred
	}

	clientConn, err := blockingDial(ctx, network, arg.Target, creds, opts...)
	if err != nil {
		return nil, err
	}
	return clientConn, nil
}

type CheckerResponse struct {
	Error        error
	Status       string
	MessageRPC   string
	ConnectionTs float64
	ConnectTs    float64
	ResolveTs    float64
	Reflections  map[string]interface{}
	RespTrailers metadata.MD
}

type CompositeSource struct {
	Reflection DescriptorSource
	File       DescriptorSource
}

func (cs CompositeSource) ListServices() ([]string, error) {
	return cs.Reflection.ListServices()
}

func (cs CompositeSource) FindSymbol(fullyQualifiedName string) (desc.Descriptor, error) {
	d, err := cs.Reflection.FindSymbol(fullyQualifiedName)
	if err == nil {
		return d, nil
	}
	return cs.File.FindSymbol(fullyQualifiedName)
}

func (cs CompositeSource) AllExtensionsForType(typeName string) ([]*desc.FieldDescriptor, error) {
	exts, err := cs.Reflection.AllExtensionsForType(typeName)
	if err != nil {
		// On error fall back to file source
		return cs.File.AllExtensionsForType(typeName)
	}
	// Track the tag numbers from the reflection source
	tags := make(map[int32]bool)
	for _, ext := range exts {
		tags[ext.GetNumber()] = true
	}
	fileExts, err := cs.File.AllExtensionsForType(typeName)
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
