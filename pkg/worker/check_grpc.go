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

type grpcAssertion string

const (
	grpcResponseTime grpcAssertion = "response_time"
	grpcResponse     grpcAssertion = "grpc_response"
	grpcMetadata     grpcAssertion = "grpc_metadata"
)

func buildCredentials(skipVerify bool, caCerts, clientCert, clientKey,
	serverName string) (credentials.TransportCredentials, error) {
	var cfg tls.Config

	if clientCert != "" && clientKey != "" {
		keyPair, err := tls.X509KeyPair([]byte(clientCert),
			[]byte(clientKey))
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

func expandGRPCError(err error, c SyntheticCheck) error {
	if stat, ok := status.FromError(err); ok && stat.Code() == codes.Unimplemented {
		return fmt.Errorf("error: this server does not implement the : %s", stat.Message())
	} else if stat, ok := status.FromError(err); ok && stat.Code() == codes.DeadlineExceeded {
		return fmt.Errorf("timeout: health rpc did not complete within %v",
			time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)
	} else if stat.Code() != codes.OK {
		return fmt.Errorf("error: rpc failed, status is not OK %+v", err)
	}
	return err
}

func (checker *grpcChecker) processGRPCError(testStatus testStatus, c SyntheticCheck) {
	for _, a := range c.Request.Assertions.GRPC.Cases {
		checker.assertions = append(checker.assertions, map[string]string{
			"status": testStatusFail,
			"reason": "previous step failed",
			"actual": "N/A",
			"type":   a.Type,
		})
	}

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))
}

// check type grpc health
func (checker *grpcChecker) processGRPCHealthCheck(ctx context.Context,
	healthClient healthpb.HealthClient) testStatus {

	var respHeaders metadata.MD
	var respTrailers metadata.MD

	c := checker.c
	testStatus := testStatus{
		status: testStatusOK,
	}

	rpcCtx, rpcCancel := context.WithTimeout(ctx, time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)
	defer rpcCancel()
	md := metadata.MD{}
	for _, v := range c.Request.GRPCPayload.Metadata {
		md.Set(v.Name, v.Value)
	}

	rpcCtx = metadata.NewOutgoingContext(rpcCtx, md)

	rpcStart := time.Now()
	resp, err := healthClient.Check(rpcCtx,
		&healthpb.HealthCheckRequest{Service: ""},
		grpc.Header(&respHeaders), grpc.Trailer(&respTrailers))

	checker.timers["duration"] = timeInMs(time.Since(rpcStart))
	if err != nil {
		err = expandGRPCError(err, c)
		testStatus.status = testStatusError
		testStatus.msg = err.Error()
		return testStatus
	}

	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		testStatus.status = testStatusFail
		testStatus.msg = fmt.Sprintf("service unhealthy (responded with %q)",
			resp.GetStatus().String())
	}
	return testStatus
}

// check type grpc behaviour
func processGRPCBehaviourCheck(ctx context.Context, conn *grpc.ClientConn,
	c SyntheticCheck, timers map[string]float64) (metadata.MD, testStatus) {
	var respHeaders metadata.MD
	var respTrailers metadata.MD
	testStatus := testStatus{
		status: testStatusOK,
	}

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
			testStatus.status = testStatusError
			testStatus.msg = fmt.Sprintf("reflection method not found: %v", err)
			return respTrailers, testStatus
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
			testStatus.status = testStatusError
			testStatus.msg = fmt.Sprintf("could not parse given files: %v", err)
			return respTrailers, testStatus
		}

		if len(fds) == 0 {
			testStatus.status = testStatusError
			testStatus.msg = "no file descriptor found"
			return respTrailers, testStatus
		}

		if len(fds) > 0 {
			fsd = fds[0]
		}
	}

	dsc := fsd.FindSymbol(svc)

	if dsc == nil {
		timers["duration"] = timeInMs(time.Since(_start))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("service not found %s", svc)
		return respTrailers, testStatus
	}

	sd, ok := dsc.(*desc.ServiceDescriptor)
	if !ok {
		timers["duration"] = timeInMs(time.Since(_start))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("symbol %q is not a service", svc)
		return respTrailers, testStatus
	}
	mtd := sd.FindMethodByName(mth)
	if mtd == nil {
		timers["duration"] = timeInMs(time.Since(_start))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("service %q does not include a method named %q", svc, mth)
		return respTrailers, testStatus
	}

	timers["duration_resolve"] = timeInMs(time.Since(rpcStart))

	var ext dynamic.ExtensionRegistry
	msgFactory := dynamic.NewMessageFactoryWithExtensionRegistry(&ext)

	if mtd.IsClientStreaming() || mtd.IsServerStreaming() {
		testStatus.status = testStatusError
		testStatus.msg = "streaming grpc calls are not supported"
		return respTrailers, testStatus
	}

	rdr := strings.NewReader(c.Request.GRPCPayload.Message)
	var msg json.RawMessage
	deErr := json.NewDecoder(rdr).Decode(&msg)
	if deErr != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("json decode failed %v", deErr)
		return respTrailers, testStatus
	}

	unmarshaler := jsonpb.Unmarshaler{AllowUnknownFields: true}
	req := msgFactory.NewMessage(mtd.GetInputType())

	uErr := unmarshaler.Unmarshal(bytes.NewReader(msg), req)
	if uErr != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("unmarshaler.Unmarshal failed %v", uErr)
		return respTrailers, testStatus
	}

	rpcStart = time.Now()

	stub := grpcdynamic.NewStubWithMessageFactory(conn, msgFactory)
	resp, ivErr := stub.InvokeRpc(ctx, mtd, req,
		grpc.Trailer(&respTrailers), grpc.Header(&respHeaders))

	if ivErr != nil {
		testStatus.status = testStatusError
		testStatus.msg = expandGRPCError(ivErr, c).Error()
		return respTrailers, testStatus
	}

	jsm := jsonpb.Marshaler{Indent: "  "}
	_, mErr := jsm.MarshalToString(resp)
	timers["duration"] = timeInMs(time.Since(rpcStart))
	if mErr != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("resp msg marshal failed %v", mErr)
		return respTrailers, testStatus
	}

	return respTrailers, testStatus
}

type grpcChecker struct {
	c            SyntheticCheck
	respStr      string
	respTrailers metadata.MD
	timers       map[string]float64
	testBody     map[string]interface{}
	assertions   []map[string]string
	attrs        pcommon.Map
}

func newGRPCChecker(c SyntheticCheck) protocolChecker {
	return &grpcChecker{
		c:          c,
		respStr:    "",
		timers:     make(map[string]float64),
		testBody:   make(map[string]interface{}),
		assertions: make([]map[string]string, 0),
		attrs:      pcommon.NewMap(),
	}
}

func (checker *grpcChecker) fillGRPCAssertions() testStatus {
	c := checker.c
	testStatus := testStatus{
		status: testStatusOK,
	}

	for _, assert := range c.Request.Assertions.GRPC.Cases {
		ck := map[string]string{
			"type":   assert.Type,
			"status": testStatusPass,
			"reason": "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") +
				" " + fmt.Sprintf("%v", assert.Config.Value),
		}

		switch assert.Type {
		case string(grpcResponseTime):
			ck["actual"] = fmt.Sprintf("%v", checker.timers["duration"])
			if !assertInt(int64(checker.timers["duration"]), assert) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFail
				testStatus.msg = "duration did not match withthe condition"
			}
			checker.assertions = append(checker.assertions, ck)

		case string(grpcResponse):
			ck["actual"] = checker.respStr
			if !assertString(checker.respStr, assert) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFail
				testStatus.msg = "response message didn't matched with the condition"
			}

			checker.assertions = append(checker.assertions, ck)

		case string(grpcMetadata):
			actual := strings.Join(checker.respTrailers.Get(assert.Config.Target), "\n")
			ck["actual"] = actual
			if !assertString(actual, assert) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFail
				testStatus.msg = "metadata message did not match with the condition"
			}
			checker.assertions = append(checker.assertions, ck)
		}
	}
	return testStatus
}

func (checker *grpcChecker) check() testStatus {
	c := checker.c
	ctx, _ := context.WithCancel(context.Background())

	opts := make([]grpc.DialOption, 0)
	testStatus := testStatus{
		status: testStatusOK,
	}

	if c.Request.GRPCPayload.Certificate != "" && c.Request.GRPCPayload.PrivateKey != "" {
		cred, err := buildCredentials(c.Request.GRPCPayload.IgnoreServerCertificateError,
			"", c.Request.GRPCPayload.Certificate, c.Request.GRPCPayload.PrivateKey, "")
		if err != nil {
			testStatus.status = testStatusFail
			testStatus.msg = fmt.Sprintf("failed to initialize tls credentials: %v", err)
			checker.processGRPCError(testStatus, c)
			return testStatus
		}
		opts = append(opts, grpc.WithTransportCredentials(cred))
	} else {
		/*roots, err := x509.SystemCertPool()
		if err != nil {
			slog.Error("failed to read system root certificates", slog.Error(err))
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
		testStatus.status = testStatusFail
		testStatus.msg = fmt.Sprintf("did not connect: %v", err)
		checker.processGRPCError(testStatus, c)
		return testStatus
	}

	defer conn.Close()
	healthClient := healthpb.NewHealthClient(conn)

	checker.timers["duration_connection"] = timeInMs(time.Since(_start))

	if c.Request.GRPCPayload.CheckType == "health" {
		testStatus = checker.processGRPCHealthCheck(ctx, healthClient)
	} else {
		checker.respTrailers, testStatus = processGRPCBehaviourCheck(ctx, conn, c, checker.timers)
	}

	if testStatus.status != testStatusOK {
		checker.processGRPCError(testStatus, c)
		return testStatus
	}

	testStatus = checker.fillGRPCAssertions()
	if testStatus.status != testStatusOK {
		checker.processGRPCError(testStatus, c)
		return testStatus
	}

	resultStr, _ := json.Marshal(checker.assertions)

	checker.attrs.PutStr("assertions", string(resultStr))

	return testStatus
}

func (checker *grpcChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *grpcChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *grpcChecker) getTestResponseBody() map[string]interface{} {
	return checker.testBody
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
