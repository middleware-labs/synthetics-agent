package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jhump/protoreflect/grpcreflect"
	grpccheckerhelper "github.com/middleware-labs/synthetics-agent/pkg/worker/grpc-checker"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc/metadata"
)

type grpcAssertion string

const (
	grpcResponseTime grpcAssertion = "response_time"
	grpcResponse     grpcAssertion = "grpc_response"
	grpcMetadata     grpcAssertion = "grpc_metadata"
	defaultGrpcPort                = "50051"
)

func (checker *grpcChecker) processGRPCError(testStatus testStatus, c SyntheticCheck) {
	for _, a := range c.Request.Assertions.GRPC.Cases {
		checker.assertions = append(checker.assertions, map[string]string{
			"status": testStatusFail,
			"reason": fmt.Sprintf("should be %s %v", strings.ReplaceAll(a.Config.Operator, "_", " "), a.Config.Value),
			"actual": "N/A",
			"type":   a.Type,
		})
	}

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))
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
	if strings.TrimSpace(c.Request.Port) == "" {
		c.Request.Port = defaultGrpcPort
	}
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
			"status": testStatusOK,
			"reason": fmt.Sprintf("should be %s %v", strings.ReplaceAll(assert.Config.Operator, "_", " "), assert.Config.Value),
			"actual": "N/A",
		}

		switch assert.Type {
		case string(grpcResponseTime):
			ck["actual"] = fmt.Sprintf("%v", checker.timers["duration"])
			if !assertFloat(checker.timers["duration"], assert) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFail
				testStatus.msg = "duration did not match with the condition"
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

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))
	return testStatus
}
func (checker *grpcChecker) healthCheckGRPC(ctx context.Context, cc *grpc.ClientConn) testStatus {
	cnts := time.Now()
	newMD := metadata.MD{}
	for _, v := range checker.c.Request.GRPCPayload.Metadata {
		newMD.Set(v.Name, v.Value)
	}
	healthClient := healthpb.NewHealthClient(cc)
	rpcCtx := metadata.NewOutgoingContext(ctx, newMD)
	checker.timers["connect"] = timeInMs(time.Since(cnts))
	_d0 := time.Now()
	resp, err := healthClient.Check(rpcCtx,
		&healthpb.HealthCheckRequest{Service: checker.c.Request.GRPCPayload.Service},
		//grpc.Header(&newMD), grpc.Trailer(&newMD),
	)

	checker.timers["resolve"] = timeInMs(time.Since(_d0))

	if err != nil {
		t := testStatus{
			status: testStatusError,
			msg:    err.Error(),
		}
		checker.testBody["error"] = t.msg
		checker.processGRPCError(t, checker.c)
		return t
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t := testStatus{
			status: testStatusFail,
			msg:    fmt.Sprintf("service unhealthy (responded with %q)", resp.GetStatus().String()),
		}
		checker.testBody["error"] = t.msg
		checker.processGRPCError(t, checker.c)
		return t
	}
	return testStatus{
		status: testStatusOK,
	}
}
func (checker *grpcChecker) reflectionCheckGRPC(ctx context.Context, cc *grpc.ClientConn) testStatus {
	var (
		refClient   *grpcreflect.Client
		reflections = make(map[string]interface{}, 0)
		cnts        = time.Now()
		addlHeaders = make([]string, 0)
		reflHeaders = make([]string, 0)
	)

	metaData := grpccheckerhelper.MetadataFromHeaders(append(addlHeaders, reflHeaders...))
	refCtx := metadata.NewOutgoingContext(ctx, metaData)
	refClient = grpcreflect.NewClientAuto(refCtx, cc)

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

	listSvc, err := refClient.ListServices()
	if err != nil {
		t := testStatus{
			status: testStatusError,
			msg:    err.Error(),
		}
		checker.processGRPCError(t, checker.c)
		return t
	}
	checker.timers["connect"] = timeInMs(time.Since(cnts))
	d0 := time.Now()
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
	checker.timers["resolve"] = timeInMs(time.Since(d0))
	checker.testBody["reflections"] = reflections

	return testStatus{
		status: testStatusOK,
	}
}
func (checker *grpcChecker) behaviourCheckGRPC(ctx context.Context, cc *grpc.ClientConn) testStatus {

	var (
		descSource  grpccheckerhelper.DescriptorSource
		refClient   *grpcreflect.Client
		fileSource  grpccheckerhelper.DescriptorSource
		c           = checker.c
		_d0         = time.Now()
		addlHeaders = make([]string, 0)
		rpcHeaders  = make([]string, 0)
		symbol      = c.Request.GRPCPayload.MethodSelection
	)

	if c.Request.GRPCPayload.ProtoFileContent != "" {
		var err error
		fileSource, err = grpccheckerhelper.DescriptorSourceFromProtoFileContent(c.Request.GRPCPayload.ProtoFileContent)
		if err != nil {
			t := testStatus{
				msg:    err.Error(),
				status: testStatusError,
			}
			checker.timers["connect"] = timeInMs(time.Since(_d0))
			checker.timers["resolve"] = timeInMs(time.Since(time.Now()))
			checker.testBody["error"] = t.msg
			checker.processGRPCError(t, checker.c)
			return t
		}
	}

	if len(c.Request.GRPCPayload.Metadata) > 0 {
		for _, v := range c.Request.GRPCPayload.Metadata {
			rpcHeaders = append(rpcHeaders, fmt.Sprintf("%s:%s", v.Name, v.Value))
		}
	}

	hmd := grpccheckerhelper.MetadataFromHeaders(append(addlHeaders, rpcHeaders...))
	refCtx := metadata.NewOutgoingContext(ctx, hmd)
	refClient = grpcreflect.NewClientAuto(refCtx, cc)
	reflSource := grpccheckerhelper.DescriptorSourceFromServer(ctx, refClient)
	if fileSource != nil {
		descSource = grpccheckerhelper.CompositeSource{
			Reflection: reflSource,
			File:       fileSource,
		}
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

	if symbol == "" {
		_, err := descSource.FindSymbol(symbol)
		if err != nil {
			checker.timers["connect"] = timeInMs(time.Since(_d0))
			checker.timers["resolve"] = timeInMs(time.Since(time.Now()))
			t := testStatus{
				status: testStatusError,
				msg:    fmt.Sprintf("failed to resolve symbol %s", symbol),
			}
			checker.testBody["error"] = t.msg
			checker.processGRPCError(t, checker.c)
			return t
		}
	}

	var messageReader *strings.Reader
	if c.Request.GRPCPayload.Message != "" {
		messageReader = strings.NewReader(c.Request.GRPCPayload.Message)
	}

	options := grpccheckerhelper.FormatOptions{
		EmitJSONDefaultFields: false,
		IncludeTextSeparator:  true,
		AllowUnknownFields:    false,
	}
	rf, formatter, err := grpccheckerhelper.RequestParserAndFormatter("json", descSource, messageReader, options)
	if err != nil {
		checker.timers["connect"] = timeInMs(time.Since(_d0))
		checker.timers["resolve"] = timeInMs(time.Since(time.Now()))
		t := testStatus{
			status: testStatusError,
			msg:    fmt.Sprintf("failed to construct request parser and formatter for %q: %v", "json", err),
		}
		checker.testBody["error"] = t.msg
		checker.processGRPCError(t, checker.c)
		return t
	}

	h := &grpccheckerhelper.DefaultEventHandler{
		Out:            os.Stdout,
		Formatter:      formatter,
		VerbosityLevel: 0,
		ConnectStart:   _d0,
	}

	invoke := grpccheckerhelper.DynamicInvokeRPC(ctx, descSource, cc, symbol, append(addlHeaders, rpcHeaders...), h, rf.Next)

	checker.timers["resolve"] = invoke.ResolveTs
	checker.respStr = strSensitise(invoke.MessageRPC)
	checker.respTrailers = invoke.RespTrailers
	checker.testBody["body"] = checker.respStr
	checker.timers["connect"] = invoke.ConnectTs

	t := testStatus{
		status: invoke.Status,
	}
	if invoke.Error != nil {
		t.msg = invoke.Error.Error()
		t.status = testStatusError

		checker.testBody["error"] = t.msg

		checker.processGRPCError(t, checker.c)
		return t
	}
	return testStatus{
		status: testStatusOK,
	}
}
func (checker *grpcChecker) check() testStatus {
	c := checker.c
	ctx, cnlFnc := context.WithCancel(context.Background())
	defer cnlFnc()
	_start := time.Now()

	clientGRPC, err := grpccheckerhelper.NewClientGRPC(ctx, grpccheckerhelper.ClientDialOptions{
		Target:      fmt.Sprintf("%s:%s", c.Endpoint, c.Request.Port),
		TimeoutSec:  float64(c.Expect.ResponseTimeLessThen),
		Certificate: c.Request.GRPCPayload.Certificate,
		PrivateKey:  c.Request.GRPCPayload.PrivateKey,
		IgnoreCert:  c.Request.GRPCPayload.IgnoreServerCertificateError,
	})
	checker.timers["connection"] = timeInMs(time.Since(_start))

	if err != nil {
		_t := testStatus{
			status: testStatusError,
			msg:    err.Error(),
		}
		checker.testBody["body"] = _t.msg
		checker.testBody["error"] = _t.msg
		checker.processGRPCError(_t, c)
		return _t
	}

	if c.Request.GRPCPayload.ServiceDefinition == "reflection" {
		t := checker.reflectionCheckGRPC(ctx, clientGRPC)
		checker.timers["duration"] = timeInMs(time.Since(_start))
		if t.status == testStatusOK {
			return checker.fillGRPCAssertions()
		}
		return t
	}

	if c.Request.GRPCPayload.CheckType == "health" {
		t := checker.healthCheckGRPC(ctx, clientGRPC)
		checker.timers["duration"] = timeInMs(time.Since(_start))
		if t.status == testStatusOK {
			return checker.fillGRPCAssertions()
		}
		return t
	}

	t := checker.behaviourCheckGRPC(ctx, clientGRPC)
	checker.timers["duration"] = timeInMs(time.Since(_start))
	if t.status == testStatusOK {
		return checker.fillGRPCAssertions()
	}
	return t
}

func (checker *grpcChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *grpcChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *grpcChecker) getTestResponseBody() map[string]interface{} {

	checker.testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
	checker.testBody["request"] = checker.c.Request.GRPCPayload.Message
	if checker.testBody["body"] == "" && checker.respStr != "" {
		checker.testBody["body"] = checker.respStr
	}

	assert := []map[string]interface{}{
		{
			"type": grpcResponseTime,
			"config": map[string]string{
				"operator": "less_than",
				"value":    fmt.Sprintf("%v", percentCalc(checker.timers["duration"], 4)),
			},
		},
	}
	if checker.respStr != "" {
		assert = append(assert, map[string]interface{}{
			"type": grpcResponse,
			"config": map[string]string{
				"operator": "is",
				"value":    checker.respStr,
			},
		})
	}
	if len(checker.respTrailers) > 0 {
		assert = append(assert, map[string]interface{}{
			"type": grpcMetadata,
			"config": map[string]string{
				"operator": "is",
				"value":    strings.Join(checker.respTrailers.Get("grpc-status"), "\n"),
			},
		})
	}

	checker.testBody["assertions"] = assert

	return checker.testBody
}

func strSensitise(s string) string {
	if s == "" {
		return ""
	}
	// if value is a json string, then we need to remove \n, \, and whitespaces
	if s != "" && s[0] == '{' {
		s = strings.ReplaceAll(s, "\n", "")
		s = strings.ReplaceAll(s, "\\", "")
		s = strings.ReplaceAll(s, " ", "")
	}
	return s

}
