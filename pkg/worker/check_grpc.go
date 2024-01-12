package worker

import (
	"context"
	"encoding/json"
	"fmt"
	grpcchecker "github.com/middleware-labs/synthetics-agent/pkg/worker/grpc-checker"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc/metadata"
)

type grpcAssertion string

const (
	grpcResponseTime grpcAssertion = "response_time"
	grpcResponse     grpcAssertion = "grpc_response"
	grpcMetadata     grpcAssertion = "grpc_metadata"
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
	respStatus   string
	respError    string
	reflections  map[string]interface{}
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
		respStatus: "",
		respError:  "",
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
			if !assertInt(int64(checker.timers["duration"]), assert) {
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

func (checker *grpcChecker) check() testStatus {
	c := checker.c
	ctx, cnlFnc := context.WithCancel(context.Background())
	defer cnlFnc()
	_start := time.Now()
	rsp := grpcchecker.RequestRPC(grpcchecker.CheckerOptions{
		Ctx:                   ctx,
		IgnoreCert:            true,
		Target:                fmt.Sprintf("%s:%s", c.Endpoint, c.Request.Port),
		Reflection:            c.Request.GRPCPayload.ServiceDefinition == "reflection",
		ServiceMethodSymbol:   c.Request.GRPCPayload.MethodSelection,
		ServiceRequestMessage: c.Request.GRPCPayload.Message,
		TimeoutSec:            c.Expect.ResponseTimeLessThen,
		ProtoFileContent:      c.Request.GRPCPayload.ProtoFileContent,
	})
	rsp.MessageRPC = strSensitise(rsp.MessageRPC)
	checker.timers["duration"] = timeInMs(time.Since(_start))
	checker.timers["connection"] = rsp.ConnectionTs
	checker.timers["connect"] = rsp.ConnectTs
	_d0 := time.Now()
	if rsp.ResolveTs < 1 {
		rsp.ResolveTs = timeInMs(time.Since(_d0))
	}
	checker.timers["resolve"] = rsp.ResolveTs
	checker.reflections = rsp.Reflections
	checker.respStatus = rsp.Status
	checker.respStr = rsp.MessageRPC
	checker.respTrailers = rsp.RespTrailers

	testStatus := testStatus{
		status: rsp.Status,
	}
	if rsp.Error != nil {
		testStatus.msg = rsp.Error.Error()
		checker.testBody["body"] = testStatus.msg
		checker.processGRPCError(testStatus, c)
		return testStatus
	}

	testStatus = checker.fillGRPCAssertions()
	checker.testBody["body"] = testStatus.msg
	return testStatus
}

func (checker *grpcChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *grpcChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *grpcChecker) getTestResponseBody() map[string]interface{} {

	checker.testBody["tookMs"] = checker.timers["duration"]
	checker.testBody["reflections"] = make(map[string]interface{}, 0)
	if checker.c.SyntheticsModel.Request.GRPCPayload.ServiceDefinition == "reflection" {
		checker.testBody["reflections"] = checker.reflections
	}
	if checker.testBody["body"] == "" && checker.respStr != "" {
		checker.testBody["body"] = checker.respStr
	}

	assert := []map[string]interface{}{
		{
			"type": grpcResponseTime,
			"config": map[string]string{
				"operator": "less_than",
				"value":    fmt.Sprintf("%v", checker.timers["duration"]*0.4+checker.timers["duration"]),
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
