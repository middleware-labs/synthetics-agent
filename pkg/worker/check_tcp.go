package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

type tcpChecker struct {
	c          SyntheticsModelCustom
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
}

func newTCPChecker(c SyntheticsModelCustom) *tcpChecker {
	return &tcpChecker{
		c: c,
		timers: map[string]float64{
			"duration":   0,
			"dns":        0,
			"connection": 0,
		},
		testBody: map[string]interface{}{
			"assertions": make([]map[string]interface{}, 0),
			"tookMs":     "0 ms",
			"connection": map[string]string{
				"status": "",
			},
		},
		assertions: make([]map[string]string, 0),
		attrs:      pcommon.NewMap(),
	}
}

var (
	tcpStatusEstablished = "established"
	tcpStatusRefused     = "refused"
	tcpStatusTimeout     = "timeout"
)

func (checker *tcpChecker) processTCPResponse(err error) {
	c := checker.c
	status := reqStatusOK
	if errors.As(err, &errTestStatusError{}) {
		status = reqStatusError
	} else if errors.As(err, &errTestStatusFail{}) {
		status = reqStatusFail
	}

	if c.CheckTestRequest.URL == "" {
		resultStr, _ := json.Marshal(checker.assertions)
		checker.attrs.PutStr("assertions", string(resultStr))

		FinishCheckRequest(c, string(status), err.Error(),
			checker.timers, checker.attrs)
	} else {
		testBody := make(map[string]interface{}, 0)
		testBody["assertions"] = []map[string]interface{}{
			{
				"type": "response_time",
				"config": map[string]string{
					"operator": "is",
					"value":    fmt.Sprintf("%v", checker.timers["duration"]),
				},
			},
		}
		testBody["connection_status"] = status
		testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
		WebhookSendCheckRequest(c, testBody)
	}

}

func (checker *tcpChecker) processTCPAssertions(err error, tcpStatus string) {
	for _, assert := range checker.c.Request.Assertions.TCP.Cases {
		ck := make(map[string]string)
		ck["type"] = assert.Type
		ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") +
			" " + assert.Config.Value
		ck["status"] = "PASS"

		switch assert.Type {
		case "response_time":
			ck["actual"] = fmt.Sprintf("%v", checker.timers["duration"])
			ck["reason"] += ck["reason"] + "ms"
			if !assertInt(int64(checker.timers["duration"]), assert) {
				ck["status"] = "FAIL"
				if !errors.As(err, &errTestStatusFail{}) {
					err = errTestStatusFail{
						msg: "assert failed, response_time didn't matched",
					}
				}
			}

		case "network_hopes":
			v, there := checker.attrs.Get("hops.count")
			ck["actual"] = fmt.Sprintf("%v", v.Int())

			if checker.c.Request.TTL && there && !assertInt(v.Int(), assert) {
				ck["status"] = "FAIL"
				if !errors.As(err, &errTestStatusFail{}) {
					err = errTestStatusFail{
						msg: "assert failed, network hopes count didn't matched",
					}
				}
			}

		case "connection":
			assert.Config.Operator = "is"
			ck["actual"] = tcpStatus
			ck["reason"] = "should be is " + assert.Config.Value

			if !assertString(tcpStatus, assert) {
				ck["status"] = "FAIL"
				if !errors.As(err, &errTestStatusFail{}) {
					err = errTestStatusFail{
						msg: "assert failed, connection status didn't matched",
					}
				}
			}
		}

		checker.assertions = append(checker.assertions, ck)
	}
}

func (checker *tcpChecker) processTCPTTL(addr []net.IP, lcErr error) error {
	if checker.c.Request.TTL {
		if len(addr) > 0 {
			if ttlErr := traceRoute(addr[0], checker.c,
				checker.timers, checker.attrs); ttlErr != "" {
				return errTestStatusFail{
					msg: fmt.Sprintf("error resolving dns %v", ttlErr),
				}
			}
		} else {
			return errTestStatusFail{
				msg: fmt.Sprintf("error resolving dns %v", lcErr),
			}
		}
	}
	return nil
}

func (checker *tcpChecker) check() error {
	var err error
	err = errTestStatusOK{
		msg: "OK",
	}
	tcpStatus := tcpStatusEstablished
	start := time.Now()

	addr, lcErr := net.LookupIP(checker.c.Endpoint)
	if lcErr != nil {
		checker.timers["duration"] = timeInMs(time.Since(start))
		err = errTestStatusFail{
			msg: fmt.Sprintf("error resolving dns %v", lcErr),
		}

		for _, assert := range checker.c.Request.Assertions.TCP.Cases {
			checker.assertions = append(checker.assertions,
				map[string]string{
					"type": assert.Type,
					"reason": "should be " +
						strings.ReplaceAll(assert.Config.Operator, "_", " ") +
						" " + assert.Config.Value,
					"status": "FAIL",
					"actual": "DNS resolution failed",
				})
		}
		checker.processTCPResponse(err)
		return err
	}

	checker.timers["dns"] = timeInMs(time.Since(start))
	cnTime := time.Now()

	conn, tmErr := net.DialTimeout("tcp", addr[0].String()+
		":"+checker.c.Request.Port,
		time.Duration(checker.c.Expect.ResponseTimeLessThen)*time.Second)
	if tmErr != nil {
		checker.timers["connection"] = timeInMs(time.Since(cnTime))

		err = errTestStatusFail{
			msg: fmt.Sprintf("Error connecting tcp %v", tmErr),
		}

		checker.attrs.PutStr("connection.error", tmErr.Error())
		tcpStatus = tcpStatusRefused
		if strings.Contains(tmErr.Error(), tcpStatusTimeout) {
			tcpStatus = tcpStatusTimeout
		}
	} else {
		defer conn.Close()
		checker.timers["connection"] = timeInMs(time.Since(cnTime))
	}

	checker.attrs.PutStr("connection.status", tcpStatus)
	checker.timers["duration"] = timeInMs(time.Since(start))

	// process ttl
	checker.processTCPTTL(addr, lcErr)
	// process assertions
	checker.processTCPAssertions(err, tcpStatus)
	// process response
	checker.processTCPResponse(err)
	return nil
}

func CheckTcpRequest(c SyntheticsModelCustom) {
	checker := newTCPChecker(c)
	checker.check()
}
