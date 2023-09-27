package worker

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

func CheckTcpRequest(c SyntheticsModelCustom) {
	timers := map[string]float64{
		"duration":   0,
		"dns":        0,
		"connection": 0,
	}

	assertions := make([]map[string]string, 0)
	_Status := "OK"
	_Message := ""
	status := "established"

	attrs := pcommon.NewMap()
	_start := time.Now()

	addr, lcErr := net.LookupIP(c.Endpoint)
	if lcErr != nil {
		timers["duration"] = timeInMs(time.Since(_start))
		_Status = "FAIL"
		_Message = fmt.Sprintf("error resolving dns %v", lcErr)

		for _, assert := range c.Request.Assertions.TCP.Cases {
			assertions = append(assertions, map[string]string{
				"type":   assert.Type,
				"reason": "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value,
				"status": "FAIL",
				"actual": "DNS resolution failed",
			})
		}
	} else {

		timers["dns"] = timeInMs(time.Since(_start))
		_cnTime := time.Now()

		conn, tmErr := net.DialTimeout("tcp", addr[0].String()+":"+c.Request.Port, time.Duration(c.Expect.ResponseTimeLessThen)*time.Second)

		if tmErr != nil {
			timers["connection"] = timeInMs(time.Since(_cnTime))

			_Status = "FAIL"
			_Message = fmt.Sprintf("Error connecting tcp %v", tmErr)

			attrs.PutStr("connection.error", tmErr.Error())
			if strings.Index(tmErr.Error(), "timeout") >= 0 {
				status = "timeout"
			} else {
				status = "refused"
			}
		} else {
			defer conn.Close()
			timers["connection"] = timeInMs(time.Since(_cnTime))
		}

		attrs.PutStr("connection.status", status)
		timers["duration"] = timeInMs(time.Since(_start))

		if c.Request.TTL {
			if len(addr) > 0 {
				if ttlErr := traceRoute(addr[0], c, timers, attrs); ttlErr != "" {
					_Status = "FAIL"
					_Message = fmt.Sprintf("error resolving dns %v", ttlErr)
				}
			} else {
				_Status = "FAIL"
				_Message = fmt.Sprintf("error resolving dns %v", lcErr)
			}
		}

		for _, assert := range c.Request.Assertions.TCP.Cases {
			_ck := make(map[string]string)
			_ck["type"] = assert.Type
			_ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
			_ck["status"] = "PASS"

			switch assert.Type {
			case "response_time":
				_ck["actual"] = fmt.Sprintf("%v", timers["duration"])
				_ck["reason"] += _ck["reason"] + "ms"
				if !assertInt(int64(timers["duration"]), assert) {
					_ck["status"] = "FAIL"
					if _Status != "FAIL" {
						_Status = "FAIL"
						_Message = "assert failed, response_time didn't matched"
					}
				}
				break
			case "network_hopes":
				v, there := attrs.Get("hops.count")
				_ck["actual"] = fmt.Sprintf("%v", v.Int())

				if c.Request.TTL && there && !assertInt(v.Int(), assert) {
					_ck["status"] = "FAIL"
					if _Status != "FAIL" {
						_Status = "FAIL"
						_Message = "assert failed, network hopes count didn't matched"
					}
				}
				break
			case "connection":
				assert.Config.Operator = "is"
				_ck["actual"] = status
				_ck["reason"] = "should be is " + assert.Config.Value

				if !assertString(status, assert) {
					_ck["status"] = "FAIL"
					if _Status != "FAIL" {
						_Status = "FAIL"
						_Message = "assert failed, connection status didn't matched"
					}
				}
				break
			}

			assertions = append(assertions, _ck)
		}
	}

	if c.CheckTestRequest.URL == "" {
		resultStr, _ := json.Marshal(assertions)
		attrs.PutStr("assertions", string(resultStr))

		FinishCheckRequest(c, _Status, _Message, timers, attrs)
	} else {
		_testBody := make(map[string]interface{}, 0)
		_testBody["assertions"] = []map[string]interface{}{
			{
				"type": "response_time",
				"config": map[string]string{
					"operator": "is",
					"value":    fmt.Sprintf("%v", timers["duration"]),
				},
			},
		}
		_testBody["connection_status"] = status
		_testBody["tookMs"] = fmt.Sprintf("%.2f ms", timers["duration"])
		WebhookSendCheckRequest(c, _testBody)
	}
}
