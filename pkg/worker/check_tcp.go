package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

const (
	assertTypeTCPResponseTime string = "response_time"
	assertTypeTCPNetworkHops  string = "network_hops"
	assertTypeTCPConnection   string = "connection"
)

type tcpChecker struct {
	c          SyntheticCheck
	timers     map[string]float64
	assertions []map[string]string
	netter     Netter
	BaseCheckerForTTL
}

type BaseCheckerForTTL struct {
	testBody map[string]interface{}
	attrs    pcommon.Map
}

func (bc *BaseCheckerForTTL) getTestResponseBody() map[string]interface{} {
	var traceroute []map[string]interface{}
	hopData := make(map[int]map[string]interface{})
	maxHopNum := 0

	bc.attrs.Range(func(k string, v pcommon.Value) bool {
		if k == "hops.count" {
			bc.testBody["hops_count"] = v.AsRaw()
		}

		if k == "hops" {
			hopsStr := v.AsString()
			lines := strings.Split(hopsStr, "\n")
			hopRegex := regexp.MustCompile(`hop (\d+)\. ([\d.]+) ([\d.]+)ms`)

			for _, line := range lines {
				matches := hopRegex.FindStringSubmatch(line)
				if matches == nil {
					continue
				}

				hopNum, _ := strconv.Atoi(matches[1])
				ip := matches[2]
				latency, _ := strconv.ParseFloat(matches[3], 64)

				if _, exists := hopData[hopNum]; !exists {
					hopData[hopNum] = map[string]interface{}{
						"latency": map[string]interface{}{
							"min":    latency,
							"max":    latency,
							"avg":    latency,
							"values": []float64{latency},
						},
						"routers": []map[string]string{{"ip": ip}},
					}
				} else {
					latencyData := hopData[hopNum]["latency"].(map[string]interface{})
					values := latencyData["values"].([]float64)
					values = append(values, latency)

					minLatency := latencyData["min"].(float64)
					maxLatency := latencyData["max"].(float64)

					if latency < minLatency {
						latencyData["min"] = latency
					}
					if latency > maxLatency {
						latencyData["max"] = latency
					}
					latencyData["values"] = values
					latencyData["avg"] = (latencyData["min"].(float64) + latencyData["max"].(float64)) / 2

					routers := hopData[hopNum]["routers"].([]map[string]string)
					routers = append(routers, map[string]string{"ip": ip})
					hopData[hopNum]["routers"] = routers
				}

				if hopNum > maxHopNum {
					maxHopNum = hopNum
				}
			}

			// Converting the map to a slice, filling gaps with default values
			for i := 1; i <= maxHopNum; i++ {
				if data, exists := hopData[i]; exists {
					traceroute = append(traceroute, data)
				} else {
					// Adding default values for missing hop numbers
					traceroute = append(traceroute, map[string]interface{}{
						"latency": map[string]interface{}{
							"min":    nil,
							"max":    nil,
							"avg":    nil,
							"values": nil,
						},
						"routers": []map[string]string{{"ip": "???"}},
					})
				}
			}
		}

		return true
	})

	bc.testBody["traceroute"] = traceroute
	return bc.testBody
}

func newTCPChecker(c SyntheticCheck) (protocolChecker, error) {
	if strings.TrimSpace(c.Request.Port) == "" {
		return nil, errors.New("port is required for TCP checks")
	}
	return &tcpChecker{
		c: c,
		timers: map[string]float64{
			"duration":   0,
			"dns":        0,
			"connection": 0,
		},
		assertions: make([]map[string]string, 0),
		netter:     &DefaultNetter{},
		BaseCheckerForTTL: BaseCheckerForTTL{
			testBody: map[string]interface{}{
				"assertions":        make([]map[string]interface{}, 0),
				"tookMs":            "0 ms",
				"connection_status": tcpStatusEstablished,
			},
			attrs: pcommon.NewMap(),
		},
	}, nil
}

var (
	tcpStatusEstablished = "established"
	tcpStatusRefused     = "refused"
	tcpStatusTimeout     = "timeout"
)

func (checker *tcpChecker) processTCPResponse(testStatus testStatus) {
	c := checker.c

	if c.CheckTestRequest.URL == "" {
		resultStr, _ := json.Marshal(checker.assertions)
		checker.attrs.PutStr("assertions", string(resultStr))
	} else {
		checker.testBody["assertions"] = []map[string]interface{}{
			{
				"type": assertTypeTCPResponseTime,
				"config": map[string]string{
					"operator": "less_than",
					"value":    fmt.Sprintf("%v", percentCalc(checker.timers["duration"], 4)),
				},
			},
		}
		if checker.testBody["connection_status"] == "" {
			checker.testBody["connection_status"] = testStatus.status
		}
		checker.testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
	}
}

func (checker *tcpChecker) processTCPAssertions(testStatus testStatus, tcpStatus string) testStatus {
	testStatusMsg := make([]string, 0)
	for _, assert := range checker.c.Request.Assertions.TCP.Cases {
		ck := AssertResult{
			Type:   assert.Type,
			Status: testStatusPass,
			Reason: AssertObj{
				Verb:     "should be ",
				Operator: strings.ReplaceAll(assert.Config.Operator, "_", " "),
				Value:    assert.Config.Value,
			},
		}

		switch assert.Type {
		case "response_time":
			ck.Actual = fmt.Sprintf("%v", checker.timers["duration"])
			ck.Reason.Value += ck.Reason.Value + "ms"
			if !assertFloat(checker.timers["duration"], assert) {
				ck.Status = testStatusFail
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, checker.timers["duration"]))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			}

		case "network_hops":
			v, there := checker.attrs.Get("hops.count")
			ck.Actual = fmt.Sprintf("%v", v.Int())

			if checker.c.Request.TTL && there && !assertInt(v.Int(), assert) {
				ck.Status = testStatusFail
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, v.Int()))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			}

		case assertTypeTCPConnection:
			assert.Config.Operator = "is"
			ck.Actual = tcpStatus
			ck.Reason = AssertObj{
				Verb:  "should be ",
				Value: assert.Config.Value,
			}

			if !assertString(tcpStatus, assert) {
				ck.Status = testStatusFail
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, tcpStatus))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			}
		}

		checker.assertions = append(checker.assertions, ck.ToMap())
	}
	return testStatus
}

func (checker *tcpChecker) processTCPTTL(addr []net.IP, lcErr error) testStatus {
	testStatus := testStatus{
		status: testStatusOK,
	}

	if checker.c.Request.TTL {
		if len(addr) > 0 {
			traceRouter := newTraceRouteChecker(addr[0],
				checker.c.Expect.ResponseTimeLessThen, checker.timers, checker.attrs)
			tStatus := traceRouter.check()
			traceRouter.getAttrs().CopyTo(checker.attrs)

			testStatus.status = tStatus.status
			testStatus.msg = fmt.Sprintf("error resolving dns %v", tStatus)
		} else {
			testStatus.status = testStatusError
			testStatus.msg = fmt.Sprintf("error resolving dns %v", lcErr)
		}
	}
	return testStatus
}

func (checker *tcpChecker) check() testStatus {
	testStatus := testStatus{
		status: testStatusOK,
	}

	tcpStatus := tcpStatusEstablished
	start := time.Now()

	addr, lcErr := checker.netter.LookupIP(checker.c.Endpoint)
	if lcErr != nil {
		checker.timers["duration"] = timeInMs(time.Since(start))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error resolving dns: %v", lcErr)

		for _, assert := range checker.c.Request.Assertions.TCP.Cases {
			ck := AssertResult{
				Type:   assert.Type,
				Status: testStatusFail,
				Actual: "DNS resolution failed",
				Reason: AssertObj{
					Verb: "should be ",
					Operator: strings.ReplaceAll(assert.Config.Operator, "_", " ") +
						" " + assert.Config.Value,
					Value: assert.Config.Value,
				},
			}
			checker.assertions = append(checker.assertions, ck.ToMap())
		}
		checker.processTCPResponse(testStatus)
		return testStatus
	}

	checker.timers["dns"] = timeInMs(time.Since(start))
	cnTime := time.Now()

	conn, tmErr := checker.netter.DialTimeout("tcp", addr[0].String()+
		":"+checker.c.Request.Port,
		time.Duration(checker.c.Expect.ResponseTimeLessThen)*time.Second)
	if tmErr != nil {
		checker.timers["connection"] = timeInMs(time.Since(cnTime))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error connecting tcp %v", tmErr)

		checker.attrs.PutStr("connection.error", tmErr.Error())
		tcpStatus = tcpStatusRefused
		checker.testBody["connection_status"] = tcpStatusRefused
		if strings.Contains(tmErr.Error(), tcpStatusTimeout) {
			tcpStatus = tcpStatusTimeout
			checker.testBody["connection_status"] = tcpStatusTimeout
		}
	} else {
		defer checker.netter.ConnClose(conn)
		checker.timers["connection"] = timeInMs(time.Since(cnTime))
		checker.testBody["connection_status"] = tcpStatusEstablished
	}

	checker.attrs.PutStr("connection.status", tcpStatus)
	checker.timers["duration"] = timeInMs(time.Since(start))

	// process ttl
	checker.processTCPTTL(addr, lcErr)
	// process assertions
	testStatus = checker.processTCPAssertions(testStatus, tcpStatus)
	// process response
	checker.processTCPResponse(testStatus)
	return testStatus
}

func (checker *tcpChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *tcpChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *tcpChecker) getDetails() map[string]float64 {
	return nil
}
