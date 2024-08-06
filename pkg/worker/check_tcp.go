package worker

import (
	"encoding/json"
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

type netter interface {
	lookupIP(host string) ([]net.IP, error)
	dialTimeout(network, address string,
		timeout time.Duration) (net.Conn, error)
	connClose(conn net.Conn) error
}

type defaultNetter struct{}

func (d *defaultNetter) lookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

func (d *defaultNetter) dialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

func (d *defaultNetter) connClose(conn net.Conn) error {
	return conn.Close()
}

type tcpChecker struct {
	c          SyntheticCheck
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
	netter     netter
}

func newTCPChecker(c SyntheticCheck) protocolChecker {
	return &tcpChecker{
		c: c,
		timers: map[string]float64{
			"duration":   0,
			"dns":        0,
			"connection": 0,
		},
		testBody: map[string]interface{}{
			"assertions":        make([]map[string]interface{}, 0),
			"tookMs":            "0 ms",
			"connection_status": tcpStatusEstablished,
		},
		assertions: make([]map[string]string, 0),
		attrs:      pcommon.NewMap(),
		netter:     &defaultNetter{},
	}
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
	for _, assert := range checker.c.Request.Assertions.TCP.Cases {
		ck := make(map[string]string)
		ck["type"] = assert.Type
		ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") +
			" " + assert.Config.Value
		ck["status"] = testStatusPass

		switch assert.Type {
		case "response_time":
			ck["actual"] = fmt.Sprintf("%v", checker.timers["duration"])
			ck["reason"] += ck["reason"] + "ms"
			if !assertFloat(checker.timers["duration"], assert) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFail
				testStatus.msg = "assert failed, response_time didn't matched"
			}

		case "network_hops":
			v, there := checker.attrs.Get("hops.count")
			ck["actual"] = fmt.Sprintf("%v", v.Int())

			if checker.c.Request.TTL && there && !assertInt(v.Int(), assert) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFail
				testStatus.msg = "assert failed, network hopes count didn't matched"
			}

		case assertTypeTCPConnection:
			assert.Config.Operator = "is"
			ck["actual"] = tcpStatus
			ck["reason"] = "should be is " + assert.Config.Value

			if !assertString(tcpStatus, assert) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFail
				testStatus.msg = "assert failed, connection status didn't matched"
			}
		}

		checker.assertions = append(checker.assertions, ck)
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

	addr, lcErr := checker.netter.lookupIP(checker.c.Endpoint)
	if lcErr != nil {
		checker.timers["duration"] = timeInMs(time.Since(start))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error resolving dns: %v", lcErr)

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
		checker.processTCPResponse(testStatus)
		return testStatus
	}

	checker.timers["dns"] = timeInMs(time.Since(start))
	cnTime := time.Now()

	conn, tmErr := checker.netter.dialTimeout("tcp", addr[0].String()+
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
		defer checker.netter.connClose(conn)
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

func (checker *tcpChecker) getTestResponseBody() map[string]interface{} {
	var traceroute []map[string]interface{}

	checker.attrs.Range(func(k string, v pcommon.Value) bool {
		if k == "hops.count" {
			checker.testBody["hops_count"] = v.AsRaw()
		}

		if k == "hops" {
			hopsStr := v.AsString()
			lines := strings.Split(hopsStr, "\n")
			hopRegex := regexp.MustCompile(`hop (\d+)\. ([\d.]+) ([\d.]+)ms`)

			hopData := make(map[int]map[string]interface{})

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
						"router": []map[string]string{{"ip": ip}},
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

					routers := hopData[hopNum]["router"].([]map[string]string)
					routers = append(routers, map[string]string{"ip": ip})
					hopData[hopNum]["router"] = routers
				}
			}

			// Converting the map to a slice
			for _, data := range hopData {
				traceroute = append(traceroute, data)
			}
		}

		return true
	})

	checker.testBody["traceroute"] = traceroute
	return checker.testBody
}

func (checker *tcpChecker) getDetails() map[string]float64 {
	return nil
}
