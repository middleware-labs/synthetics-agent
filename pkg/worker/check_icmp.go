package worker

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

const (
	assertTypeICMPLatency    string = "latency"
	assertTypeICMPPacketLoss string = "packet_loss"
	assertTypeICMPPacketRecv string = "packet_received"
)

var (
	icmpStatusEstablished = "established"
	icmpStatusRefused     = "refused"
	icmpStatusTimeout     = "timeout"
)

type pinger interface {
	Run() error
	Statistics() *probing.Statistics
	GetSize() int
}

type icmpPinger struct {
	*probing.Pinger
}

func (p *icmpPinger) Run() error {
	return p.Pinger.Run()
}

func (p *icmpPinger) Statistics() *probing.Statistics {
	return p.Pinger.Statistics()
}

func (p *icmpPinger) GetSize() int {
	return p.Pinger.Size
}

func (p *icmpPinger) SetPrivileged(privileged bool) {
	p.Pinger.SetPrivileged(privileged)
}

func (p *icmpPinger) SetInterval(interval time.Duration) {
	p.Pinger.Interval = interval
}

func (p *icmpPinger) SetTimeout(timeout time.Duration) {
	p.Pinger.Timeout = timeout
}

func (p *icmpPinger) SetCount(count int) {
	p.Pinger.Count = count
}

func (p *icmpPinger) SetSize(size int) {
	p.Pinger.Size = size
}

func (p *icmpPinger) SetRecordRtts(recordRtts bool) {
	p.Pinger.RecordRtts = recordRtts
}

type icmpChecker struct {
	c          SyntheticCheck
	details    map[string]float64
	timers     map[string]float64
	assertions []map[string]string
	pinger     pinger
	netter     Netter
	BaseCheckerForTTL
}

func getDefaultPinger(c SyntheticCheck) (*icmpPinger, error) {
	pinger, err := probing.NewPinger(c.Endpoint)
	if err != nil {
		return nil, err
	}
	pinger.Timeout = time.Second * 5
	pinger.Interval = time.Second
	pinger.Count = c.Request.ICMPPayload.PingsPerTest
	pinger.RecordRtts = false
	pinger.Size = 24

	pinger.SetPrivileged(true)
	return &icmpPinger{Pinger: pinger}, nil
}

func newICMPChecker(c SyntheticCheck, pinger pinger) protocolChecker {
	return &icmpChecker{
		c: c,
		details: map[string]float64{
			"packets_sent":     0,
			"packets_received": 0,
			"packet_loss":      0,
			"latency_min":      0,
			"latency_max":      0,
			"latency_avg":      0,
			"latency_std_dev":  0,
		},
		timers: map[string]float64{
			"duration": 0,
		},
		BaseCheckerForTTL: BaseCheckerForTTL{
			testBody: map[string]interface{}{
				"rcmp_status": "FAILED",
				"packet_size": "0 bytes",
				"packet":      "N/A",
				"latency":     "N/A",
			},
			attrs: pcommon.NewMap(),
		},
		assertions: make([]map[string]string, 0),
		pinger:     pinger,
		netter:     &DefaultNetter{},
	}
}

func (checker *icmpChecker) processICMPResponse(testStatus testStatus) {

	c := checker.c
	if testStatus.status != testStatusOK {
		for _, v := range c.Request.Assertions.ICMP.Cases {
			checker.assertions = append(checker.assertions, map[string]string{
				"type":   v.Type,
				"status": testStatusFail,
				"reason": fmt.Sprintf("should be %s %s",
					strings.ReplaceAll(v.Config.Operator, "_", " "), v.Config.Value),
				"actual": "N/A",
			})
		}
	}

	if c.CheckTestRequest.URL != "" {
		checker.testBody["assertions"] = []map[string]interface{}{
			{
				"type": assertTypeICMPLatency,
				"config": map[string]interface{}{
					"operator": "less_than",
					"value":    checker.timers["duration"],
				},
			},
			{
				"type": assertTypeICMPPacketLoss,
				"config": map[string]interface{}{
					"operator": "less_than",
					"value":    checker.timers["packet_loss"],
				},
			},
			{
				"type": assertTypeICMPPacketRecv,
				"config": map[string]interface{}{
					"operator": "less_than",
					"value":    checker.timers["packet_recv"],
				},
			},
		}
		checker.testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
		// finishTestRequest(checker.c, checker.testBody)
		return
	}

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))

	for k, v := range checker.details {
		checker.attrs.PutStr(k, fmt.Sprintf("%f", v))
	}

	//finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
}

func (checker *icmpChecker) check() testStatus {
	c := checker.c
	testStatus := testStatus{
		status: testStatusOK,
	}

	icmpStatus := icmpStatusEstablished
	err := checker.pinger.Run() // Blocks until finished.
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error running ping %v", err)

		checker.processICMPResponse(testStatus)
		return testStatus
	}

	start := time.Now()
	addr, lcErr := checker.netter.LookupIP(checker.c.Endpoint)
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
		checker.processICMPResponse(testStatus)
		return testStatus
	}

	checker.timers["dns"] = timeInMs(time.Since(start))
	cnTime := time.Now()

	conn, tmErr := checker.netter.DialTimeout("icmp", addr[0].String()+
		":"+checker.c.Request.Port,
		time.Duration(checker.c.Expect.ResponseTimeLessThen)*time.Second)
	if tmErr != nil {
		checker.timers["connection"] = timeInMs(time.Since(cnTime))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error connecting icmp %v", tmErr)

		checker.attrs.PutStr("connection.error", tmErr.Error())
		icmpStatus = icmpStatusRefused
		checker.testBody["connection_status"] = icmpStatusRefused
		if strings.Contains(tmErr.Error(), icmpStatusTimeout) {
			icmpStatus = tcpStatusTimeout
			checker.testBody["connection_status"] = icmpStatusTimeout
		}
	} else {
		defer checker.netter.ConnClose(conn)
		checker.timers["connection"] = timeInMs(time.Since(cnTime))
		checker.testBody["connection_status"] = icmpStatusEstablished
	}

	checker.attrs.PutStr("connection.status", icmpStatus)
	checker.timers["duration"] = timeInMs(time.Since(start))

	// process ttl
	checker.processICMPTTL(addr, lcErr)

	stats := checker.pinger.Statistics()

	checker.timers["duration"] = timeInMs(stats.AvgRtt)
	checker.timers["packet_loss"] = stats.PacketLoss
	checker.timers["packet_recv"] = float64(stats.PacketsRecv)

	isTestReq := c.CheckTestRequest.URL != ""
	if isTestReq {
		checker.testBody["rcmp_status"] = "SUCCESSFUL"
		checker.testBody["packet"] = fmt.Sprintf("%d packets sent, %d packets received, %f%% packet loss",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		checker.testBody["latency"] = fmt.Sprintf("min/avg/max/stddev = %f/%f/%f/%f ms",
			timeInMs(stats.MinRtt),
			timeInMs(stats.AvgRtt),
			timeInMs(stats.MaxRtt),
			timeInMs(stats.StdDevRtt))
		// packet_size in bytes
		checker.testBody["packet_size"] = checker.pinger.GetSize()
		checker.processICMPResponse(testStatus)
		return testStatus
	}

	checker.attrs.PutStr("ip", stats.IPAddr.String())
	checker.attrs.PutStr("addr", stats.Addr)

	checker.details["packets_sent"] = float64(stats.PacketsSent)
	checker.details["packets_received"] = float64(stats.PacketsRecv)
	checker.details["packet_loss"] = stats.PacketLoss
	checker.details["latency_min"] = timeInMs(stats.MinRtt)
	checker.details["latency_max"] = timeInMs(stats.MaxRtt)
	checker.details["latency_avg"] = timeInMs(stats.AvgRtt)
	checker.details["latency_std_dev"] = timeInMs(stats.StdDevRtt)

	if c.Expect.LatencyLimit > 0 && c.Expect.LatencyLimit <= checker.timers["rtt"] {
		// TODO revisit testStatusFailed
		testStatus.status = testStatusFail
		testStatus.msg = fmt.Sprintf("latency higher then expected %s", c.Endpoint)
	} else if c.Expect.PacketLossLimit > 0 && c.Expect.PacketLossLimit <= stats.PacketLoss {
		// TODO revisit testStatusFailed
		testStatus.status = testStatusFail
		testStatus.msg = fmt.Sprintf("packet loss higher then expected %s", c.Endpoint)
	}
	testStatusMsg := make([]string, 0)
	for _, v := range c.Request.Assertions.ICMP.Cases {
		ck := make(map[string]string)
		ck["type"] = v.Type
		ck["status"] = "OK"
		ck["reason"] = fmt.Sprintf("should be %s %s", strings.ReplaceAll(v.Config.Operator, "_", " "), v.Config.Value)

		switch v.Type {
		case assertTypeICMPLatency:
			ck["actual"] = fmt.Sprintf("%f", checker.timers["rtt"])
			if !assertFloat(checker.timers["duration"], v) {
				ck["status"] = testStatusFail
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", v.Type, v.Config.Operator, v.Config.Value, checker.timers["rtt"]))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			}

		case assertTypeICMPPacketLoss:
			ck["actual"] = fmt.Sprintf("%f", checker.timers["packet_loss"])
			if !assertInt(int64(checker.timers["packet_loss"]), v) {
				ck["status"] = testStatusFail
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", v.Type, v.Config.Operator, v.Config.Value, checker.timers["packet_loss"]))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			}

		case assertTypeICMPPacketRecv:
			ck["actual"] = fmt.Sprintf("%f", checker.timers["packet_recv"])
			if !assertInt(int64(checker.timers["packet_recv"]), v) {
				ck["status"] = testStatusFail
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", v.Type, v.Config.Operator, v.Config.Value, checker.timers["packet_recv"]))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			}
		}

		checker.assertions = append(checker.assertions, ck)
	}
	checker.processICMPResponse(testStatus)
	return testStatus
}

func (checker *icmpChecker) processICMPTTL(addr []net.IP, lcErr error) testStatus {
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

func (checker *icmpChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *icmpChecker) getAttrs() pcommon.Map {
	return checker.attrs
}
