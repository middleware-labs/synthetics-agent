package worker

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"go.opentelemetry.io/collector/pdata/pcommon"
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
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
	pinger     pinger
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
		testBody: map[string]interface{}{
			"rcmp_status": "FAILED",
			"packet_size": "0 bytes",
			"packet":      "N/A",
			"latency":     "N/A",
		},
		assertions: make([]map[string]string, 0),
		attrs:      pcommon.NewMap(),
		pinger:     pinger,
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
				"type": "latency",
				"config": map[string]interface{}{
					"operator": "less_than",
					"value":    checker.timers["duration"],
				},
			},
			{
				"type": "packet_loss",
				"config": map[string]interface{}{
					"operator": "less_than",
					"value":    checker.timers["packet_loss"],
				},
			},
			{
				"type": "packet_received",
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

	err := checker.pinger.Run() // Blocks until finished.
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error running ping %v", err)

		checker.processICMPResponse(testStatus)
		return testStatus
	}

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
		testStatus.status = testStatusFailed
		testStatus.msg = fmt.Sprintf("latency higher then expected %s", c.Endpoint)
	} else if c.Expect.PacketLossLimit > 0 && c.Expect.PacketLossLimit <= stats.PacketLoss {
		// TODO revisit testStatusFailed
		testStatus.status = testStatusFailed
		testStatus.msg = fmt.Sprintf("packet loss higher then expected %s", c.Endpoint)
	}

	for _, v := range c.Request.Assertions.ICMP.Cases {
		ck := make(map[string]string)
		ck["type"] = v.Type
		ck["status"] = "OK"
		ck["reason"] = "should be " + strings.ReplaceAll(v.Config.Operator, "_", " ") +
			" " + v.Config.Value

		switch v.Type {
		case "latency":
			ck["actual"] = fmt.Sprintf("%f", checker.timers["rtt"])
			if !assertInt(int64(checker.timers["duration"]), v) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFailed
				testStatus.msg = fmt.Sprintf("latency didn't matched %s", c.Endpoint)
			}

			checker.assertions = append(checker.assertions, ck)
		case "packet_loss":
			ck["actual"] = fmt.Sprintf("%f", checker.timers["packet_loss"])
			if !assertInt(int64(checker.timers["packet_loss"]), v) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFailed
				testStatus.msg = fmt.Sprintf("packet_loss didn't matched %s", c.Endpoint)
			}

			checker.assertions = append(checker.assertions, ck)

		case "packet_received":
			ck["actual"] = fmt.Sprintf("%f", checker.timers["packet_recv"])
			if !assertInt(int64(checker.timers["packet_recv"]), v) {
				ck["status"] = testStatusFail
				testStatus.status = testStatusFailed
				testStatus.msg = fmt.Sprintf("packet_received didn't matched %s", c.Endpoint)
			}
			checker.assertions = append(checker.assertions, ck)
		}
	}
	checker.processICMPResponse(testStatus)
	return testStatus
}

func (checker *icmpChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *icmpChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *icmpChecker) getTestBody() map[string]interface{} {
	return checker.testBody
}

func (checker *icmpChecker) getDetails() map[string]float64 {
	return checker.details
}

func timeInMs(t time.Duration) float64 {
	return float64(t) / float64(time.Millisecond)
}
