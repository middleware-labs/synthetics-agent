package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type icmpChecker struct {
	c          SyntheticsModelCustom
	details    map[string]float64
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
}

func newICMPChecker(c SyntheticsModelCustom) protocolChecker {
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
	}
}

func (checker *icmpChecker) processICMPResponse(err error) {

	c := checker.c
	status := reqStatusOK
	if errors.As(err, &errTestStatusError{}) {
		status = reqStatusError
	} else if errors.As(err, &errTestStatusFail{}) {
		status = reqStatusFail
	}

	if status != reqStatusOK {
		for _, v := range c.Request.Assertions.ICMP.Cases {
			checker.assertions = append(checker.assertions, map[string]string{
				"type":   v.Type,
				"status": "FAIL",
				"reason": fmt.Sprintf("should be %s %s", strings.ReplaceAll(v.Config.Operator, "_", " "), v.Config.Value),
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
		WebhookSendCheckRequest(checker.c, checker.testBody)
		return
	}

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))

	for k, v := range checker.details {
		checker.attrs.PutStr(k, fmt.Sprintf("%f", v))
	}

	FinishCheckRequest(c, string(status), err.Error(), checker.timers, checker.attrs)
}

func (checker *icmpChecker) check() error {
	c := checker.c
	pinger, err := probing.NewPinger(c.Endpoint)
	if err != nil {
		return err
	}

	pinger.Timeout = time.Second * 5
	pinger.Interval = time.Second
	pinger.Count = c.Request.ICMPPayload.PingsPerTest
	pinger.RecordRtts = false
	pinger.Size = 24

	pinger.SetPrivileged(true)

	err = pinger.Run() // Blocks until finished.
	if err != nil {
		newErr := errTestStatusError{
			msg: fmt.Sprintf("error running ping %v", err),
		}

		checker.processICMPResponse(newErr)
		return newErr
	}

	stats := pinger.Statistics()

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
		checker.testBody["packet_size"] = pinger.Size
		checker.processICMPResponse(err)
		return nil
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

	err = errTestStatusPass{
		msg: string(reqStatusPass),
	}

	if c.Expect.LatencyLimit > 0 && c.Expect.LatencyLimit <= checker.timers["rtt"] {
		err = errTestStatusFailed{
			msg: fmt.Sprintf("latency higher then expected %s", c.Endpoint),
		}
	} else if c.Expect.PacketLossLimit > 0 && c.Expect.PacketLossLimit <= stats.PacketLoss {
		err = errTestStatusFailed{
			msg: fmt.Sprintf("packet loss higher then expected %s", c.Endpoint),
		}
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
				ck["status"] = "FAIL"
				err = errTestStatusFailed{
					msg: fmt.Sprintf("latency didn't matched %s", c.Endpoint),
				}
			}

			checker.assertions = append(checker.assertions, ck)
		case "packet_loss":
			ck["actual"] = fmt.Sprintf("%f", checker.timers["packet_loss"])
			if !assertInt(int64(checker.timers["packet_loss"]), v) {
				ck["status"] = "FAIL"
				err = errTestStatusFailed{
					msg: fmt.Sprintf("packet_loss didn't matched %s", c.Endpoint),
				}
			}
			checker.assertions = append(checker.assertions, ck)

		case "packet_received":
			ck["actual"] = fmt.Sprintf("%f", checker.timers["packet_recv"])
			if !assertInt(int64(checker.timers["packet_recv"]), v) {
				ck["status"] = "FAIL"
				err = errTestStatusFailed{
					msg: fmt.Sprintf("packet_received didn't matched %s", c.Endpoint),
				}
			}
			checker.assertions = append(checker.assertions, ck)
			break
		}
	}
	checker.processICMPResponse(err)
	return nil
}

func timeInMs(t time.Duration) float64 {
	return float64(t) / float64(time.Millisecond)
}
