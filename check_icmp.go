package synthetics_agent

import (
	"encoding/json"
	"fmt"
	probing "github.com/prometheus-community/pro-bing"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"strings"
	"time"
)

func CheckPingRequest(c SyntheticsModelCustom) {
	timers := map[string]float64{
		"duration": 0,
	}
	_details := map[string]float64{
		"packets_sent":     0,
		"packets_received": 0,
		"packet_loss":      0,
		"latency_min":      0,
		"latency_max":      0,
		"latency_avg":      0,
		"latency_std_dev":  0,
	}

	_Status := "OK"
	_Message := ""
	assertions := make([]map[string]string, 0)

	_IsTestReq := c.CheckTestRequest.URL != ""
	_testBody := map[string]interface{}{
		"rcmp_status": "FAILED",
		"packet_size": "0 bytes",
		"packet":      "N/A",
		"latency":     "N/A",
	}

	attrs := pcommon.NewMap()
	pinger, err := probing.NewPinger(c.Endpoint)
	if err != nil {
		pinger.Timeout = time.Second * 5
		pinger.Interval = time.Second
		pinger.Count = c.Request.ICMPPayload.PingsPerTest
		pinger.RecordRtts = false
		pinger.Size = 24

		pinger.SetPrivileged(true)

		err = pinger.Run() // Blocks until finished.
	}
	if err != nil {
		_Status = "ERROR"
		_Message = fmt.Sprintf("error running ping %v", err)
		for _, v := range c.Request.Assertions.ICMP.Cases {
			assertions = append(assertions, map[string]string{
				"type":   v.Type,
				"status": "FAIL",
				"reason": "should be " + strings.ReplaceAll(v.Config.Operator, "_", " ") + " " + v.Config.Value,
				"actual": "N/A",
			})
		}
	} else {
		stats := pinger.Statistics()

		timers["duration"] = timeInMs(stats.AvgRtt)
		timers["packet_loss"] = stats.PacketLoss
		timers["packet_recv"] = float64(stats.PacketsRecv)

		if !_IsTestReq {
			attrs.PutStr("ip", stats.IPAddr.String())
			attrs.PutStr("addr", stats.Addr)

			_details["packets_sent"] = float64(stats.PacketsSent)
			_details["packets_received"] = float64(stats.PacketsRecv)
			_details["packet_loss"] = stats.PacketLoss
			_details["latency_min"] = timeInMs(stats.MinRtt)
			_details["latency_max"] = timeInMs(stats.MaxRtt)
			_details["latency_avg"] = timeInMs(stats.AvgRtt)
			_details["latency_std_dev"] = timeInMs(stats.StdDevRtt)

			if c.Expect.LatencyLimit > 0 && c.Expect.LatencyLimit <= timers["rtt"] {
				_Status = "FAILED"
				_Message = fmt.Sprintf("latency higher then expected %s", c.Endpoint)
			} else if c.Expect.PacketLossLimit > 0 && c.Expect.PacketLossLimit <= stats.PacketLoss {
				_Status = "FAILED"
				_Message = fmt.Sprintf("packet loss higher then expected %s", c.Endpoint)
			}

			for _, v := range c.Request.Assertions.ICMP.Cases {
				_ck := make(map[string]string)
				_ck["type"] = v.Type
				_ck["status"] = "OK"
				_ck["reason"] = "should be " + strings.ReplaceAll(v.Config.Operator, "_", " ") + " " + v.Config.Value

				switch v.Type {
				case "latency":
					_ck["actual"] = fmt.Sprintf("%f", timers["rtt"])
					if !assertInt(int64(timers["duration"]), v) {
						_ck["status"] = "FAIL"
						_Status = "FAILED"
						_Message = fmt.Sprintf("latency didn't matched %s", c.Endpoint)
					}
					assertions = append(assertions, _ck)
					break
				case "packet_loss":
					_ck["actual"] = fmt.Sprintf("%f", timers["packet_loss"])
					if !assertInt(int64(timers["packet_loss"]), v) {
						_ck["status"] = "FAIL"
						_Status = "FAILED"
						_Message = fmt.Sprintf("packet_loss didn't matched %s", c.Endpoint)
					}
					assertions = append(assertions, _ck)
					break
				case "packet_received":
					_ck["actual"] = fmt.Sprintf("%f", timers["packet_recv"])
					if !assertInt(int64(timers["packet_recv"]), v) {
						_ck["status"] = "FAIL"
						_Status = "FAILED"
						_Message = fmt.Sprintf("packet_received didn't matched %s", c.Endpoint)
					}
					assertions = append(assertions, _ck)
					break
				}
			}
		} else {

			_testBody["rcmp_status"] = "SUCCESSFUL"
			_testBody["packet"] = fmt.Sprintf("%d packets sent, %d packets received, %f%% packet loss", stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
			_testBody["latency"] = fmt.Sprintf("min/avg/max/stddev = %f/%f/%f/%f ms",
				timeInMs(stats.MinRtt),
				timeInMs(stats.AvgRtt),
				timeInMs(stats.MaxRtt),
				timeInMs(stats.StdDevRtt))
			// packet_size in bytes
			_testBody["packet_size"] = pinger.Size
		}
	}

	if !_IsTestReq {
		resultStr, _ := json.Marshal(assertions)
		attrs.PutStr("assertions", string(resultStr))

		for k, v := range _details {
			attrs.PutStr(k, fmt.Sprintf("%f", v))
		}

		FinishCheckRequest(c, _Status, _Message, timers, attrs)
	} else {

		_testBody["assertions"] = []map[string]interface{}{
			{
				"type": "latency",
				"config": map[string]interface{}{
					"operator": "less_than",
					"value":    timers["duration"],
				},
			},
			{
				"type": "packet_loss",
				"config": map[string]interface{}{
					"operator": "less_than",
					"value":    timers["packet_loss"],
				},
			},
			{
				"type": "packet_received",
				"config": map[string]interface{}{
					"operator": "less_than",
					"value":    timers["packet_recv"],
				},
			},
		}
		_testBody["tookMs"] = fmt.Sprintf("%.2f ms", timers["duration"])
		WebhookSendCheckRequest(c, _testBody)
	}
}

func timeInMs(t time.Duration) float64 {
	return float64(t) / float64(time.Millisecond)
}
