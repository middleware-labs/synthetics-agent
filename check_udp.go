package syntheticsagent

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

func CheckUdpRequest(c SyntheticsModelCustom) {
	timers := map[string]float64{
		"duration": 0,
		"dns":      0,
		"dial":     0,
	}
	attrs := pcommon.NewMap()
	_start := time.Now()

	assertions := make([]map[string]string, 0)
	_Status := "OK"
	_Message := ""
	received := make([]byte, 1024)

	addr, err := net.ResolveUDPAddr("udp", c.Endpoint+":"+c.Request.Port)
	if err != nil {
		log.Printf("error resolving dns %v", err)
		_Status = "FAIL"
		_Message = fmt.Sprintf("error resolving dns %v", err)
	} else {
		timers["dns"] = timeInMs(time.Since(_start))
		_start = time.Now()

		conn, udpErr := net.DialUDP("udp", nil, addr)
		if udpErr != nil {
			println("Listen failed:", udpErr.Error())

			_Status = "FAIL"
			_Message = fmt.Sprintf("error connecting udp %v", udpErr)

		} else {
			defer conn.Close()

			timers["dial"] = timeInMs(time.Since(_start))
			_, err = conn.Write([]byte(c.Request.UDPPayload.Message))
			if err != nil {
				_Status = "FAIL"
				_Message = fmt.Sprintf("udp write message failed, %v", err.Error())

			} else {
				err = conn.SetReadDeadline(time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThen) * time.Second))
				if err != nil {
					_Status = "FAIL"
					_Message = fmt.Sprintf("conn SetReadDeadline failed, %v", err.Error())
				} else {
					_, err = conn.Read(received)
					if err != nil {
						_Status = "FAIL"
						_Message = fmt.Sprintf("error reading message, %v", err.Error())
					}
				}
			}
		}
	}

	timers["duration"] = timeInMs(time.Since(_start))

	for _, assert := range c.Request.Assertions.UDP.Cases {
		_ck := make(map[string]string)
		_ck["type"] = strings.ReplaceAll(assert.Type, "_", " ")

		switch assert.Type {
		case "response_time":
			dur := timers["duration"]
			_ck["actual"] = fmt.Sprintf("%v", dur)
			_ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + fmt.Sprintf("%v", assert.Config.Value)
			_ck["status"] = "OK"

			if !assertInt(int64(dur), assert) {
				_ck["status"] = "FAIL"
				_Status = "FAIL"
				_Message = "response time didn't matched with condition"
			}
			assertions = append(assertions, _ck)
			break
		case "receive_message":
			_ck["actual"] = "Matched"
			_ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
			_ck["status"] = "OK"
			if !assertString(string(received), assert) {
				_ck["status"] = "FAIL"
				_ck["actual"] = "Not Matched"
				_Status = "FAIL"
				_Message = "response message didn't matched with condition"
			}
			assertions = append(assertions, _ck)
			break
		}
	}

	resultStr, _ := json.Marshal(assertions)
	attrs.PutStr("assertions", string(resultStr))

	FinishCheckRequest(c, _Status, _Message, timers, attrs)

}
