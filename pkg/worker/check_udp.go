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

type udpChecker struct {
	c          SyntheticsModelCustom
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
}

const (
	udpStatusSuccessful = "successful"
	udpStatusFailed     = "failed"
)

func newUDPChecker(c SyntheticsModelCustom) *udpChecker {
	return &udpChecker{
		c: c,
		timers: map[string]float64{
			"duration": 0,
			"dns":      0,
			"dial":     0,
		},
		testBody: map[string]interface{}{
			"assertions": make([]map[string]interface{}, 0),
			"tookMs":     "0 ms",
			"udp_status": "",
		},
		assertions: make([]map[string]string, 0),
		attrs:      pcommon.NewMap(),
	}
}

func (checker *udpChecker) processUDPResponse(err error, received []byte, start time.Time) {
	checker.timers["duration"] = timeInMs(time.Since(start))
	c := checker.c
	udpStatus := udpStatusSuccessful
	status := reqStatusOK

	if errors.As(err, &errTestStatusError{}) {
		status = reqStatusError
	} else if errors.As(err, &errTestStatusFail{}) {
		status = reqStatusFail
	}

	isTestReq := c.CheckTestRequest.URL != ""
	if !isTestReq {
		for _, assert := range c.Request.Assertions.UDP.Cases {
			// do not process assertions if status of any (previous)
			// assertion is not OK
			if status != reqStatusOK {
				break
			}

			ck := make(map[string]string)
			ck["type"] = strings.ReplaceAll(assert.Type, "_", " ")

			switch assert.Type {
			case "response_time":
				dur := checker.timers["duration"]
				ck["actual"] = fmt.Sprintf("%v", dur)
				ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") +
					" " + fmt.Sprintf("%v", assert.Config.Value)
				ck["status"] = string(reqStatusOK)

				if !assertInt(int64(dur), assert) {
					ck["status"] = string(reqStatusFail)
					udpStatus = udpStatusFailed
					status = reqStatusFail
					err = errTestStatusFail{
						msg: "assert failed, response_time didn't matched",
					}
				}

			case "receive_message":
				ck["actual"] = "Matched"
				ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") +
					" " + assert.Config.Value
				ck["status"] = string(reqStatusOK)

				if !assertString(string(received), assert) {
					ck["status"] = string(reqStatusFail)
					ck["actual"] = "Not Matched"
					status = reqStatusFail
					udpStatus = udpStatusFailed
					err = errTestStatusFail{
						msg: "assert failed, response message didn't matched",
					}
				}
			}

			checker.assertions = append(checker.assertions, ck)
		}

		resultStr, _ := json.Marshal(checker.assertions)
		checker.attrs.PutStr("assertions", string(resultStr))

		FinishCheckRequest(c, string(status), err.Error(), checker.timers, checker.attrs)
		return
	}

	testBody := make(map[string]interface{})
	testBody["assertions"] = []map[string]interface{}{
		{
			"type": "response_time",
			"config": map[string]string{
				"operator": "is",
				"value":    fmt.Sprintf("%v", checker.timers["duration"]),
			},
		},
	}

	testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
	testBody["udp_status"] = udpStatus

	WebhookSendCheckRequest(c, testBody)

}

func (checker *udpChecker) resolveUDPAddr(endpoint string) (*net.UDPAddr, error) {
	var newErr error
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		newErr = errTestStatusFail{
			msg: fmt.Sprintf("error resolving dns %v", err),
		}

		return nil, newErr
	}

	return addr, nil
}

func (checker *udpChecker) dialUDP(addr *net.UDPAddr, start time.Time) (*net.UDPConn, error) {
	checker.timers["dns"] = timeInMs(time.Since(start))
	conn, udpErr := net.DialUDP("udp", nil, addr)
	if udpErr != nil {
		println("Listen failed:", udpErr.Error())
		newErr := errTestStatusFail{
			msg: fmt.Sprintf("error connecting udp: %v", udpErr),
		}
		return nil, newErr
	}

	return conn, nil
}

func (checker *udpChecker) writeUDPMessage(conn *net.UDPConn, start time.Time, b []byte) error {
	checker.timers["dial"] = timeInMs(time.Since(start))
	_, err := conn.Write(b)
	if err != nil {
		newErr := errTestStatusFail{
			msg: fmt.Sprintf("udp write message failed, %v", err.Error()),
		}
		return newErr
	}

	return nil
}

func (checker *udpChecker) setReadDeadline(conn *net.UDPConn, t time.Time) error {
	err := conn.SetReadDeadline(t)
	if err != nil {
		newErr := errTestStatusFail{
			msg: fmt.Sprintf("conn SetReadDeadline failed, %v", err.Error()),
		}

		return newErr
	}

	return nil
}

func (checker *udpChecker) check() error {
	var newErr error
	c := checker.c
	start := time.Now()

	received := make([]byte, 1024)
	addr, err := checker.resolveUDPAddr(c.Endpoint + ":" + c.Request.Port)
	if err != nil {
		checker.processUDPResponse(err, received, start)
		return err
	}

	start = time.Now()
	conn, err := checker.dialUDP(addr, start)
	if err != nil {
		checker.processUDPResponse(err, received, start)
		return err
	}

	defer conn.Close()

	err = checker.writeUDPMessage(conn, start, []byte(c.Request.UDPPayload.Message))
	if err != nil {
		checker.processUDPResponse(err, received, start)
		return err
	}

	deadline := time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThen) * time.Second)
	err = checker.setReadDeadline(conn, deadline)
	if err != nil {
		checker.processUDPResponse(err, received, start)
		return err
	}

	_, err = conn.Read(received)
	if err != nil {
		err = errTestStatusFail{
			msg: fmt.Sprintf("error reading message, %v", err.Error()),
		}
	}

	checker.processUDPResponse(err, received, start)
	return newErr
}

func CheckUdpRequest(c SyntheticsModelCustom) {
	checker := newUDPChecker(c)
	checker.check()
}
