package worker

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

const (
	assertTypeUDPResponseTime string = "response_time"
	assertTypeUDPRecvMessage  string = "receive_message"
)

type udpChecker struct {
	c          SyntheticCheck
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
	netHelper  udpNetHelper
}

const (
	udpStatusSuccessful = "successful"
	udpStatusFailed     = "failed"
)

func newUDPChecker(c SyntheticCheck) ProtocolChecker {
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
		netHelper:  &defaultUDPNetHelper{},
	}
}

func (checker *udpChecker) processUDPResponse(testStatus *testStatus, received []byte) {
	c := checker.c
	udpStatus := udpStatusSuccessful
	if testStatus.status != testStatusOK {
		udpStatus = udpStatusFailed
	}

	isTestReq := c.CheckTestRequest.URL != ""
	if !isTestReq {

		for _, assert := range c.Request.Assertions.UDP.Cases {
			// do not process assertions if status of any (previous)
			// assertion is not OK
			if testStatus.status != testStatusOK {
				break
			}

			ck := make(map[string]string)
			ck["type"] = strings.ReplaceAll(assert.Type, "_", " ")

			switch assert.Type {
			case assertTypeUDPResponseTime:
				dur := checker.timers["duration"]
				ck["actual"] = fmt.Sprintf("%v", dur)
				ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") +
					" " + fmt.Sprintf("%v", assert.Config.Value)
				ck["status"] = testStatusOK

				if !assertInt(int64(dur), assert) {
					ck["status"] = testStatusFail
					testStatus.status = testStatusFail
					testStatus.msg = "assert failed, response_time didn't matched"
				}

			case assertTypeUDPRecvMessage:
				ck["actual"] = "Matched"
				ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") +
					" " + assert.Config.Value
				ck["status"] = testStatusOK
				if !assertString(string(received), assert) {
					ck["status"] = testStatusFail
					ck["actual"] = "Not Matched"
					testStatus.status = testStatusFail
					testStatus.msg = "assert failed, response message didn't matched"
				}
			}

			checker.assertions = append(checker.assertions, ck)
		}

		resultStr, _ := json.Marshal(checker.assertions)
		checker.attrs.PutStr("assertions", string(resultStr))

		// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
		return
	}

	testBody := make(map[string]interface{})
	testBody["assertions"] = []map[string]interface{}{
		{
			"type": assertTypeUDPResponseTime,
			"config": map[string]string{
				"operator": "is",
				"value":    fmt.Sprintf("%v", checker.timers["duration"]),
			},
		},
	}

	testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
	testBody["udp_status"] = udpStatus

	// finishTestRequest(c, testBody)

}

type udpNetHelper interface {
	resolveUDPAddr(endpoint string) (*net.UDPAddr, error)
	dialUDP(addr *net.UDPAddr) (*net.UDPConn, error)
	writeUDPMessage(conn *net.UDPConn, b []byte) error
	readUDPMessage(conn *net.UDPConn, b []byte) error
	setUDPReadDeadline(conn *net.UDPConn, t time.Time) error
}

type defaultUDPNetHelper struct{}

func (*defaultUDPNetHelper) resolveUDPAddr(endpoint string) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

func (*defaultUDPNetHelper) dialUDP(addr *net.UDPAddr) (*net.UDPConn, error) {
	conn, udpErr := net.DialUDP("udp", nil, addr)
	if udpErr != nil {
		return nil, udpErr
	}

	return conn, nil
}

func (*defaultUDPNetHelper) writeUDPMessage(conn *net.UDPConn, b []byte) error {
	_, err := conn.Write(b)
	if err != nil {
		return err
	}

	return nil
}

func (*defaultUDPNetHelper) readUDPMessage(conn *net.UDPConn, b []byte) error {
	_, err := conn.Read(b)
	if err != nil {
		return err
	}

	return nil
}

func (*defaultUDPNetHelper) setUDPReadDeadline(conn *net.UDPConn, t time.Time) error {
	err := conn.SetReadDeadline(t)
	if err != nil {
		return err
	}

	return nil
}

func (checker *udpChecker) check() testStatus {
	c := checker.c
	start := time.Now()
	testStatus := testStatus{
		status: testStatusOK,
	}

	received := make([]byte, 1024)
	addr, err := checker.netHelper.resolveUDPAddr(c.Endpoint + ":" + c.Request.Port)
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error resolving dns: %v", err)
		checker.timers["duration"] = timeInMs(time.Since(start))
		checker.processUDPResponse(&testStatus, received)
		return testStatus
	}

	start = time.Now()
	checker.timers["dns"] = timeInMs(time.Since(start))
	conn, err := checker.netHelper.dialUDP(addr)
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error connecting udp: %v", err)
		checker.timers["duration"] = timeInMs(time.Since(start))
		checker.processUDPResponse(&testStatus, received)
		return testStatus
	}

	defer conn.Close()

	checker.timers["dial"] = timeInMs(time.Since(start))
	err = checker.netHelper.writeUDPMessage(conn, []byte(c.Request.UDPPayload.Message))
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("udp write message failed: %v", err.Error())
		checker.timers["duration"] = timeInMs(time.Since(start))
		checker.processUDPResponse(&testStatus, received)
		return testStatus
	}

	deadline := time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThen) * time.Second)
	err = checker.netHelper.setUDPReadDeadline(conn, deadline)
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("conn SetUDPReadDeadline failed: %v", err.Error())
		checker.timers["duration"] = timeInMs(time.Since(start))
		checker.processUDPResponse(&testStatus, received)
		return testStatus
	}

	err = checker.netHelper.readUDPMessage(conn, received)
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error reading message: %v", err.Error())
	}

	checker.timers["duration"] = timeInMs(time.Since(start))
	checker.processUDPResponse(&testStatus, received)
	return testStatus
}

func (checker *udpChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *udpChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *udpChecker) getTestResponseBody() map[string]interface{} {
	return checker.testBody
}

func (checker *udpChecker) getDetails() map[string]float64 {
	return nil
}
