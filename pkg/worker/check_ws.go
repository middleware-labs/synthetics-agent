package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"log/slog"

	"github.com/gorilla/websocket"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type wsChecker struct {
	c          SyntheticsModelCustom
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
}

func newWSChecker(c SyntheticsModelCustom) protocolChecker {
	return &wsChecker{
		c: c,
		timers: map[string]float64{
			"duration":         0,
			"dns":              0,
			"connect":          0,
			"ssl":              0,
			"ws.write_message": 0,
			"ws.read_message":  0,
		},
		testBody: map[string]interface{}{
			"url":              c.Endpoint,
			"host":             "N/A",
			"version":          "HTTP/1.1",
			"req_conn":         "N/A",
			"sent_message":     c.Request.WSPayload.Message,
			"received_message": "N/A",
			"headers":          make(map[string]string),
		},
		assertions: make([]map[string]string, 0),
		attrs:      pcommon.NewMap(),
	}
}

func (checker *wsChecker) getWSDialer() *websocket.Dialer {
	c := checker.c
	roots, rtErr := x509.SystemCertPool()
	if rtErr != nil {
		slog.Error("root certificates error", slog.String("error", rtErr.Error()))
		return nil
	}
	netDialer := &net.Dialer{
		Timeout: time.Duration(c.Expect.ResponseTimeLessThen) * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
		},
	}
	tlsDialer := &tls.Dialer{
		NetDialer: netDialer,
	}

	return &websocket.Dialer{
		HandshakeTimeout: time.Duration(c.Expect.ResponseTimeLessThen) * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:            roots,
			InsecureSkipVerify: true,
		},
		NetDialContext: func(ctx context.Context, network,
			addr string) (net.Conn, error) {
			dnsStart := time.Now()

			dialConn, dcErr := netDialer.DialContext(ctx, network, addr)
			if dcErr != nil {
				checker.timers["dns"] = timeInMs(time.Since(dnsStart))
				return nil, dcErr
			}

			dnsDuration := time.Since(dnsStart)
			checker.timers["dns"] = timeInMs(dnsDuration)

			tlsConn, tlsErr := tlsDialer.Dial(network, dialConn.RemoteAddr().String())
			if tlsErr != nil {
				_ = dialConn.Close()
				return nil, tlsErr
			}

			sslDuration := timeInMs(time.Since(dnsStart) - dnsDuration)
			checker.timers["ssl"] = sslDuration

			return tlsConn, nil
		},
	}
}

func (checker *wsChecker) fillWSAssertions(httpResp *http.Response,
	recMsg string) testStatus {
	c := checker.c
	testStatus := testStatus{
		status: testStatusOK,
	}

	for _, assert := range c.Request.Assertions.WebSocket.Cases {
		ck := make(map[string]string)
		ck["type"] = strings.ReplaceAll(assert.Type, "_", " ")
		switch assert.Type {
		case "response_time":
			ck["actual"] = fmt.Sprintf("%v", checker.timers["duration"])
			ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + fmt.Sprintf("%v", assert.Config.Value)
			if !assertInt(int64(checker.timers["duration"]), assert) {
				testStatus.status = testStatusFail
				testStatus.msg = "response time not matched with the condition"
				ck["status"] = testStatus.status
				ck["reason"] = testStatus.msg
			} else {
				ck["status"] = testStatusPass
				ck["reason"] = "response time matched with the condition"
			}
			checker.assertions = append(checker.assertions, ck)
		case "received_message":
			ck["actual"] = recMsg
			ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
			if !assertString(recMsg, assert) {
				testStatus.status = testStatusFail
				testStatus.msg = "received message not matched with the condition"

				ck["status"] = testStatus.status
				ck["reason"] = testStatus.msg
			} else {
				ck["status"] = testStatusPass
			}
			checker.assertions = append(checker.assertions, ck)

		case "header":
			if httpResp != nil && len(httpResp.Header) > 0 {
				vl := httpResp.Header.Get(assert.Config.Target)
				ck["actual"] = vl
				ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
				if !assertString(vl, assert) {
					testStatus.status = testStatusFail
					testStatus.msg = "response header didn't matched with the condition"
					ck["status"] = testStatus.status
					ck["reason"] = testStatus.msg
				} else {
					ck["status"] = testStatusPass
				}
			} else {
				testStatus.status = testStatusFail
				testStatus.msg = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
				ck["status"] = testStatus.status
				ck["actual"] = "No Header"
				ck["reason"] = testStatus.msg
			}
			checker.assertions = append(checker.assertions, ck)
		}
	}

	return testStatus
}

func (checker *wsChecker) processWSResonse(testStatus testStatus, httpResp *http.Response,
	recMsg string) {
	c := checker.c

	if httpResp != nil && len(httpResp.Header) > 0 {
		checker.testBody["req_conn"] = httpResp.Header.Get("Connection")
		checker.testBody["host"] = httpResp.Request.Host
		headers := make(map[string]string)
		for k, v := range httpResp.Header {
			headers[k] = v[0]
		}

		checker.testBody["headers"] = headers
	}

	if c.CheckTestRequest.URL == "" {
		resultStr, _ := json.Marshal(checker.assertions)
		checker.attrs.PutStr("assertions", string(resultStr))

		// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
		return
	}

	assertions := make([]map[string]interface{}, 0)
	assertions = append(assertions, map[string]interface{}{
		"type": "response_time",
		"config": map[string]string{
			"operator": "is",
			"value":    fmt.Sprintf("%v", checker.timers["duration"]),
		},
	})
	assertions = append(assertions, map[string]interface{}{
		"type": "received_message",
		"config": map[string]string{
			"operator": "is",
			"value":    recMsg,
		},
	})

	checker.testBody["assertions"] = assertions
	checker.testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
	// finishTestRequest(c, checker.testBody)

}

func (checker *wsChecker) check() testStatus {
	c := checker.c
	start := time.Now()
	testStatus := testStatus{
		status: testStatusOK,
	}

	wsDialer := checker.getWSDialer()

	headers := make(http.Header)
	for _, v := range c.Request.WSPayload.Headers {
		headers.Set(v.Name, v.Value)
	}
	if c.Request.WSPayload.Authentication.Username != "" && c.Request.WSPayload.Authentication.Password != "" {
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(
			c.Request.WSPayload.Authentication.Username+":"+c.Request.WSPayload.Authentication.Password,
		)))
	}

	conn, httpResp, err := wsDialer.Dial(c.Endpoint, headers)
	if httpResp != nil {
		checker.testBody["version"] = httpResp.Proto
	}

	if err != nil {
		checker.timers["duration"] = timeInMs(time.Since(start))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("failed to connect websocket, %v", err)

		checker.processWSResonse(testStatus, httpResp, "")
		return testStatus
	}

	checker.timers["duration"] = timeInMs(time.Since(start))
	start = time.Now()

	err = conn.SetWriteDeadline(time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThen) * time.Second))
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("failed to set WriteDeadline, %v", err)
		checker.processWSResonse(testStatus, httpResp, "")
		return testStatus

	}

	err = conn.SetReadDeadline(time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThen) * time.Second))
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("failed to set ReadDeadline, %v", err)

		checker.processWSResonse(testStatus, httpResp, "")
		return testStatus
	}

	err = conn.WriteMessage(websocket.TextMessage, []byte(c.Request.HTTPPayload.RequestBody.Content))
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("write message to ws failed, %v", err.Error())

		checker.processWSResonse(testStatus, httpResp, "")
		return testStatus
	}

	checker.timers["ws.write_message"] = timeInMs(time.Since(start))
	start = time.Now()

	msgType, msg, mErr := conn.ReadMessage()
	if mErr != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("read message failed, %v", mErr.Error())

		checker.processWSResonse(testStatus, httpResp, "")
		return testStatus
	}

	checker.timers["ws.read_message"] = timeInMs(time.Since(start))
	checker.attrs.PutInt("ws.message_type", int64(msgType))
	checker.attrs.PutInt("ws.message_length", int64(len(msg)))
	checker.testBody["received_message"] = string(msg)

	return testStatus
}

func (checker *wsChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *wsChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *wsChecker) getTestBody() map[string]interface{} {
	return checker.testBody
}

func (checker *wsChecker) getDetails() map[string]float64 {
	return nil
}
