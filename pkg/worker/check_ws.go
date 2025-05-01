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

const (
	assertTypeWSResponseTime string = "response_time"
	assertTypeWSRecvMessage  string = "received_message"
	assertTypeWSHeader       string = "header"
)

type defaultTLSDialer struct {
	dialer *tls.Dialer
}

func (d *defaultTLSDialer) GetDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.NetDialer.DialContext(ctx, network, addr)
}

func (d *defaultTLSDialer) Dial(network, addr string) (net.Conn, error) {
	return d.dialer.Dial(network, addr)
}

type wsChecker struct {
	c          SyntheticCheck
	wsDialer   *websocket.Dialer
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
}

func newWSChecker(c SyntheticCheck) protocolChecker {

	timers := map[string]float64{
		"duration":         0,
		"dns":              0,
		"connect":          0,
		"ssl":              0,
		"ws.write_message": 0,
		"ws.read_message":  0,
	}

	return &wsChecker{
		c:        c,
		wsDialer: getWSDialer(c, timers),

		timers: timers,
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

func getWSDialer(c SyntheticCheck, timers map[string]float64) *websocket.Dialer {
	roots, rtErr := x509.SystemCertPool()
	if rtErr != nil {
		slog.Error("root certificates error", slog.String("error", rtErr.Error()))
		return nil
	}

	tlsDialer := &defaultTLSDialer{
		dialer: &tls.Dialer{
			NetDialer: &net.Dialer{
				Timeout: time.Duration(c.Expect.ResponseTimeLessThan) * time.Second,
				Resolver: &net.Resolver{
					PreferGo: true,
				},
			},
		},
	}

	return &websocket.Dialer{
		HandshakeTimeout: time.Duration(c.Expect.ResponseTimeLessThan) * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:            roots,
			InsecureSkipVerify: true,
		},
		NetDialContext: func(ctx context.Context, network,
			addr string) (net.Conn, error) {
			dnsStart := time.Now()

			dialConn, dcErr := tlsDialer.GetDialContext(ctx, network, addr)
			if dcErr != nil {
				timers["dns"] = timeInMs(time.Since(dnsStart))
				return nil, dcErr
			}

			dnsDuration := time.Since(dnsStart)
			timers["dns"] = timeInMs(dnsDuration)

			tlsConn, tlsErr := tlsDialer.Dial(network, dialConn.RemoteAddr().String())
			if tlsErr != nil {
				_ = dialConn.Close()
				return nil, tlsErr
			}

			sslDuration := timeInMs(time.Since(dnsStart) - dnsDuration)
			timers["ssl"] = sslDuration

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
	testStatusMsg := make([]string, 0)
	for _, assert := range c.Request.Assertions.WebSocket.Cases {
		ck := make(map[string]string)

		ck["type"] = strings.ReplaceAll(assert.Type, "_", " ")
		switch assert.Type {
		case assertTypeWSResponseTime:
			ck["actual"] = fmt.Sprintf("%v", checker.timers["duration"])
			ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + fmt.Sprintf("%v", assert.Config.Value)
			if !assertFloat(checker.timers["duration"], assert) {
				ck["status"] = testStatusFail
				ck["reason"] = fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, checker.timers["duration"])
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, checker.timers["duration"]))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			} else {
				ck["status"] = testStatusPass
				ck["reason"] = "response time matched with the condition"
			}
		case assertTypeWSRecvMessage:
			ck["actual"] = recMsg
			ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
			if !assertString(recMsg, assert) {
				ck["status"] = testStatusFail
				ck["reason"] = fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, recMsg)
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, recMsg))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			} else {
				ck["status"] = testStatusPass
			}
		case assertTypeWSHeader:
			if httpResp != nil && len(httpResp.Header) > 0 {
				vl := httpResp.Header.Get(assert.Config.Target)
				ck["actual"] = vl
				ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
				if !assertString(vl, assert) {
					ck["status"] = testStatusFail
					ck["reason"] = fmt.Sprintf("%s %s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value, vl)
					testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value, vl))
					testStatus.status = testStatusFail
					testStatus.msg = strings.Join(testStatusMsg, "; ")
				} else {
					ck["status"] = testStatusPass
				}
			} else {
				testStatus.status = testStatusFail
				ck["status"] = testStatusFail
				ck["actual"] = "No Header"
				ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s %s assertion failed (got no header)", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value))
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			}
		}

		checker.assertions = append(checker.assertions, ck)
	}

	return testStatus
}

func (checker *wsChecker) processWSResonse(testStatus *testStatus, httpResp *http.Response,
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

	tStatus := checker.fillWSAssertions(httpResp, recMsg)
	testStatus.status = tStatus.status
	testStatus.msg = tStatus.msg
	if !c.IsPreviewRequest {
		resultStr, _ := json.Marshal(checker.assertions)
		checker.attrs.PutStr("assertions", string(resultStr))
		return
	}

	assertions := make([]map[string]interface{}, 0)
	assertions = append(assertions, map[string]interface{}{
		"type": assertTypeWSResponseTime,
		"config": map[string]string{
			"operator": "less_than",
			"value":    fmt.Sprintf("%v", percentCalc(checker.timers["duration"], 4)),
		},
	})
	assertions = append(assertions, map[string]interface{}{
		"type": assertTypeWSRecvMessage,
		"config": map[string]string{
			"operator": "is",
			"value":    recMsg,
		},
	})

	checker.testBody["assertions"] = assertions
	checker.testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
}

func (checker *wsChecker) check() testStatus {
	c := checker.c
	start := time.Now()
	checker.attrs.PutInt("check.created_at", start.UnixMilli())

	testStatus := testStatus{
		status: testStatusOK,
	}

	headers := make(http.Header)
	for _, v := range c.Request.WSPayload.Headers {
		headers.Set(v.Name, v.Value)
	}
	if c.Request.WSPayload.Authentication.Username != "" && c.Request.WSPayload.Authentication.Password != "" {
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(
			c.Request.WSPayload.Authentication.Username+":"+c.Request.WSPayload.Authentication.Password,
		)))
	}

	conn, httpResp, err := checker.wsDialer.Dial(c.Endpoint, headers)
	if httpResp != nil {
		checker.testBody["version"] = httpResp.Proto
	}

	if err != nil {
		checker.timers["duration"] = timeInMs(time.Since(start))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("failed to connect websocket, %v", err)

		checker.processWSResonse(&testStatus, httpResp, "")
		return testStatus
	}

	checker.timers["duration"] = timeInMs(time.Since(start))
	start = time.Now()

	err = conn.SetWriteDeadline(time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThan) * time.Second))
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("failed to set WriteDeadline, %v", err)
		checker.processWSResonse(&testStatus, httpResp, "")
		return testStatus

	}

	err = conn.SetReadDeadline(time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThan) * time.Second))
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("failed to set ReadDeadline, %v", err)

		checker.processWSResonse(&testStatus, httpResp, "")
		return testStatus
	}

	err = conn.WriteMessage(websocket.TextMessage, []byte(c.Request.HTTPPayload.RequestBody.Content))
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("write message to ws failed, %v", err.Error())

		checker.processWSResonse(&testStatus, httpResp, "")
		return testStatus
	}

	checker.timers["ws.write_message"] = timeInMs(time.Since(start))
	start = time.Now()

	msgType, msg, mErr := conn.ReadMessage()
	if mErr != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("read message failed, %v", mErr.Error())

		checker.processWSResonse(&testStatus, httpResp, "")
		return testStatus
	}

	checker.timers["ws.read_message"] = timeInMs(time.Since(start))
	checker.attrs.PutInt("ws.message_type", int64(msgType))
	checker.attrs.PutInt("ws.message_length", int64(len(msg)))
	checker.testBody["received_message"] = string(msg)

	checker.processWSResonse(&testStatus, httpResp, "")
	return testStatus
}

func (checker *wsChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *wsChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *wsChecker) getTestResponseBody() map[string]interface{} {
	return checker.testBody
}

func (checker *wsChecker) getDetails() map[string]float64 {
	return nil
}
