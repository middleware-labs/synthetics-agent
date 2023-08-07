package synthetics_agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"net"
	"net/http"
	"strings"
	"time"
)

func CheckWsRequest(c SyntheticsModelCustom) {
	_start := time.Now()
	timers := map[string]float64{
		"duration":         0,
		"dns":              0,
		"connect":          0,
		"ssl":              0,
		"ws.write_message": 0,
		"ws.read_message":  0,
	}
	_Status := "OK"
	_Message := ""
	recMsg := ""
	assertions := make([]map[string]string, 0)
	attrs := pcommon.NewMap()
	roots, rtErr := x509.SystemCertPool()
	if rtErr != nil {
		log.Printf("root certificates error  %v", rtErr)
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

	wsDialer := &websocket.Dialer{
		HandshakeTimeout: time.Duration(c.Expect.ResponseTimeLessThen) * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:            roots,
			InsecureSkipVerify: true,
		},
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dnsStart := time.Now()

			dialConn, dcErr := netDialer.DialContext(ctx, network, addr)
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
	if err != nil {
		timers["duration"] = timeInMs(time.Since(_start))
		_Status = "FAIL"
		_Message = fmt.Sprintf("failed to connect websocket, %v", err.Error())
		//FinishCheckRequest(c, "FAIL", fmt.Sprintf("failed to connect websocket, %v", err.Error()), timers, attrs)
		//return
	} else {
		timers["duration"] = timeInMs(time.Since(_start))
		_start = time.Now()

		err = conn.SetWriteDeadline(time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThen) * time.Second))
		if err != nil {
			_Status = "FAIL"
			_Message = fmt.Sprintf("failed to set WriteDeadline, %v", err.Error())
		} else {
			err = conn.SetReadDeadline(time.Now().Add(time.Duration(c.Expect.ResponseTimeLessThen) * time.Second))
			if err != nil {
				_Status = "FAIL"
				_Message = fmt.Sprintf("failed to set ReadDeadline, %v", err.Error())
			} else {
				err = conn.WriteMessage(websocket.TextMessage, []byte(c.Request.HTTPPayload.RequestBody.Content))
				if err != nil {
					_Status = "FAIL"
					_Message = fmt.Sprintf("write message to ws failed, %v", err.Error())

				} else {
					timers["ws.write_message"] = timeInMs(time.Since(_start))
					_start = time.Now()

					msgType, msg, mErr := conn.ReadMessage()
					if mErr != nil {
						_Status = "FAIL"
						_Message = fmt.Sprintf("read message failed, %v", mErr.Error())
					} else {
						timers["ws.read_message"] = timeInMs(time.Since(_start))
						attrs.PutInt("ws.message_type", int64(msgType))
						attrs.PutInt("ws.message_length", int64(len(msg)))
						recMsg = string(msg)
					}
				}
			}
		}

	}

	for _, assert := range c.Request.Assertions.WebSocket.Cases {
		_ck := make(map[string]string)
		_ck["type"] = strings.ReplaceAll(assert.Type, "_", " ")
		switch assert.Type {
		case "response_time":
			_ck["actual"] = fmt.Sprintf("%v", timers["duration"])
			_ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + fmt.Sprintf("%v", assert.Config.Value)
			if !assertInt(int64(timers["duration"]), assert) {
				_ck["status"] = "FAIL"
				_Status = "FAIL"
				_Message = fmt.Sprintf("response time not matched with condition")
			} else {
				_ck["status"] = "PASS"
				_ck["reason"] = "response time matched with condition"
			}
			assertions = append(assertions, _ck)
			break
		case "received_message":
			_ck["actual"] = recMsg
			_ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
			if !assertString(recMsg, assert) {
				_ck["status"] = "FAIL"
				_Status = "FAIL"
				_Message = fmt.Sprintf("received message not matched with condition")
			} else {
				_ck["status"] = "PASS"
			}
			assertions = append(assertions, _ck)
			break
		case "header":
			if httpResp != nil && len(httpResp.Header) > 0 {
				_vl := httpResp.Header.Get(assert.Config.Target)
				_ck["actual"] = _vl
				_ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
				if !assertString(_vl, assert) {
					_ck["status"] = "FAIL"
					_Status = "FAIL"
					_Message = fmt.Sprintf("response header didn't matched with condition")
				} else {
					_ck["status"] = "PASS"
				}
			} else {
				_ck["status"] = "FAIL"
				_ck["actual"] = "No Header"
				_ck["reason"] = "should be " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value
				_Status = "FAIL"
				_Message = fmt.Sprintf("response header didn't matched with condition")
			}
			assertions = append(assertions, _ck)
			break
		}
	}

	resultStr, _ := json.Marshal(assertions)
	attrs.PutStr("assertions", string(resultStr))

	FinishCheckRequest(c, _Status, _Message, timers, attrs)

}
