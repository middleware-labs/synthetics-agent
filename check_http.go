package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

func buildHttpRequest(c SyntheticsModelCustom, client *http.Client, timers map[string]float64, digest bool) (error, *http.Request) {

	var reader io.Reader = nil
	if c.Request.HTTPPayload.RequestBody.Content != "" && c.Request.HTTPPayload.RequestBody.Type != "" {
		reader = strings.NewReader(c.Request.HTTPPayload.RequestBody.Content)
	}

	req, err := http.NewRequest(c.Request.HTTPMethod, c.Endpoint, reader)

	if c.Request.HTTPPayload.RequestBody.Type != "" {
		req.Header.Set("Content-Type", c.Request.HTTPPayload.RequestBody.Type)
	}
	for _, header := range strings.Split(c.Request.HTTPPayload.Cookies, "\n") {
		req.Header.Add("Set-Cookie", strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(header, "\t", ""), "\n", ""), "\r", "")))
	}
	//log.Printf("c.Request.HTTPPayload.Authentication %v", c.Request.HTTPPayload.Authentication)

	if c.Request.HTTPPayload.Authentication.Type == "basic" && c.Request.HTTPPayload.Authentication.Basic.Username != "" && c.Request.HTTPPayload.Authentication.Basic.Password != "" {
		req.Header.Set("Authorization", c.Request.HTTPPayload.Authentication.Basic.Username+":"+c.Request.HTTPPayload.Authentication.Basic.Password)
	}

	if digest && c.Request.HTTPPayload.Authentication.Type == "digest" && c.Request.HTTPPayload.Authentication.Digest.Username != "" && c.Request.HTTPPayload.Authentication.Digest.Password != "" {
		_start := time.Now()
		err, prereq := buildHttpRequest(c, client, timers, false)
		if err != nil {
			return fmt.Errorf("error while requesting preauth %v", err), nil
		}
		respauth, err := client.Do(prereq)
		if err != nil {
			return fmt.Errorf("error while requesting preauth %v", err), nil
		}
		defer respauth.Body.Close()
		if respauth.StatusCode != http.StatusUnauthorized {
			return fmt.Errorf("Recieved status code '%v' while preauth but expected %d", respauth.StatusCode, http.StatusUnauthorized), nil
		} else {
			parts := digestParts(respauth)
			parts["uri"] = c.Endpoint
			parts["method"] = c.Request.HTTPMethod
			parts["username"] = c.Request.HTTPPayload.Authentication.Digest.Username
			parts["password"] = c.Request.HTTPPayload.Authentication.Digest.Password

			req.Header.Set("Authorization", getDigestAuthrization(parts))
		}
		timers["preauth"] = timeInMs(time.Since(_start))
	}

	for _, header := range c.Request.HTTPHeaders {
		req.Header.Set(header.Name, header.Value)
	}

	return err, req
}
func digestParts(resp *http.Response) map[string]string {
	result := map[string]string{}
	if len(resp.Header["Www-Authenticate"]) > 0 {
		wantedHeaders := []string{"nonce", "realm", "qop"}
		responseHeaders := strings.Split(resp.Header["Www-Authenticate"][0], ",")
		for _, r := range responseHeaders {
			for _, w := range wantedHeaders {
				if strings.Contains(r, w) {
					result[w] = strings.Split(r, `"`)[1]
				}
			}
		}
	}
	return result
}
func CheckHttpRequest(c SyntheticsModelCustom) {
	var _startConn time.Time
	var _startDns time.Time
	var _startConnect time.Time
	var _startTls time.Time
	var _tlsDone time.Time
	timestamps := map[string]int64{}
	assertions := make([]map[string]string, 0)
	_Status := "OK"
	_Message := ""
	attrs := pcommon.NewMap()
	_start := time.Now()
	isCheckTestReq := c.CheckTestRequest.URL != ""
	timers := map[string]float64{
		"duration":   0.0,
		"dns":        0.0,
		"connection": 0.0,
		"tls":        0.0,
		"connect":    0.0,
		"first_byte": 0.0,
		"body_read":  0.0,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Request.HTTPPayload.IgnoreServerCertificateError,
			},
			ForceAttemptHTTP2:  c.Request.HTTPVersion == "HTTP/2",
			DisableKeepAlives:  false,
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
		},
		Timeout: time.Duration(c.Expect.ResponseTimeLessThen) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !c.Request.HTTPPayload.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	rErr, req := buildHttpRequest(c, client, timers, true)
	if rErr != nil {
		_Status = "ERROR"
		timers["duration"] = timeInMs(time.Since(_start))
		_Message = fmt.Sprintf("error while requesting %v", rErr)

		for _, assert := range c.Request.Assertions.HTTP.Cases {
			assertions = append(assertions, map[string]string{
				"type":   assert.Type,
				"reason": "error while requesting",
				"actual": "N/A",
				"status": "FAIL",
			})
		}
	} else {
		trace := &httptrace.ClientTrace{
			GetConn: func(hostPort string) {
				_startConn = time.Now()
				timestamps["start_conn"] = time.Now().UnixMilli()
			},
			GotConn: func(connInfo httptrace.GotConnInfo) {
				timers["connection"] = timeInMs(time.Since(_startConn))
				timestamps["got_conn"] = time.Now().UnixMilli()
			},
			DNSStart: func(info httptrace.DNSStartInfo) {
				_startDns = time.Now()
				timestamps["dns_start"] = time.Now().UnixMilli()
			},
			DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
				timers["dns"] = timeInMs(time.Since(_startDns))
				timestamps["dns_done"] = time.Now().UnixMilli()
			},
			ConnectStart: func(network, addr string) {
				_startConnect = time.Now()
				timestamps["connect_start"] = time.Now().UnixMilli()
			},
			ConnectDone: func(network, addr string, err error) {
				timers["connect"] = timeInMs(time.Since(_startConnect))
				timestamps["connect_done"] = time.Now().UnixMilli()
			},
			TLSHandshakeStart: func() {
				timestamps["tls_start"] = time.Now().UnixMilli()
				_startTls = time.Now()
			},
			TLSHandshakeDone: func(state tls.ConnectionState, err error) {
				_tlsDone = time.Now()
				timestamps["tls_end"] = time.Now().UnixMilli()
				timers["tls"] = timeInMs(time.Since(_startTls))
			},
			GotFirstResponseByte: func() {
				timestamps["first_byte"] = time.Now().UnixMilli()
				timers["first_byte"] = timeInMs(time.Since(_tlsDone))
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		resp, err := client.Do(req)
		if err != nil {
			timers["duration"] = timeInMs(time.Since(_start))
			_Status = "ERROR"
			_Message = fmt.Sprintf("error while sending request %v", err)

			for _, assert := range c.Request.Assertions.HTTP.Cases {
				assertions = append(assertions, map[string]string{
					"type":   assert.Type,
					"reason": "error while sending request",
					"actual": "N/A",
					"status": "FAIL",
				})
			}
		} else {
			_bodyStart := time.Now()

			attrs.PutStr("check.response.type", resp.Header.Get("content-type"))
			timestamps["response_read"] = time.Now().UnixMilli()

			bs, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*100)) // 100kb max we read
			timers["body_read"] = timeInMs(time.Since(_bodyStart))
			_ = resp.Body.Close()
			timestamps["response_close"] = time.Now().UnixMilli()

			js, _ := json.Marshal(timestamps)
			attrs.PutStr("checkpoints", string(js))
			bss := string(bs)
			// todo: tmp disabled reason: memory full on large responses
			//if c.Request.HTTPPayload.Privacy.SaveBodyResponse {
			//	attrs.PutStr("check.response.body", bss)
			//}

			timers["duration"] = timeInMs(time.Since(_start))

			for k, v := range resp.Header {
				attrs.PutStr("check.details.headers."+k, strings.Join(v, ","))
			}
			attrs.PutStr("check.details.body_size", fmt.Sprintf("%d KB\n", len(bs)/1024))
			//attrs.PutStr("check.details.body_raw", fmt.Sprintf("%d", string(bs)))

			var checkHttp200 = true
			for _, assert := range c.Request.Assertions.HTTP.Cases {
				_artVal := make(map[string]string)
				_artVal["type"] = assert.Type
				switch assert.Type {
				case "body":
					_artVal["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
					if !assertString(bss, assert) {
						_Status = "FAIL"
						_Message = "assert failed, body didn't matched"
						_artVal["status"] = "FAIL"
						_artVal["actual"] = "Not Matched"
					} else {
						_artVal["actual"] = "Matched"
						_artVal["status"] = "PASS"
					}
					assertions = append(assertions, _artVal)
					break
				case "body_hash":
					var hash string = ""
					switch assert.Config.Target {
					case "md5":
						hs := md5.Sum([]byte(bss))
						hash = hex.EncodeToString(hs[:])
						break
					case "sha1":
						hs := sha1.Sum([]byte(bss))
						hash = hex.EncodeToString(hs[:])
						break
					case "sha256":
						hs := sha256.Sum256([]byte(bss))
						hash = hex.EncodeToString(hs[:])
						break
					case "sha512":
						hs := sha512.Sum512([]byte(bss))
						hash = hex.EncodeToString(hs[:])
						break
					}
					assert.Config.Operator = "is"
					_artVal["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
					_artVal["actual"] = hash
					if !assertString(hash, assert) {
						_Status = "FAIL"
						_Message = "body hash didn't matched"
						_artVal["status"] = "FAIL"
					} else {
						_artVal["status"] = "PASS"
					}
					assertions = append(assertions, _artVal)
					break
				case "header":
					_artVal["actual"] = resp.Header.Get(assert.Config.Target)
					_artVal["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
					if !assertString(resp.Header.Get(assert.Config.Target), assert) {
						_Status = "FAIL"
						_Message = "assert failed, header (" + assert.Config.Target + ")  didn't matched"
						_artVal["status"] = "FAIL"
					} else {
						_artVal["status"] = "PASS"
					}
					assertions = append(assertions, _artVal)
					break
				case "response_time":
					_artVal["actual"] = fmt.Sprintf("%v", timers["duration"])
					_artVal["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
					if !assertInt(int64(timers["duration"]), assert) {
						_Status = "FAIL"
						_Message = "assert failed, response_time didn't matched"
						_artVal["status"] = "FAIL"
					} else {
						_artVal["status"] = "PASS"
					}
					assertions = append(assertions, _artVal)
					break
				case "status_code":
					checkHttp200 = false
					_artVal["actual"] = fmt.Sprintf("%v", resp.StatusCode)
					_artVal["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
					if !assertInt(int64(resp.StatusCode), assert) {
						_Status = "FAIL"
						_Message = "assert failed, status_code didn't matched (" + assert.Config.Value + ") but got " + resp.Status
						_artVal["status"] = "FAIL"
					} else {
						_artVal["status"] = "PASS"
					}
					assertions = append(assertions, _artVal)
					break
				}
			}

			if checkHttp200 && !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
				_Status = "FAIL"
				_Message = "response code is not 2XX"
			}
		}
	}

	resultStr, _ := json.Marshal(assertions)
	attrs.PutStr("assertions", string(resultStr))

	// todo: will discuss with meghraj
	tt0 := timers["dns"] + timers["connection"] + timers["tls"] + timers["connect"] + timers["body_read"]
	subTt := tt0 + timers["first_byte"]

	if subTt > timers["duration"] {
		timers["first_byte"] = timers["first_byte"] - tt0
	}

	if !isCheckTestReq {
		FinishCheckRequest(c, _Status, _Message, timers, attrs)
	} else {
		//--Finish
		//WebhookSendCheckRequest(c, _body)
	}
}

func getMD5(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getCnonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)[:16]
}

func getDigestAuthrization(digestParts map[string]string) string {
	d := digestParts
	ha1 := getMD5(d["username"] + ":" + d["realm"] + ":" + d["password"])
	ha2 := getMD5(d["method"] + ":" + d["uri"])
	nonceCount := 00000001
	cnonce := getCnonce()
	response := getMD5(fmt.Sprintf("%s:%s:%v:%s:%s:%s", ha1, d["nonce"], nonceCount, cnonce, d["qop"], ha2))
	authorization := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc="%v", qop="%s", response="%s"`,
		d["username"], d["realm"], d["nonce"], d["uri"], cnonce, nonceCount, d["qop"], response)
	return authorization
}
