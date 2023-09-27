package worker

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

func CheckHttpRequest(c SyntheticsModelCustom) {
	if c.Request.HTTPMultiTest && len(c.Request.HTTPMultiSteps) > 0 {
		CheckHTTPMultiStepsRequest(c)
	} else {
		CheckHttpSingleStepRequest(c)
	}
}

func buildHttpRequest(c SyntheticsModelCustom, client *http.Client,
	timers map[string]float64, digest bool) (*http.Request, error) {

	var reader io.Reader = nil
	if c.Request.HTTPPayload.RequestBody.Content != "" &&
		c.Request.HTTPPayload.RequestBody.Type != "" {
		reader = strings.NewReader(c.Request.HTTPPayload.RequestBody.Content)
	}

	req, err := http.NewRequest(c.Request.HTTPMethod, c.Endpoint, reader)

	if c.Request.HTTPPayload.RequestBody.Type != "" {
		req.Header.Set("Content-Type", c.Request.HTTPPayload.RequestBody.Type)
	}
	for _, header := range strings.Split(c.Request.HTTPPayload.Cookies, "\n") {
		req.Header.Add("Set-Cookie",
			strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(header, "\t", ""), "\n", ""), "\r", "")))
	}

	if c.Request.HTTPPayload.Authentication.Type == "basic" &&
		c.Request.HTTPPayload.Authentication.Basic.Username != "" &&
		c.Request.HTTPPayload.Authentication.Basic.Password != "" {
		req.Header.Set("Authorization", c.Request.HTTPPayload.Authentication.Basic.Username+
			":"+c.Request.HTTPPayload.Authentication.Basic.Password)
	}

	if digest && c.Request.HTTPPayload.Authentication.Type == "digest" &&
		c.Request.HTTPPayload.Authentication.Digest.Username != "" &&
		c.Request.HTTPPayload.Authentication.Digest.Password != "" {
		_start := time.Now()
		prereq, err := buildHttpRequest(c, client, timers, false)
		if err != nil {
			return nil, fmt.Errorf("error while requesting preauth %v", err)
		}
		respauth, err := client.Do(prereq)
		if err != nil {
			return nil, fmt.Errorf("error while requesting preauth %v", err)
		}
		defer respauth.Body.Close()
		if respauth.StatusCode != http.StatusUnauthorized {
			return nil, fmt.Errorf("recieved status code '%v' while preauth but expected %d",
				respauth.StatusCode, http.StatusUnauthorized)
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

	return req, err
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

func processHTTPError(err error, c SyntheticsModelCustom,
	timers map[string]float64,
	testBody map[string]interface{}) {

	assertions := make([]map[string]string, 0)
	attrs := pcommon.NewMap()

	testBody["body"] = err.Error()
	testBody["statusCode"] = http.StatusInternalServerError

	for _, assert := range c.Request.Assertions.HTTP.Cases {
		assertions = append(assertions, map[string]string{
			"type":   assert.Type,
			"reason": err.Error(),
			"actual": "N/A",
			"status": "FAIL",
		})
	}

	processHTTPResponse(err, c, timers, testBody, assertions, attrs)
}

func getHTTPClient(c SyntheticsModelCustom) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Request.HTTPPayload.IgnoreServerCertificateError,
			},
			ForceAttemptHTTP2:   c.Request.HTTPVersion == "HTTP/2",
			DisableKeepAlives:   false,
			MaxIdleConns:        10,
			TLSHandshakeTimeout: time.Duration(math.Min(float64(c.Expect.ResponseTimeLessThen*1000), float64(c.IntervalSeconds*1000-500))) * time.Millisecond,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
		},
		Timeout: time.Duration(math.Min(float64(c.Expect.ResponseTimeLessThen*1000),
			float64(c.IntervalSeconds*1000-500))) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !c.Request.HTTPPayload.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

}

func processHTTPResponse(err error, c SyntheticsModelCustom, timers map[string]float64,
	testBody map[string]interface{}, assertions []map[string]string, attrs pcommon.Map) {

	isCheckTestReq := c.CheckTestRequest.URL != ""
	resultStr, _ := json.Marshal(assertions)
	attrs.PutStr("assertions", string(resultStr))

	// todo: will discuss with meghraj
	tt0 := timers["dns"] + timers["connection"] + timers["tls"] + timers["connect"] + timers["body_read"]
	subTt := tt0 + timers["first_byte"]

	if subTt > timers["duration"] {
		timers["first_byte"] = timers["first_byte"] - tt0
	}

	status := reqStatusOK
	if errors.As(err, &errTestStatusError{}) {
		status = reqStatusError
	} else if errors.As(err, &errTestStatusFail{}) {
		status = reqStatusFail
	}

	message := ""
	if err != nil {
		status = reqStatusError
		message = err.Error()
	}
	if !isCheckTestReq {
		FinishCheckRequest(c, string(status), message, timers, attrs)
		return
	}

	assert := []map[string]interface{}{
		{
			"type": "status_code",
			"config": map[string]string{
				"operator": "is",
				"value":    fmt.Sprintf("%v", testBody["statusCode"]),
			},
		},
		{
			"type": "response_time",
			"config": map[string]string{
				"operator": "is",
				"value":    fmt.Sprintf("%v", timers["duration"]),
			},
		},
	}

	if h, k := testBody["headers"].(map[string]string); k && h != nil {
		assert = append(assert, map[string]interface{}{
			"type": "header",
			"config": map[string]string{
				"operator": "is",
				"target":   "Content-Type",
				"value":    h["Content-Type"],
			},
		})
	}

	testBody["assertions"] = assert
	testBody["tookMs"] = fmt.Sprintf("%.2f ms", timers["duration"])

	WebhookSendCheckRequest(c, testBody)
}

func getHTTPTraceClientTrace(timers map[string]float64,
	timestamps map[string]int64) *httptrace.ClientTrace {
	var startConn time.Time
	var startDns time.Time
	var startConnect time.Time
	var startTls time.Time
	var tlsDone time.Time
	return &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			startConn = time.Now()
			timestamps["start_conn"] = startConn.UnixMilli()
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			timers["connection"] = timeInMs(time.Since(startConn))
			timestamps["got_conn"] = time.Now().UnixMilli()
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			startDns = time.Now()
			timestamps["dns_start"] = startDns.UnixMilli()
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			timers["dns"] = timeInMs(time.Since(startDns))
			timestamps["dns_done"] = time.Now().UnixMilli()
		},
		ConnectStart: func(network, addr string) {
			startConnect = time.Now()
			timestamps["connect_start"] = startConnect.UnixMilli()
		},
		ConnectDone: func(network, addr string, err error) {
			timers["connect"] = timeInMs(time.Since(startConnect))
			timestamps["connect_done"] = time.Now().UnixMilli()
		},
		TLSHandshakeStart: func() {
			startTls = time.Now()
			timestamps["tls_start"] = startTls.UnixMilli()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
			timestamps["tls_end"] = tlsDone.UnixMilli()
			timers["tls"] = timeInMs(time.Since(startTls))
		},
		GotFirstResponseByte: func() {
			timestamps["first_byte"] = time.Now().UnixMilli()
			timers["first_byte"] = timeInMs(time.Since(tlsDone))
		},
	}
}

func getHTTPTestCaseBodyAssertions(body string, assert CaseOptions) (map[string]string, error) {
	assertions := make(map[string]string)
	assertions["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
	var testErr error
	if !assertString(body, assert) {
		testErr = errTestStatusFail{
			msg: "assert failed, body didn't matched",
		}
		assertions["status"] = string(reqStatusFail)
		assertions["actual"] = "Not Matched"
	} else {
		assertions["status"] = string(reqStatusPass)
		assertions["actual"] = "Matched"
	}

	return assertions, testErr
}

func getHTTPTestCaseBodyHashAssertions(body string, assert CaseOptions) (map[string]string, error) {
	assertions := make(map[string]string)
	var testErr error
	var hash string = ""
	switch assert.Config.Target {
	case "md5":
		hs := md5.Sum([]byte(body))
		hash = hex.EncodeToString(hs[:])
	case "sha1":
		hs := sha1.Sum([]byte(body))
		hash = hex.EncodeToString(hs[:])
	case "sha256":
		hs := sha256.Sum256([]byte(body))
		hash = hex.EncodeToString(hs[:])
	case "sha512":
		hs := sha512.Sum512([]byte(body))
		hash = hex.EncodeToString(hs[:])
	}

	assert.Config.Operator = "is"
	assertions["reason"] = "should be " + assert.Config.Operator +
		" " + assert.Config.Value
	assertions["actual"] = hash
	if !assertString(hash, assert) {
		testErr = errTestStatusFail{
			msg: "body hash didn't matched",
		}

		assertions["status"] = string(reqStatusFail)
	} else {
		assertions["status"] = string(reqStatusPass)
	}

	return assertions, testErr
}

func getHTTPTestCaseHeaderAssertions(header string, assert CaseOptions) (map[string]string, error) {
	assertions := make(map[string]string)
	var testErr error
	assertions["actual"] = header
	assertions["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
	if !assertString(header, assert) {
		testErr = errTestStatusFail{
			msg: "assert failed, header (" +
				assert.Config.Target + ")  didn't matched",
		}

		assertions["status"] = string(reqStatusFail)
	} else {
		assertions["status"] = string(reqStatusPass)
	}
	return assertions, testErr
}

func getHTTPTestCaseResponseTimeAssertions(responseTime float64,
	assert CaseOptions) (map[string]string, error) {
	assertions := make(map[string]string)
	var testErr error

	assertions["actual"] = fmt.Sprintf("%v", responseTime)
	assertions["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
	if !assertInt(int64(responseTime), assert) {
		testErr = errTestStatusFail{
			msg: "assert failed, response_time didn't matched",
		}
		assertions["status"] = string(reqStatusFail)
	} else {
		assertions["status"] = string(reqStatusPass)
	}
	return assertions, testErr
}

func getHTTPTestCaseStatusCodeAssertions(statusCode int,
	assert CaseOptions) (map[string]string, error) {
	assertions := make(map[string]string)
	var testErr error
	assertions["actual"] = fmt.Sprintf("%v", statusCode)
	assertions["reason"] = "should be " + assert.Config.Operator +
		" " + assert.Config.Value
	if !assertInt(int64(statusCode), assert) {
		testErr = errTestStatusFail{
			msg: "assert failed, status_code didn't matched (" +
				assert.Config.Value + ") but got " + http.StatusText(statusCode),
		}
		assertions["status"] = string(reqStatusFail)
	} else {
		assertions["status"] = string(reqStatusPass)
	}

	return assertions, testErr
}

func CheckHttpSingleStepRequest(c SyntheticsModelCustom) {

	timestamps := map[string]int64{}
	assertions := make([]map[string]string, 0)
	//_Status := "OK"
	// _Message := ""
	var testErr error
	attrs := pcommon.NewMap()
	_start := time.Now()
	timers := map[string]float64{
		"duration":   0.0,
		"dns":        0.0,
		"connection": 0.0,
		"tls":        0.0,
		"connect":    0.0,
		"first_byte": 0.0,
		"body_read":  0.0,
	}

	parsedURL, _ := url.Parse(c.Endpoint)
	testBody := map[string]interface{}{
		"headers":    make(map[string]string),
		"assertions": make([]map[string]interface{}, 0),
		"statusCode": http.StatusFound,
		"method":     c.Request.HTTPMethod,
		"url":        c.Endpoint,
		"authority":  parsedURL.Host,
		"path":       parsedURL.Path + "?" + parsedURL.RawQuery,
		"tookMs":     "0 ms",
		"body":       "",
	}

	// get http client
	client := getHTTPClient(c)

	// build http request from client
	httpReq, err := buildHttpRequest(c, client, timers, true)
	if err != nil {
		testErr = errTestStatusError{
			msg: fmt.Sprintf("error while building request %v", err),
		}
		timers["duration"] = timeInMs(time.Since(_start))

		processHTTPError(testErr, c, timers, testBody)
		return
	}

	// get httptrace client
	trace := getHTTPTraceClientTrace(timers, timestamps)

	// perform the requested http request
	reqCtx := httpReq.WithContext(httptrace.WithClientTrace(httpReq.Context(), trace))
	resp, err := client.Do(reqCtx)
	if err != nil {
		testErr = errTestStatusError{
			msg: fmt.Sprintf("error while sending request %v", err),
		}

		timers["duration"] = timeInMs(time.Since(_start))

		processHTTPError(testErr, c, timers, testBody)
		return
	}

	// process the response and setup attributes
	bodyStart := time.Now()

	attrs.PutStr("check.response.type", resp.Header.Get("content-type"))
	timestamps["response_read"] = time.Now().UnixMilli()

	bs, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // 100kb max we read
	timers["body_read"] = timeInMs(time.Since(bodyStart))
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

	testBody["tookMs"] = fmt.Sprintf("%v ms", timers["duration"])
	testBody["body"] = bss
	testBody["statusCode"] = resp.StatusCode

	hdr := make(map[string]string)
	for k, v := range resp.Header {
		hdr[k] = strings.Join(v, ",")
		attrs.PutStr("check.details.headers."+k, strings.Join(v, ","))
	}

	testBody["headers"] = hdr

	attrs.PutStr("check.details.body_size", fmt.Sprintf("%d KB\n", len(bs)/1024))
	//attrs.PutStr("check.details.body_raw", fmt.Sprintf("%d", string(bs)))

	var checkHttp200 = true
	for _, assert := range c.Request.Assertions.HTTP.Cases {
		artVal := make(map[string]string)
		artVal["type"] = assert.Type
		switch assert.Type {
		case "body":
			var bodyAssertions map[string]string
			bodyAssertions, testErr = getHTTPTestCaseBodyAssertions(bss, assert)
			assertions = append(assertions, bodyAssertions)

		case "body_hash":
			var bodyHashAssertions map[string]string
			bodyHashAssertions, testErr = getHTTPTestCaseBodyHashAssertions(bss, assert)
			assertions = append(assertions, bodyHashAssertions)

		case "header":
			var headerAssertions map[string]string
			assertHeader := resp.Header.Get(assert.Config.Target)
			headerAssertions, testErr = getHTTPTestCaseHeaderAssertions(assertHeader, assert)
			assertions = append(assertions, headerAssertions)

		case "response_time":
			var responseTimeAssertions map[string]string
			responseTime := timers["duration"]
			responseTimeAssertions, testErr =
				getHTTPTestCaseResponseTimeAssertions(responseTime, assert)
			assertions = append(assertions, responseTimeAssertions)

		case "status_code":
			checkHttp200 = false
			var statusCodeAssertions map[string]string
			statusCodeAssertions, testErr =
				getHTTPTestCaseStatusCodeAssertions(resp.StatusCode, assert)
			assertions = append(assertions, statusCodeAssertions)
		}
	}

	if checkHttp200 && !(resp.StatusCode >= http.StatusOK &&
		resp.StatusCode < http.StatusMultipleChoices) {
		testErr = errTestStatusFail{
			msg: "response code is not 2XX, received response code: " +
				strconv.Itoa(resp.StatusCode),
		}
	}

	processHTTPResponse(testErr, c, timers, testBody, assertions, attrs)
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
