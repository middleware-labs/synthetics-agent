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

type httpChecker struct {
	c          SyntheticsModelCustom
	client     *http.Client
	assertions []map[string]string
	timestamps map[string]int64
	timers     map[string]float64
	testBody   map[string]interface{}
	attrs      pcommon.Map
}

func newHTTPChecker(c SyntheticsModelCustom) *httpChecker {
	parsedURL, _ := url.Parse(c.Endpoint)
	return &httpChecker{
		c:          c,
		client:     getHTTPClient(c),
		assertions: make([]map[string]string, 0),
		timers: map[string]float64{
			"duration":   0.0,
			"dns":        0.0,
			"connection": 0.0,
			"tls":        0.0,
			"connect":    0.0,
			"first_byte": 0.0,
			"body_read":  0.0,
		},
		timestamps: map[string]int64{},
		testBody: map[string]interface{}{
			"headers":    make(map[string]string),
			"assertions": make([]map[string]interface{}, 0),
			"statusCode": http.StatusFound,
			"method":     c.Request.HTTPMethod,
			"url":        c.Endpoint,
			"authority":  parsedURL.Host,
			"path":       parsedURL.Path + "?" + parsedURL.RawQuery,
			"tookMs":     "0 ms",
			"body":       "",
		},
		attrs: pcommon.NewMap(),
	}
}

func CheckHttpRequest(c SyntheticsModelCustom) {
	if c.Request.HTTPMultiTest && len(c.Request.HTTPMultiSteps) > 0 {
		CheckHTTPMultiStepsRequest(c)
	} else {
		CheckHttpSingleStepRequest(c)
	}
}

func (checker *httpChecker) buildHttpRequest(digest bool) (*http.Request, error) {
	c := checker.c
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
		prereq, err := checker.buildHttpRequest(false)
		if err != nil {
			return nil, fmt.Errorf("error while requesting preauth %v", err)
		}
		respauth, err := checker.client.Do(prereq)
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
		checker.timers["preauth"] = timeInMs(time.Since(_start))
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

func (checker *httpChecker) processHTTPError(err error) {
	c := checker.c

	checker.testBody["body"] = err.Error()
	checker.testBody["statusCode"] = http.StatusInternalServerError

	for _, assert := range c.Request.Assertions.HTTP.Cases {
		checker.assertions = append(checker.assertions, map[string]string{
			"type":   assert.Type,
			"reason": err.Error(),
			"actual": "N/A",
			"status": "FAIL",
		})
	}

	checker.processHTTPResponse(err)
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

func (checker *httpChecker) processHTTPResponse(err error) {
	c := checker.c
	isCheckTestReq := c.CheckTestRequest.URL != ""
	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))

	// todo: will discuss with meghraj
	tt0 := checker.timers["dns"] + checker.timers["connection"] +
		checker.timers["tls"] + checker.timers["connect"] +
		checker.timers["body_read"]
	subTt := tt0 + checker.timers["first_byte"]

	if subTt > checker.timers["duration"] {
		checker.timers["first_byte"] = checker.timers["first_byte"] - tt0
	}

	status := reqStatusOK
	if errors.As(err, &errTestStatusError{}) {
		status = reqStatusError
	} else if errors.As(err, &errTestStatusFail{}) {
		status = reqStatusFail
	}

	/*if err != nil {
		status = reqStatusError
		message = err.Error()
	}*/

	if !isCheckTestReq {
		FinishCheckRequest(c, string(status), err.Error(), checker.timers, checker.attrs)
		return
	}

	assert := []map[string]interface{}{
		{
			"type": "status_code",
			"config": map[string]string{
				"operator": "is",
				"value":    fmt.Sprintf("%v", checker.testBody["statusCode"]),
			},
		},
		{
			"type": "response_time",
			"config": map[string]string{
				"operator": "is",
				"value":    fmt.Sprintf("%v", checker.timers["duration"]),
			},
		},
	}

	if h, k := checker.testBody["headers"].(map[string]string); k && h != nil {
		assert = append(assert, map[string]interface{}{
			"type": "header",
			"config": map[string]string{
				"operator": "is",
				"target":   "Content-Type",
				"value":    h["Content-Type"],
			},
		})
	}

	checker.testBody["assertions"] = assert
	checker.testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])

	WebhookSendCheckRequest(c, checker.testBody)
}

func (checker *httpChecker) getHTTPTraceClientTrace() *httptrace.ClientTrace {
	var startConn time.Time
	var startDns time.Time
	var startConnect time.Time
	var startTls time.Time
	var tlsDone time.Time
	return &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			startConn = time.Now()
			checker.timestamps["start_conn"] = startConn.UnixMilli()
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			checker.timers["connection"] = timeInMs(time.Since(startConn))
			checker.timestamps["got_conn"] = time.Now().UnixMilli()
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			startDns = time.Now()
			checker.timestamps["dns_start"] = startDns.UnixMilli()
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			checker.timers["dns"] = timeInMs(time.Since(startDns))
			checker.timestamps["dns_done"] = time.Now().UnixMilli()
		},
		ConnectStart: func(network, addr string) {
			startConnect = time.Now()
			checker.timestamps["connect_start"] = startConnect.UnixMilli()
		},
		ConnectDone: func(network, addr string, err error) {
			checker.timers["connect"] = timeInMs(time.Since(startConnect))
			checker.timestamps["connect_done"] = time.Now().UnixMilli()
		},
		TLSHandshakeStart: func() {
			startTls = time.Now()
			checker.timestamps["tls_start"] = startTls.UnixMilli()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
			checker.timestamps["tls_end"] = tlsDone.UnixMilli()
			checker.timers["tls"] = timeInMs(time.Since(startTls))
		},
		GotFirstResponseByte: func() {
			checker.timestamps["first_byte"] = time.Now().UnixMilli()
			checker.timers["first_byte"] = timeInMs(time.Since(tlsDone))
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

func (checker *httpChecker) check() error {
	c := checker.c
	start := time.Now()

	var newErr error
	newErr = errTestStatusOK{
		msg: string(reqStatusOK),
	}
	// build http request from client
	httpReq, err := checker.buildHttpRequest(true)
	if err != nil {
		newErr = errTestStatusError{
			msg: fmt.Sprintf("error while building request %v", err),
		}
		checker.timers["duration"] = timeInMs(time.Since(start))

		checker.processHTTPError(newErr)
		return newErr
	}

	// get httptrace client
	trace := checker.getHTTPTraceClientTrace()
	// perform the requested http request
	reqCtx := httpReq.WithContext(httptrace.WithClientTrace(httpReq.Context(), trace))
	resp, err := checker.client.Do(reqCtx)
	if err != nil {
		newErr = errTestStatusError{
			msg: fmt.Sprintf("error while sending request %v", err),
		}

		checker.timers["duration"] = timeInMs(time.Since(start))

		checker.processHTTPError(newErr)
		return newErr
	}

	// process the response and setup attributes
	bodyStart := time.Now()

	checker.attrs.PutStr("check.response.type", resp.Header.Get("content-type"))
	checker.timestamps["response_read"] = time.Now().UnixMilli()

	bs, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // 100kb max we read
	checker.timers["body_read"] = timeInMs(time.Since(bodyStart))
	_ = resp.Body.Close()
	checker.timestamps["response_close"] = time.Now().UnixMilli()

	js, _ := json.Marshal(checker.timestamps)
	checker.attrs.PutStr("checkpoints", string(js))
	bss := string(bs)
	// todo: tmp disabled reason: memory full on large responses
	//if c.Request.HTTPPayload.Privacy.SaveBodyResponse {
	//	attrs.PutStr("check.response.body", bss)
	//}

	checker.timers["duration"] = timeInMs(time.Since(start))

	checker.testBody["tookMs"] = fmt.Sprintf("%v ms", checker.timers["duration"])
	checker.testBody["body"] = bss
	checker.testBody["statusCode"] = resp.StatusCode

	hdr := make(map[string]string)
	for k, v := range resp.Header {
		hdr[k] = strings.Join(v, ",")
		checker.attrs.PutStr("check.details.headers."+k, strings.Join(v, ","))
	}

	checker.testBody["headers"] = hdr

	checker.attrs.PutStr("check.details.body_size",
		fmt.Sprintf("%d KB\n", len(bs)/1024))
	//attrs.PutStr("check.details.body_raw", fmt.Sprintf("%d", string(bs)))

	var checkHttp200 = true
	for _, assert := range c.Request.Assertions.HTTP.Cases {
		artVal := make(map[string]string)
		artVal["type"] = assert.Type
		switch assert.Type {
		case "body":
			var bodyAssertions map[string]string
			bodyAssertions, newErr = getHTTPTestCaseBodyAssertions(bss, assert)
			checker.assertions = append(checker.assertions, bodyAssertions)

		case "body_hash":
			var bodyHashAssertions map[string]string
			bodyHashAssertions, newErr = getHTTPTestCaseBodyHashAssertions(bss, assert)
			checker.assertions = append(checker.assertions, bodyHashAssertions)

		case "header":
			var headerAssertions map[string]string
			assertHeader := resp.Header.Get(assert.Config.Target)
			headerAssertions, newErr = getHTTPTestCaseHeaderAssertions(assertHeader, assert)
			checker.assertions = append(checker.assertions, headerAssertions)

		case "response_time":
			var responseTimeAssertions map[string]string
			responseTime := checker.timers["duration"]
			responseTimeAssertions, newErr =
				getHTTPTestCaseResponseTimeAssertions(responseTime, assert)
			checker.assertions = append(checker.assertions, responseTimeAssertions)

		case "status_code":
			checkHttp200 = false
			var statusCodeAssertions map[string]string
			statusCodeAssertions, newErr =
				getHTTPTestCaseStatusCodeAssertions(resp.StatusCode, assert)
			checker.assertions = append(checker.assertions,
				statusCodeAssertions)
		}
	}

	if checkHttp200 && !(resp.StatusCode >= http.StatusOK &&
		resp.StatusCode < http.StatusMultipleChoices) {
		newErr = errTestStatusFail{
			msg: "response code is not 2XX, received response code: " +
				strconv.Itoa(resp.StatusCode),
		}
	}

	checker.processHTTPResponse(newErr)
	return newErr
}

func CheckHttpSingleStepRequest(c SyntheticsModelCustom) {
	httpChecker := newHTTPChecker(c)
	httpChecker.check()
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
