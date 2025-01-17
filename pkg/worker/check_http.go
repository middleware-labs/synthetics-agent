package worker

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

const (
	assertTypeHTTPBody         = "body"
	assertTypeHTTPBodyHash     = "body_hash"
	assertTypeHTTPHeader       = "header"
	assertTypeHTTPResponseTime = "response_time"
	assertTypeHTTPStatusCode   = "status_code"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type httpChecker struct {
	c          SyntheticCheck
	client     httpClient
	assertions []map[string]string
	timestamps map[string]int64
	timers     map[string]float64
	testBody   map[string]interface{}
	attrs      pcommon.Map
	k6Scripter k6Scripter
}

func newHTTPChecker(c SyntheticCheck) (protocolChecker, error) {
	parsedURL, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, err
	}

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
		attrs:      pcommon.NewMap(),
		k6Scripter: &defaultK6Scripter{},
	}, nil
}

func (checker *httpChecker) buildHttpRequest(digest bool) (*http.Request, error) {
	c := checker.c
	var reader io.Reader = nil
	if c.Request.HTTPPayload.RequestBody.Content != "" &&
		c.Request.HTTPPayload.RequestBody.Type != "" {
		reader = strings.NewReader(c.Request.HTTPPayload.RequestBody.Content)
	}

	req, err := http.NewRequest(c.Request.HTTPMethod, c.Endpoint, reader)
	if err != nil {
		return nil, err
	}

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
		auth := c.Request.HTTPPayload.Authentication.Basic.Username + ":" + c.Request.HTTPPayload.Authentication.Basic.Password
		encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Authorization", "Basic "+encodedAuth)
	}

	if digest && c.Request.HTTPPayload.Authentication.Type == "digest" &&
		c.Request.HTTPPayload.Authentication.Digest.Username != "" &&
		c.Request.HTTPPayload.Authentication.Digest.Password != "" {
		start := time.Now()
		prereq, err := checker.buildHttpRequest(false)
		if err != nil {
			return nil, fmt.Errorf("error while requesting preauth: %v", err)
		}
		respauth, err := checker.client.Do(prereq)
		if err != nil {
			return nil, fmt.Errorf("error while requesting preauth: %v", err)
		}
		defer respauth.Body.Close()
		if respauth.StatusCode != http.StatusUnauthorized {
			return nil, fmt.Errorf("recieved status code '%v' while preauth but expected %d",
				respauth.StatusCode, http.StatusUnauthorized)
		}
		parts := digestParts(respauth)
		parts["uri"] = req.URL.RequestURI()
		parts["method"] = c.Request.HTTPMethod
		parts["username"] = c.Request.HTTPPayload.Authentication.Digest.Username
		parts["password"] = c.Request.HTTPPayload.Authentication.Digest.Password
		req.Header.Set("Authorization", getDigestAuthrization(parts))
		checker.timers["preauth"] = timeInMs(time.Since(start))
	}

	for _, header := range c.Request.HTTPHeaders {
		req.Header.Set(header.Name, header.Value)
	}

	return req, err
}

func digestParts(resp *http.Response) map[string]string {
	result := map[string]string{}
	if len(resp.Header["Www-Authenticate"]) > 0 {
		wantedHeaders := []string{"nonce", "realm", "qop", "opaque"}
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

func (checker *httpChecker) processHTTPError(testStatus testStatus) {
	c := checker.c

	checker.testBody["body"] = testStatus.msg
	checker.testBody["statusCode"] = http.StatusInternalServerError

	for _, assert := range c.Request.Assertions.HTTP.Cases {
		checker.assertions = append(checker.assertions, map[string]string{
			"type":   assert.Type,
			"reason": testStatus.msg,
			"actual": "N/A",
			"status": "FAIL",
		})
	}

	checker.processHTTPResponse()
}

func getHTTPClient(c SyntheticCheck) httpClient {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Request.HTTPPayload.IgnoreServerCertificateError,
			},
			ForceAttemptHTTP2: c.Request.HTTPVersion == "HTTP/2",
			DisableKeepAlives: false,
			MaxIdleConns:      10,
			TLSHandshakeTimeout: time.Duration(math.Min(float64(c.Expect.ResponseTimeLessThen*1000),
				float64(c.IntervalSeconds*1000-500))) * time.Millisecond,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
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

func (checker *httpChecker) processHTTPResponse() {
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
				"operator": "less_than",
				"value":    fmt.Sprintf("%v", percentCalc(checker.timers["duration"], 4)),
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

func getHTTPTestCaseBodyAssertions(body string, assert CaseOptions, testStatusMsg []string) (map[string]string, testStatus, []string) {
	assertions := make(map[string]string)
	assertions["reason"] = "should be " + assert.Config.Operator +
		" " + assert.Config.Value
	testStatus := testStatus{
		status: testStatusOK,
	}

	if !assertString(body, assert) {
		testStatus.status = testStatusFail
		testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, body))

		assertions["status"] = testStatusFail
		assertions["actual"] = "Not Matched"
	} else {
		assertions["status"] = testStatusPass
		assertions["actual"] = "Matched"
	}

	return assertions, testStatus, testStatusMsg
}

func getHTTPTestCaseBodyHashAssertions(body string, assert CaseOptions, testStatusMsg []string) (map[string]string, testStatus, []string) {
	assertions := make(map[string]string)
	testStatus := testStatus{
		status: testStatusOK,
	}
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
		testStatus.status = testStatusFail
		testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, hash))
		assertions["status"] = testStatusFail
	} else {
		assertions["status"] = testStatusPass
	}

	return assertions, testStatus, testStatusMsg
}

func getHTTPTestCaseHeaderAssertions(header string, assert CaseOptions, testStatusMsg []string) (map[string]string, testStatus, []string) {
	assertions := make(map[string]string)
	testStatus := testStatus{
		status: testStatusOK,
	}

	assertions["actual"] = header
	assertions["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
	if !assertString(header, assert) {
		testStatus.status = testStatusFail
		testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value, header))
		assertions["status"] = testStatusFail
	} else {
		assertions["status"] = testStatusPass
	}
	return assertions, testStatus, testStatusMsg
}

func getHTTPTestCaseResponseTimeAssertions(responseTime float64,
	assert CaseOptions, testStatusMsg []string) (map[string]string, testStatus, []string) {
	assertions := make(map[string]string)
	testStatus := testStatus{
		status: testStatusOK,
	}

	assertions["actual"] = fmt.Sprintf("%v", responseTime)
	assertions["reason"] = "should be " + assert.Config.Operator + " " + assert.Config.Value
	if !assertFloat(responseTime, assert) {
		testStatus.status = testStatusFail
		testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, responseTime))
		assertions["status"] = testStatusFail
	} else {
		assertions["status"] = testStatusPass
	}
	return assertions, testStatus, testStatusMsg
}

func getHTTPTestCaseStatusCodeAssertions(statusCode int,
	assert CaseOptions, testStatusMsg []string) (map[string]string, testStatus, []string) {
	assertions := make(map[string]string)

	testStatus := testStatus{
		status: testStatusOK,
	}

	assertions["actual"] = fmt.Sprintf("%v", statusCode)
	assertions["reason"] = "should be " + assert.Config.Operator +
		" " + assert.Config.Value
	if !assertInt(int64(statusCode), assert) {
		testStatus.status = testStatusFail
		testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, statusCode))
		assertions["status"] = testStatusFail
	} else {
		assertions["status"] = testStatusPass
	}

	return assertions, testStatus, testStatusMsg
}

func (checker *httpChecker) checkHTTPSingleStepRequest() testStatus {
	c := checker.c
	start := time.Now()

	tStatus := testStatus{
		status: testStatusOK,
	}

	// build http request from client
	httpReq, err := checker.buildHttpRequest(true)
	if err != nil {
		tStatus.status = testStatusError
		tStatus.msg = fmt.Sprintf("error while building request %v", err)
		checker.timers["duration"] = timeInMs(time.Since(start))

		checker.processHTTPError(tStatus)
		return tStatus
	}

	// get httptrace client
	trace := checker.getHTTPTraceClientTrace()
	// perform the requested http request
	reqCtx := httpReq.WithContext(httptrace.WithClientTrace(httpReq.Context(), trace))
	resp, err := checker.client.Do(reqCtx)
	if err != nil {
		tStatus.status = testStatusError
		tStatus.msg = fmt.Sprintf("error while sending request %v", err)

		checker.timers["duration"] = timeInMs(time.Since(start))

		checker.processHTTPError(tStatus)
		return tStatus
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

	checker.timers["duration"] = timeInMs(time.Since(start))

	checker.testBody["tookMs"] = fmt.Sprintf("%v ms", checker.timers["duration"])
	checker.testBody["statusCode"] = resp.StatusCode

	hdr := make(map[string]string)
	for k, v := range resp.Header {
		hdr[k] = strings.Join(v, ",")
		checker.attrs.PutStr("check.details.headers."+k, strings.Join(v, ","))
	}

	checker.testBody["headers"] = hdr

	checker.attrs.PutStr("check.details.body_size",
		fmt.Sprintf("%.4f KB\n", float64(len(bs))/1024.0))

	contentType := hdr["Content-Type"]
	bss := string(bs)
	if strings.Contains(contentType, "application/json") {
		checker.testBody["body"] = bss
		if !c.Request.HTTPPayload.Privacy.SaveBodyResponse {
			checker.attrs.PutStr("check.details.body_raw", bss)
		}
	}

	var checkHttp200 = true
	testStatusMsg := make([]string, 0)
	for _, assert := range c.Request.Assertions.HTTP.Cases {
		assert.Config.Value = strings.TrimSpace(assert.Config.Value)
		var testAssertions map[string]string
		var assertStatus testStatus
		switch assert.Type {
		case assertTypeHTTPBody:
			testAssertions, assertStatus, testStatusMsg = getHTTPTestCaseBodyAssertions(bss, assert, testStatusMsg)

		case assertTypeHTTPBodyHash:
			testAssertions, assertStatus, testStatusMsg = getHTTPTestCaseBodyHashAssertions(bss, assert, testStatusMsg)

		case assertTypeHTTPHeader:
			assertHeader := resp.Header.Get(assert.Config.Target)
			testAssertions, assertStatus, testStatusMsg = getHTTPTestCaseHeaderAssertions(assertHeader, assert, testStatusMsg)

		case assertTypeHTTPResponseTime:
			responseTime := checker.timers["duration"]
			testAssertions, assertStatus, testStatusMsg = getHTTPTestCaseResponseTimeAssertions(responseTime, assert, testStatusMsg)

		case assertTypeHTTPStatusCode:
			checkHttp200 = false
			testAssertions, assertStatus, testStatusMsg = getHTTPTestCaseStatusCodeAssertions(resp.StatusCode, assert, testStatusMsg)
		}

		if assertStatus.status != testStatusOK {
			tStatus.status = testStatusFail
			tStatus.msg = strings.Join(testStatusMsg, "; ")
		}

		assertChecker := map[string]string{
			"type":   assert.Type,
			"status": "OK",
			"reason": fmt.Sprintf("should be %s %s", strings.ReplaceAll(assert.Config.Operator, "_", " "), assert.Config.Value),
			"actual": "N/A",
		}
		for k, v := range testAssertions {
			assertChecker[k] = v
		}
		checker.assertions = append(checker.assertions, assertChecker)
	}

	if checkHttp200 && !(resp.StatusCode >= http.StatusOK &&
		resp.StatusCode < http.StatusMultipleChoices /*300*/) {
		tStatus.status = testStatusFail
		testStatusMsg = append(testStatusMsg, "response code is not 2XX, received response code: "+strconv.Itoa(resp.StatusCode))
		tStatus.msg = strings.Join(testStatusMsg, ", ")
	}

	checker.processHTTPResponse()
	return tStatus
}

func (checker *httpChecker) check() testStatus {
	c := checker.c

	if c.Request.HTTPMultiTest && len(c.Request.HTTPMultiSteps) > 0 {
		return checker.checkHTTPMultiStepsRequest(c)
	}

	return checker.checkHTTPSingleStepRequest()
}

func (checker *httpChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *httpChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *httpChecker) getTestResponseBody() map[string]interface{} {
	return checker.testBody
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
	if opaque, ok := d["opaque"]; ok {
		authorization += fmt.Sprintf(`, opaque="%s"`, opaque)
	}
	return authorization
}
