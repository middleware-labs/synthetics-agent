package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

type browserChecker struct {
	c        SyntheticCheck
	testBody map[string]interface{}
	timers   map[string]float64
	attrs    pcommon.Map
	CmdArgs  CommandArgs
}

// getTimers implements protocolChecker.
func (checker *browserChecker) getTimers() map[string]float64 {
	return checker.timers
}

type CommandArgs struct {
	Browser    string
	CollectRum bool
	Device     string
	Region     string
	TestId     string
}

type Browser struct {
	UserAgent string `json:"user_agent"`
}

type Resolution struct {
	Width    int  `json:"width"`
	Height   int  `json:"height"`
	IsMobile bool `json:"isMobile"`
}

type Device struct {
	Resolution Resolution `json:"resolution"`
	Browser    Browser    `json:"browser"`
}

type BrowserConfig struct {
	Region string `json:"region"`
	Device Device `json:"device"`
}

type TestSummary struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Errors    int `json:"errors"`
}

type RumConfig struct {
	Enabled     bool   `json:"enabled"`
	ProjectName string `json:"projectName"`
	ServiceName string `json:"serviceName"`
	AccountKey  string `json:"accountKey"`
	Target      string `json:"target"`
	SessionID   string `json:"sessionId"`
}

type Failure struct {
	Message string `json:"message"`
}

type TestResult struct {
	Config            BrowserConfig `json:"config"`
	TestSummary       TestSummary   `json:"test_summary"`
	Status            string        `json:"status"`
	TestDuration      int64         `json:"test_duration"`
	RecordingURL      string        `json:"recordingUrl"`
	ConsoleURL        string        `json:"consoleUrl"`
	HARUrl            string        `json:"harUrl"`
	TimeToInteractive float64       `json:"timeToInteractive"`
	RumConfig         RumConfig     `json:"rumConfig"`
	Failure           *Failure      `json:"failure,omitempty"`
}

type TestReport struct {
	Steps      interface{} `json:"steps"`
	TestResult TestResult  `json:"result"`
}

func NewBrowserChecker(c SyntheticCheck) *browserChecker {
	return &browserChecker{
		c:        c,
		testBody: make(map[string]interface{}),
		timers:   make(map[string]float64),
		attrs:    pcommon.NewMap(),
	}
}

func (checker *browserChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *browserChecker) runBrowserTest(args CommandArgs) testStatus {
	start := time.Now()

	tStatus := testStatus{
		status: testStatusOK,
	}
	checker.attrs.PutStr("check.test_id", args.TestId)
	checker.attrs.PutInt("check.created_at", start.UnixMilli())
	checker.attrs.PutStr("check.device.browser.type", args.Browser)
	checker.attrs.PutInt("check.run_type", 0)
	checker.attrs.PutStr("check.type", "browser")
	checker.attrs.PutStr("check.device.id", args.Device)
	checker.attrs.PutInt("check.steps.total", int64(checker.c.Request.StepsCount))
	checker.attrs.PutInt("check.steps.completed", 0)
	checker.attrs.PutInt("check.steps.errors", 0)
	checker.attrs.PutInt("check.test_duration", 0)

	cmdArgs := map[string]interface{}{
		"browser":                  args.Browser,
		"device":                   args.Device,
		"region":                   args.Region,
		"testId":                   args.TestId,
		"url":                      checker.c.Endpoint,
		"recording":                checker.c.Request.Recording,
		"screenshots":              checker.c.Request.TakeScreenshots,
		"ignoreCertificateErrors":  checker.c.Request.HTTPPayload.IgnoreServerCertificateError,
		"proxyServer":              checker.c.Request.HTTPPayload.Proxy.URL,
		"timezone":                 checker.c.Request.Timezone,
		"language":                 checker.c.Request.Language,
		"username":                 checker.c.Request.HTTPPayload.Authentication.Basic.Username,
		"password":                 checker.c.Request.HTTPPayload.Authentication.Basic.Password,
		"cookies":                  checker.c.Request.HTTPPayload.Cookies,
		"disableCors":              checker.c.Request.DisableCors,
		"disableCsp":               checker.c.Request.DisableCSP,
		"headers":                  checker.c.Request.HTTPHeaders,
		"waitTimeout":              checker.c.Request.Timeout,
		"sslCertificatePrivateKey": checker.c.Request.SslCertificatePrivateKey,
		"sslCertificate":           checker.c.Request.SslCertificate,
		"stepsCount":               checker.c.Request.StepsCount,
		"rumConfig":                checker.c.Request.RUMConfig,
	}

	payload := map[string]interface{}{
		"args": cmdArgs,
	}

	url := os.Getenv("BROWSER_HUB_URL")
	if url == "" {
		tStatus.status = testStatusError
		tStatus.msg = "BROWSER_HUB_URL environment variable not set"
		checker.timers["browser"] = timeInMs(time.Since(start))
		return tStatus
	}

	// Make the HTTP POST request
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		tStatus.status = testStatusError
		tStatus.msg = "Failed to marshal payload"
		checker.timers["browser"] = timeInMs(time.Since(start))
		return tStatus
	}

	resp, err := http.Post(fmt.Sprintf("%s/start", url), "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		tStatus.status = testStatusError
		tStatus.msg = fmt.Sprintf("HTTP request failed: %v", err)
		checker.timers["browser"] = timeInMs(time.Since(start))
		return tStatus
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tStatus.status = testStatusError
		tStatus.msg = "Failed to read response body"
		checker.timers["browser"] = timeInMs(time.Since(start))
		return tStatus
	}

	var result TestReport
	err = json.Unmarshal(body, &result)
	if err != nil {
		tStatus.msg = "Failed to parse result"
		tStatus.status = testStatusError
		checker.timers["browser"] = timeInMs(time.Since(start))
		return tStatus
	}
	checker.attrs.PutStr("check.test_report", string(body))

	// Process the response status
	testResult := result.TestResult
	checker.attrs.PutStr("check.device.browser.user_agent", testResult.Config.Device.Browser.UserAgent)
	checker.attrs.PutInt("check.device.resolution.width", int64(testResult.Config.Device.Resolution.Width))
	checker.attrs.PutInt("check.device.resolution.height", int64(testResult.Config.Device.Resolution.Height))
	checker.attrs.PutBool("check.device.resolution.isMobile", testResult.Config.Device.Resolution.IsMobile)
	checker.attrs.PutInt("check.timeToInteractive", int64(testResult.TimeToInteractive))
	checker.attrs.PutInt("check.steps.completed", int64(testResult.TestSummary.Completed))
	checker.attrs.PutInt("check.steps.errors", int64(testResult.TestSummary.Errors))
	checker.attrs.PutInt("check.test_duration", testResult.TestDuration)
	if testResult.Status == "FAILED" && testResult.Failure != nil {
		tStatus.status = testStatusFail
		tStatus.msg = testResult.Failure.Message
	}

	checker.timers["browser"] = timeInMs(time.Since(start))
	return tStatus
}

func (checker *browserChecker) Check() testStatus {
	args := checker.CmdArgs
	testStatus := checker.runBrowserTest(args)
	return testStatus
}
