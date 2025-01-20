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
	checker.attrs.PutInt("check.created_at", start.Unix())
	checker.attrs.PutStr("check.device.browser.type", args.Browser)
	checker.attrs.PutInt("check.run_type", 0)
	checker.attrs.PutStr("check.type", "browser")
	checker.attrs.PutStr("check.device.id", args.Device)
	checker.attrs.PutInt("check.steps.total", int64(checker.c.CheckTestRequest.StepsCount))
	checker.attrs.PutInt("check.steps.completed", 0)
	checker.attrs.PutInt("check.steps.errors", 0)
	checker.attrs.PutInt("check.test_duration", 0)

	cmdArgs := map[string]interface{}{
		"browser":                  args.Browser,
		"collectRum":               true,
		"device":                   args.Device,
		"region":                   args.Region,
		"testId":                   args.TestId,
		"recording":                checker.c.CheckTestRequest.Recording,
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
		"headers":                  checker.c.CheckTestRequest.Headers,
		"waitTimeout":              checker.c.CheckTestRequest.Timeout,
		"sslCertificatePrivateKey": checker.c.Request.SslCertificatePrivateKey,
		"sslCertificate":           checker.c.Request.SslCertificate,
		"stepsCount":               checker.c.CheckTestRequest.StepsCount,
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

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		tStatus.msg = "Failed to parse result"
		tStatus.status = testStatusError
		checker.timers["browser"] = timeInMs(time.Since(start))
		return tStatus
	}
	checker.attrs.PutStr("check.test_report", string(body))
	//TODO: verify what all attributes to be sent to clickhouse

	// Process the response status
	testResult, ok := result["result"].(map[string]interface{})
	if ok {
		if configResult, ok := testResult["config"].(map[string]interface{}); ok {
			if deviceResult, ok := configResult["device"].(map[string]interface{}); ok {
				if browserResult, ok := deviceResult["browser"].(map[string]interface{}); ok {
					checker.attrs.PutStr("check.device.browser.user_agent", browserResult["user_agent"].(string))
				}
				if resolutionResult, ok := deviceResult["resolution"].(map[string]interface{}); ok {
					checker.attrs.PutInt("check.device.resolution.width", int64(resolutionResult["width"].(float64)))
					checker.attrs.PutInt("check.device.resolution.height", int64(resolutionResult["height"].(float64)))
					checker.attrs.PutBool("check.device.resolution.isMobile", resolutionResult["isMobile"].(bool))
				}
			}
		}
		checker.attrs.PutInt("check.timeToInteractive", int64(testResult["timeToInteractive"].(float64)))
		if testSummary, ok := testResult["test_summary"].(map[string]interface{}); ok {
			checker.attrs.PutInt("check.steps.completed", int64(testSummary["completed"].(float64)))
			checker.attrs.PutInt("check.steps.errors", int64(testSummary["errors"].(float64)))
		}
		if statusResult, ok := testResult["status"].(string); ok {
			if statusResult == "FAILED" {
				tStatus.status = testStatusFail
				failureResult, ok := testResult["failure"].(map[string]interface{})
				if ok {
					tStatus.msg = failureResult["message"].(string)
				}
			}
		}
	}

	checker.attrs.PutInt("check.test_duration", int64(result["test_duration"].(float64)))
	checker.timers["browser"] = timeInMs(time.Since(start))
	return tStatus
}

func (checker *browserChecker) Check() testStatus {
	args := checker.CmdArgs
	testStatus := checker.runBrowserTest(args)
	return testStatus
}
