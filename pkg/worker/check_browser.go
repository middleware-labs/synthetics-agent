package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
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
	CaptureEndpoint string
	Browser         string
	CollectRum      bool
	Device          string
	Region          string
	TestId          string
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

// runBrowserTest asks browser-hub to start the test and returns its reply.
// Any answer other than 200 is an error carrying the hub's reason.
func (checker *browserChecker) runBrowserTest(args CommandArgs) (string, error) {
	cmdArgs := map[string]interface{}{
		"browser":                  args.Browser,
		"device":                   args.Device,
		"region":                   args.Region,
		"testId":                   args.TestId,
		"captureEndpoint":          args.CaptureEndpoint,
		"projectUID":               checker.c.AccountUID,
		"id":                       checker.c.Id,
		"accountKey":               checker.c.AccountKey,
		"proto":                    checker.c.Proto,
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
		return "", errors.New("BROWSER_HUB_URL environment variable not set")
	}

	// The payload carries secrets (basic auth, cookies): never log it.
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal browser-hub payload: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := httpClient.Post(fmt.Sprintf("%s/start", url), "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", fmt.Errorf("browser-hub request failed: %w", err)
	}
	defer resp.Body.Close()

	// browser-hub answers {"status": "..."}; the status names the failure.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	reply := strings.TrimSpace(string(bodyBytes))
	var hubReply struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(bodyBytes, &hubReply) == nil && hubReply.Status != "" {
		reply = hubReply.Status
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("browser-hub returned %d: %s", resp.StatusCode, reply)
	}
	return reply, nil
}

// Check asks browser-hub to start the test. The worker reports the test's
// own result; this only says whether it was started.
func (checker *browserChecker) Check() testStatus {
	args := checker.CmdArgs
	reply, err := checker.runBrowserTest(args)
	if err != nil {
		slog.Error("browser test not started",
			slog.Int("checkId", checker.c.Id),
			slog.String("testId", args.TestId),
			slog.String("error", err.Error()))
		return testStatus{status: testStatusError, msg: err.Error()}
	}
	slog.Info("browser test started",
		slog.Int("checkId", checker.c.Id),
		slog.String("testId", args.TestId),
		slog.String("hub", reply))
	return testStatus{status: testStatusOK}
}
