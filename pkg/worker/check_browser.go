package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/middleware-labs/synthetics-agent/pkg/worker/objectstorage"
	"github.com/middleware-labs/synthetics-agent/pkg/worker/objectstorage/azure"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type browserChecker struct {
	c                 SyntheticCheck
	screenshotStorage objectstorage.ObjectStorage
	testBody          map[string]interface{}
	timers            map[string]float64
	attrs             pcommon.Map
	CmdArgs           CommandArgs
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
	screenshotStorage, _ := azure.NewAzure(&objectstorage.StorageConfig{
		CLOUD_STORAGE_TYPE:          os.Getenv("CLOUD_STORAGE_TYPE"),
		CLOUD_STORAGE_BUCKET_URL:    os.Getenv("CLOUD_STORAGE_BUCKET_URL"),
		CLOUD_STORAGE_BUCKET:        os.Getenv("CLOUD_STORAGE_BUCKET"),
		CLOUD_STORAGE_CLIENT_ID:     os.Getenv("CLOUD_STORAGE_CLIENT_ID"),
		CLOUD_STORAGE_CLIENT_SECRET: os.Getenv("CLOUD_STORAGE_CLIENT_SECRET"),
	})
	return &browserChecker{
		c:                 c,
		screenshotStorage: screenshotStorage,
		testBody:          make(map[string]interface{}),
		timers:            make(map[string]float64),
		attrs:             pcommon.NewMap(),
	}
}

func (checker *browserChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *browserChecker) runBrowserTest(args CommandArgs) (testStatus, []string) {
	tStatus := testStatus{
		status: testStatusOK,
	}

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
	}

	// Handle screenshot URLs
	screenshotUrls := []string{}
	if checker.c.CheckTestRequest.StepsCount != 0 && checker.c.Request.TakeScreenshots {
		for steps := 0; steps < checker.c.CheckTestRequest.StepsCount; steps++ {
			screenshotPath := path.Join("browser-tests", "screenshots", args.TestId, fmt.Sprintf("step-%d.png", steps))
			screenshotUrl, err := checker.screenshotStorage.GetPreSignedUploadUrl(screenshotPath, 30*24*time.Hour)
			if err == nil && screenshotUrl != "" {
				screenshotUrls = append(screenshotUrls, screenshotUrl)
			}
		}
		cmdArgs["screenshotsUrl"] = screenshotUrls
	}

	payload := map[string]interface{}{
		"args": cmdArgs,
	}

	url := os.Getenv("BROWSER_HUB_URL")
	if url == "" {
		tStatus.status = testStatusError
		tStatus.msg = "BROWSER_HUB_URL environment variable not set"
		return tStatus, []string{}
	}

	// Make the HTTP POST request
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		tStatus.status = testStatusError
		tStatus.msg = "Failed to marshal payload"
		return tStatus, []string{}
	}

	resp, err := http.Post(fmt.Sprintf("%s/start", url), "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		tStatus.status = testStatusError
		tStatus.msg = fmt.Sprintf("HTTP request failed: %v", err)
		fmt.Println(err.Error())
		return tStatus, []string{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tStatus.status = testStatusError
		tStatus.msg = "Failed to read response body"
		return tStatus, []string{}
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		tStatus.msg = "Failed to parse result"
		tStatus.status = testStatusError
		return tStatus, []string{}
	}
	fmt.Println(string(body))
	checker.attrs.PutStr("test_report", string(body))

	// Process the response status
	testResult, ok := result["result"].(map[string]interface{})
	if ok {
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

	return tStatus, screenshotUrls
}

func (checker *browserChecker) uploadScreenshots(filePath string, testId string, screenshotsUrl []string) {
	if len(screenshotsUrl) > 0 {
		screenshotDir := path.Join(filePath, "browser-tests", "screenshots", testId)

		files, err := os.ReadDir(screenshotDir)
		if err != nil {
			slog.Error("Failed to read screenshot directory for test %s: %v", testId, err)
			return
		}

		var wg sync.WaitGroup
		for index, file := range files {
			if file.IsDir() {
				continue
			}

			wg.Add(1)
			go func(fileName string) {
				defer wg.Done()
				fmt.Println("fileName", fileName)
				screenshot, err := os.ReadFile(path.Join(screenshotDir, fileName))
				if err != nil {
					slog.Error("Failed to read screenshot file: %v for testId: %s", slog.String("error", err.Error()), slog.String("testId", testId))
					return
				}
				err = checker.screenshotStorage.UploadPreSignedURL(screenshotsUrl[index], bytes.NewReader(screenshot), "image/png")
				if err != nil {
					slog.Error("Failed to upload screenshot %s: %v for testId: ", fileName, slog.String("error", err.Error()), slog.String("testId", testId))
				}
			}(file.Name())
		}
		wg.Wait()
	}
}

func (checker *browserChecker) Check() testStatus {
	args := checker.CmdArgs
	_, filePath, _, _ := runtime.Caller(0)
	currentDir := filepath.Dir(filePath)
	testStatus, screenshotsUrl := checker.runBrowserTest(args)
	checker.uploadScreenshots(currentDir, args.TestId, screenshotsUrl)
	return testStatus
}
