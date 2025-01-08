package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/middleware-labs/synthetics-agent/pkg/worker"
)

func main() {
	recordingData := `
	{
		"title": "Recording 01/01/2025 at 19:04:54",
		"steps": [
			{
				"type": "setViewport",
				"width": 1905,
				"height": 366,
				"deviceScaleFactor": 1,
				"isMobile": false,
				"hasTouch": false,
				"isLandscape": false
			},
			{
				"type": "navigate",
				"url": "https://www.google.com/",
				"assertedEvents": [
					{
						"type": "navigation",
						"url": "https://www.google.com/",
						"title": ""
					}
				]
			}
		]
	}`
	syntheticCheck := worker.SyntheticCheck{
		Uid: "synthetic-check-uid-123",
		SyntheticsModel: worker.SyntheticsModel{
			Id:              1,
			AccountId:       101,
			UserId:          202,
			Proto:           "https",
			SlugName:        "browser-test-example",
			Endpoint:        "https://example.com/test",
			IntervalSeconds: 300,
			Locations:       "us-east-1,eu-west-1",
			Status:          "active",
			Tags:            []string{"browser", "example", "test"},
			Request: worker.SyntheticsRequestOptions{
				TakeScreenshots: false,
				HTTPPayload:     worker.HTTPPayloadOptions{IgnoreServerCertificateError: true},
			},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			Action:     "run",
			AccountKey: "account-key-123",
			AccountUID: "account-uid-456",
			Details: map[string]interface{}{
				"test_type":   "browser",
				"description": "Synthetic browser test for example.com",
			},
			CheckTestRequest: worker.CheckTestRequest{
				URL: "https://example.com",
				Headers: map[string]string{
					"User-Agent": "Synthetic-Browser-Test-Agent",
				},
				Browsers: map[string][]string{
					// "chrome":  {"laptop", "mobile", "tablet"},
					// "firefox": {"laptop"},
					"edge": {"laptop"},
				},
				Recording:  json.RawMessage(recordingData),
				StepsCount: 10,
			},
		},
	}
	browserChecker := worker.NewBrowserChecker(syntheticCheck)
	browsers := syntheticCheck.CheckTestRequest.Browsers
	var wg sync.WaitGroup

	for browser, devices := range browsers {
		wg.Add(1)
		go func(browser string) {
			defer wg.Done()
			for _, device := range devices {
				commandArgs := worker.CommandArgs{
					Browser:    browser,
					CollectRum: true,
					Device:     device,
					Region:     syntheticCheck.Locations,
					TestId:     fmt.Sprintf("%s-%s-%s", string(syntheticCheck.Uid), "india", "hash"),
				}
				browserChecker.CmdArgs = commandArgs
				_ = browserChecker.Check()
				// cs.finishCheckRequest(testStatus, browserChecker.getTimers(), browserChecker.getAttrs())
			}
		}(browser)
	}

	wg.Wait()
}
