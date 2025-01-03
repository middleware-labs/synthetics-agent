package worker

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

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

func (checker *browserChecker) runBrowserTest(currentDir string, args CommandArgs) testStatus {
	tStatus := testStatus{
		status: testStatusOK,
	}

	nodeScript := fmt.Sprintf("%s/browser-tests/pup.js", currentDir)
	recordingJson := fmt.Sprintf("%s/browser-tests/recordings/%s.json", currentDir, args.TestId)
	fmt.Printf("Recording JSON: %s\n", recordingJson)
	fmt.Printf("Recording Data: %s\n", checker.c.CheckTestRequest.Recording)
	err := os.WriteFile(recordingJson, []byte(checker.c.CheckTestRequest.Recording), 0644)
	if err != nil {
		fmt.Printf("Error writing JSON to file: %v\n", err)
		return testStatus{status: testStatusError, msg: "Error writing JSON to file"}
	}
	// Create command with browser option
	cmd := exec.Command("node", nodeScript, "--browser", args.Browser, "--collectRum", "--device", args.Device, "--region", args.Region, "--testId", args.TestId, "--recording", recordingJson)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		tStatus.msg = fmt.Sprintf("Failed to run browser test %v", err)
		tStatus.status = testStatusError
		log.Printf("Error running Node.js script for %s: %v\nOutput: %s", args.Browser, err, out.String())
		return tStatus
	}

	checker.attrs.PutStr("test_report", out.String())
	return tStatus
}

func (checker *browserChecker) uploadScreenshots(filePath string, testId string) {
	screenshotDir := filepath.Join("%s/screenshots", testId)

	files, err := os.ReadDir(screenshotDir)
	if err != nil {
		log.Printf("Failed to read screenshot directory for test %s: %v", testId, err)
		return
	}

	var wg sync.WaitGroup
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		wg.Add(1)
		go func(fileName string) {
			defer wg.Done()
			screenshot, err := os.ReadFile(fileName)
			if err != nil {
				log.Printf("Failed to read video file: %v", err)
				return
			}
			err = checker.screenshotStorage.Upload(bytes.NewReader(screenshot), fileName, "image/png", objectstorage.NoCompression)
			if err != nil {
				log.Printf("Failed to upload screenshot %s: %v", fileName, err)
			}
		}(file.Name())
	}

	wg.Wait()
}

func (checker *browserChecker) Check() testStatus {
	args := checker.CmdArgs
	_, filePath, _, _ := runtime.Caller(0)
	currentDir := filepath.Dir(filePath)
	testStatus := checker.runBrowserTest(currentDir, args)
	checker.uploadScreenshots(currentDir, args.TestId)
	return testStatus
}
