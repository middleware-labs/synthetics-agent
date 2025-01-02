package worker

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

type browserChecker struct {
	c        SyntheticCheck
	testBody map[string]interface{}
	timers   map[string]float64
	attrs    pcommon.Map
	cmdArgs  commandArgs
}

// getTimers implements protocolChecker.
func (checker *browserChecker) getTimers() map[string]float64 {
	return checker.timers
}

type commandArgs struct {
	browser    string
	collectRum bool
	device     string
	region     string
	testId     string
}

func newBrowserChecker(c SyntheticCheck) *browserChecker {
	return &browserChecker{
		c:        c,
		testBody: make(map[string]interface{}),
		timers:   make(map[string]float64),

		attrs: pcommon.NewMap(),
	}
}

func (checker *browserChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *browserChecker) runBrowserTest(args commandArgs) testStatus {
	tStatus := testStatus{
		status: testStatusOK,
	}
	nodeScript := "./browser-tests/pup.js"

	// Create command with browser option
	cmd := exec.Command("node", nodeScript, "--browser", args.browser, "--collectRum", "--device", args.device, "--region", args.region, "--testId", args.testId)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		tStatus.msg = fmt.Sprintf("Failed to run browser test %v", err)
		tStatus.status = testStatusError
		log.Printf("Error running Node.js script for %s: %v\nOutput: %s", args.browser, err, out.String())
		return tStatus
	}

	checker.attrs.PutStr("test_report", out.String())
	return tStatus
	//upload screenshots to azure storage
}

func (checker *browserChecker) check() testStatus {
	args := checker.cmdArgs
	return checker.runBrowserTest(args)
}
