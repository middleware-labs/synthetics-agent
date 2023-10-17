package worker

import (
	"encoding/json"
	"fmt"
	"time"
)

func (checker *httpChecker) checkHTTPMultiStepsRequest(c SyntheticsModelCustom) testStatus {
	start := time.Now()
	testStatus := testStatus{
		status: testStatusOK,
	}

	isCheckTestReq := c.CheckTestRequest.URL != ""
	scriptSnippet := CreateScriptSnippet(c)
	respValue, exeErr := checker.k6Scripter.execute(scriptSnippet)
	checker.timers["duration"] = timeInMs(time.Since(start))

	response := make(map[string]interface{}, 0)
	err := json.Unmarshal([]byte(respValue), &response)
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error while parsing response: %v", err)
		return testStatus
	}

	if isCheckTestReq {
		resSteps := response["steps"]
		checker.testBody = map[string]interface{}{
			"multiStepPreview": true,
			"body":             resSteps,
		}
		// finishTestRequest(c, _testBody)
		return testStatus
	}

	if exeErr != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error while executing script: %v", exeErr)

		checker.assertions = append(checker.assertions, map[string]string{
			"type":   "status_code",
			"reason": "Error while executing script",
			"actual": "N/A",
			"status": testStatusFail,
		})
		checker.assertions = append(checker.assertions, map[string]string{
			"type":   "response_time",
			"reason": "Error while executing script",
			"actual": "N/A",
			"status": testStatusFail,
		})
	} else {
		if assertStep, ok := response["assertions"].(map[string]interface{}); ok {
			isfail := false
			for _, assert := range assertStep {
				if asrt, ok1 := assert.(map[string]string); ok1 {
					checker.assertions = append(checker.assertions, asrt)
					if asrt["status"] == testStatusFail && !isfail {
						isfail = true
						testStatus.status = testStatusFail
						testStatus.msg = "one or more assertions failed, " + asrt["reason"]
					}
				}
			}
		} else {
			for _, assert := range c.Request.Assertions.HTTP.Cases {
				checker.assertions = append(checker.assertions, map[string]string{
					"type":   assert.Type,
					"reason": "should be " + assert.Config.Operator + " " + assert.Config.Value,
					"actual": "N/A",
					"status": testStatusFail,
				})
			}
		}
	}

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))
	// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
	return testStatus
}
