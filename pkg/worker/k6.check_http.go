package worker

import (
	"encoding/json"
	"fmt"
	"time"
)

func (checker *httpChecker) checkHTTPMultiStepsRequest(c SyntheticCheck) testStatus {
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
		if allAssertions, ok := response["assertions"].(map[string]interface{}); ok {
			isfail := false
			stepNumber := 1
			for _, assertions := range allAssertions {
				isFirst := true
				if assertList, ok := assertions.(map[string]interface{}); ok {
					for _, assert := range assertList {
						newAsrt := make(map[string]string)
						if asrt, ok1 := assert.(map[string]interface{}); ok1 {
							for k, v := range asrt {
								newAsrt[k] = fmt.Sprintf("%v", v)
							}
						} else {
							if asrt, ok1 := assert.(map[string]string); ok1 {
								for k, v := range asrt {
									newAsrt[k] = fmt.Sprintf("%v", v)
								}
							}
						}
						if isFirst {
							newAsrt["step"] = fmt.Sprintf("Step%v", stepNumber)
							isFirst = false
							stepNumber++
						}
						checker.assertions = append(checker.assertions, newAsrt)
						if newAsrt["status"] == testStatusFail && !isfail {
							isfail = true
							testStatus.status = testStatusFail
							testStatus.msg = "one or more assertions failed, " + newAsrt["reason"]
						}
					}
				}
			}
		} else {
			for _, allallAssertions := range c.Request.HTTPMultiSteps {
				for _, assert := range allallAssertions.Request.Assertions.HTTP.Cases {
					ck := AssertResult{
						Type: assert.Type,
						Reason: AssertObj{
							Verb:     "should be",
							Operator: assert.Config.Operator,
							Value:    assert.Config.Value,
						},
						Status: testStatusFail,
						Actual: "N/A",
					}
					checker.assertions = append(checker.assertions, ck.ToMap())
				}
			}
		}
	}

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))
	// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
	return testStatus
}
