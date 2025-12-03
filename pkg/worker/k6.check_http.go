package worker

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

func (checker *httpChecker) checkHTTPMultiStepsRequest(c SyntheticCheck) testStatus {
	start := time.Now()
	checker.attrs.PutInt("check.created_at", start.UnixMilli())
	checker.attrs.PutBool("check.isMultiStep", true)
	testStatus := testStatus{
		status: testStatusOK,
	}

	isCheckTestReq := c.IsPreviewRequest
	scriptSnippet := CreateScriptSnippet(c)
	respValue, exeErr := checker.k6Scripter.execute(scriptSnippet)
	if exeErr != nil {
		slog.Error("error while executing sciptsnippet", slog.String("err", exeErr.Error()))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error while executing sciptsnippet: %v", exeErr)
		return testStatus
	}
	checker.timers["duration"] = timeInMs(time.Since(start))

	response := make(map[string]interface{}, 0)
	err := json.Unmarshal([]byte(respValue), &response)
	if err != nil {
		slog.Error("error while unmarshaling response from k6Scripter.execute()", slog.String("err", err.Error()))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error while parsing response: %v", err)
		return testStatus
	}
	resSteps, resHeaders := response["steps"], response["headers"]
	checker.testBody = map[string]interface{}{
		"multiStepPreview": true,
		"body":             resSteps,
		"headers":          resHeaders,
	}
	if isCheckTestReq {
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
					checker.assertions = append(checker.assertions, map[string]string{
						"type":   assert.Type,
						"reason": "should be " + assert.Config.Operator + " " + assert.Config.Value,
						"actual": "N/A",
						"status": testStatusFail,
					})
				}
			}
		}
	}

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))
	rawResponse, _ := json.Marshal(resSteps)
	checker.attrs.PutStr("check.details.body_raw", string(rawResponse))
	for k, v := range resHeaders.(map[string]interface{}) {
		rawHeaders, _ := json.Marshal(v)
		checker.attrs.PutStr(`check.details.`+k, string(rawHeaders))
	}

	// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
	return testStatus
}
