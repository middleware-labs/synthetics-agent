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
	testStatus := testStatus{
		status: testStatusOK,
	}

	isCheckTestReq := c.IsPreviewRequest
	slog.Info("isCheckTestReq = ", slog.Bool("value", isCheckTestReq))
	slog.Info("checker.testBody", slog.Any("checker.testBody", checker.testBody))
	scriptSnippet := CreateScriptSnippet(c)
	respValue, exeErr := checker.k6Scripter.execute(scriptSnippet)
	slog.Info("response from script excecution", slog.Any("respValue", respValue))
	checker.timers["duration"] = timeInMs(time.Since(start))

	response := make(map[string]interface{}, 0)
	err := json.Unmarshal([]byte(respValue), &response)
	if err != nil {
		slog.Error("error while parsing response from k6Scripter.execute()", slog.String("err", err.Error()))
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error while parsing response: %v", err)
		return testStatus
	}

	if isCheckTestReq {
		slog.Info("its true")
		resSteps, resHeaders := response["steps"], response["headers"]
		slog.Info("response object", slog.Any("resSteps", resSteps), slog.Any("resHeaders", resHeaders))
		checker.testBody = map[string]interface{}{
			"multiStepPreview": true,
			"body":             resSteps,
			"headers":          resHeaders,
		}
		slog.Info("checker.testBody (updated)", slog.Any("checker.testBody", checker.testBody))

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
	// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
	return testStatus
}
