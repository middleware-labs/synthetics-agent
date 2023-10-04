package worker

import (
	"encoding/json"
	"fmt"
	"time"
)

func (checker *httpChecker) checkHTTPMultiStepsRequest(c SyntheticsModelCustom) {
	start := time.Now()
	var err error
	err = errTestStatusOK{
		msg: string(reqStatusOK),
	}
	status := reqStatusOK
	// _Status := "OK"
	// _Message := ""
	// assertions := make([]map[string]interface{}, 0)

	// attrs := pcommon.NewMap()
	isCheckTestReq := c.CheckTestRequest.URL != ""
	scriptSnippet := CreateScriptSnippet(c)

	//fmt.Println("scriptSnippet-->", scriptSnippet)

	respValue, exeErr := ExecK6Script(scriptSnippet)
	checker.timers["duration"] = timeInMs(time.Since(start))

	response := make(map[string]interface{}, 0)
	_ = json.Unmarshal([]byte(respValue), &response)

	if isCheckTestReq {
		resSteps := response["steps"]
		_testBody := map[string]interface{}{
			"multiStepPreview": true,
			"body":             resSteps,
		}
		WebhookSendCheckRequest(c, _testBody)
		return
	}

	if exeErr != nil {
		err = errTestStatusError{
			msg: fmt.Sprintf("Error while executing script %v", exeErr.Error()),
		}
		status = reqStatusError
		// _Status = "ERROR"
		// _Message = fmt.Sprintf("Error while executing script %v", exeErr.Error())
		checker.assertions = append(checker.assertions, map[string]string{
			"type":   "status_code",
			"reason": "Error while executing script",
			"actual": "N/A",
			"status": "FAIL",
		})
		checker.assertions = append(checker.assertions, map[string]string{
			"type":   "response_time",
			"reason": "Error while executing script",
			"actual": "N/A",
			"status": "FAIL",
		})
	} else {
		if assertStep, ok := response["assertions"].(map[string]interface{}); ok {
			isfail := false
			for _, assert := range assertStep {
				if asrt, ok1 := assert.(map[string]string); ok1 {
					checker.assertions = append(checker.assertions, asrt)
					if asrt["status"] == "FAIL" && !isfail {
						isfail = true
						err = errTestStatusFail{
							msg: "One or more assertions failed, " + asrt["reason"],
						}
						status = reqStatusFail
						//_Status = "FAIL"
						// _Message = "One or more assertions failed, " + asrt["reason"].(string)
					}
				}
			}
		} else {
			for _, assert := range c.Request.Assertions.HTTP.Cases {
				checker.assertions = append(checker.assertions, map[string]string{
					"type":   assert.Type,
					"reason": "should be " + assert.Config.Operator + " " + assert.Config.Value,
					"actual": "N/A",
					"status": "FAIL",
				})
			}
		}
	}

	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))
	FinishCheckRequest(c, string(status), err.Error(), checker.timers, checker.attrs)
}
