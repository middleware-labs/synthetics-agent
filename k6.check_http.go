package synthetics_agent

import (
	"encoding/json"
	"fmt"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"time"
)

func CheckHTTPMultiStepsRequest(c SyntheticsModelCustom) {
	_start := time.Now()
	timers := map[string]float64{
		"duration": 0.0,
	}
	_Status := "OK"
	_Message := ""
	assertions := make([]map[string]interface{}, 0)

	attrs := pcommon.NewMap()
	isCheckTestReq := c.CheckTestRequest.URL != ""
	scriptSnippet := CreateScriptSnippet(c)

	//fmt.Println("scriptSnippet-->", scriptSnippet)

	respValue, exeErr := ExecK6Script(scriptSnippet)
	timers["duration"] = timeInMs(time.Since(_start))

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
		_Status = "ERROR"
		_Message = fmt.Sprintf("Error while executing script %v", exeErr.Error())
		assertions = append(assertions, map[string]interface{}{
			"type":   "status_code",
			"reason": "Error while executing script",
			"actual": "N/A",
			"status": "FAIL",
		})
		assertions = append(assertions, map[string]interface{}{
			"type":   "response_time",
			"reason": "Error while executing script",
			"actual": "N/A",
			"status": "FAIL",
		})
	} else {
		if assertStep, ok := response["assertions"].(map[string]interface{}); ok {
			isfail := false
			for _, assert := range assertStep {
				if asrt, ok1 := assert.(map[string]interface{}); ok1 {
					assertions = append(assertions, asrt)
					if asrt["status"] == "FAIL" && !isfail {
						isfail = true
						_Status = "FAIL"
						_Message = "One or more assertions failed, " + asrt["reason"].(string)
					}
				}
			}
		} else {
			for _, assert := range c.Request.Assertions.HTTP.Cases {
				assertions = append(assertions, map[string]interface{}{
					"type":   assert.Type,
					"reason": "should be " + assert.Config.Operator + " " + assert.Config.Value,
					"actual": "N/A",
					"status": "FAIL",
				})
			}
		}
	}

	resultStr, _ := json.Marshal(assertions)
	attrs.PutStr("assertions", string(resultStr))
	FinishCheckRequest(c, _Status, _Message, timers, attrs)
}
