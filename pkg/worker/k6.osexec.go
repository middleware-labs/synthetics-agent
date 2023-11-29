package worker

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type k6Scripter interface {
	execute(scriptSnippet string) (string, error)
}

type defaultK6Scripter struct{}

func readStdoutPipeLines(pipe io.Reader) ([]byte, error) {
	var outputBytes []byte
	buf := make([]byte, 1024)
	for {
		n, err := pipe.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}
		outputBytes = append(outputBytes, buf[:n]...)
	}
	return outputBytes, nil
}

func findValueToPattern(input string, pattern string) string {
	val := ""
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(string(input))
	if len(match) == 2 {
		val = match[1]
	}
	re = regexp.MustCompile(`\\/"`)
	val = re.ReplaceAllString(val, `"`)
	re1 := regexp.MustCompile(`\\"`)
	val = re1.ReplaceAllString(val, `"`)
	return val
}

func (k6Scripter *defaultK6Scripter) execute(scriptSnippet string) (string, error) {
	temp, tpErr := os.CreateTemp("", "script.js")
	if tpErr != nil {
		return "", fmt.Errorf("error creating temp file: %s", tpErr.Error())
	}

	defer os.Remove(temp.Name())

	if _, wrErr := temp.Write([]byte(scriptSnippet)); wrErr != nil {
		return "", fmt.Errorf("error writing to temp file: %s", wrErr.Error())
	}

	if err := temp.Close(); err != nil {
		return "", fmt.Errorf("error closing temp file: %s", err.Error())
	}

	cmd := exec.Command("k6", "run", temp.Name())

	stdoutPipe, outErr := cmd.StdoutPipe()
	if outErr != nil {
		return "", fmt.Errorf("error creating stdout pipe: %s", outErr.Error())
	}
	stderrPipe, stdErr := cmd.StderrPipe()
	if stdErr != nil {
		return "", fmt.Errorf("error creating stderr pipe: %s", stdErr.Error())
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("error starting k6 command: %s", err.Error())
	}

	outputBytes, err := readStdoutPipeLines(stdoutPipe)
	if err != nil {
		return "", fmt.Errorf("error reading stdout: %s", err.Error())
	}
	errorOutputBytes, err := readStdoutPipeLines(stderrPipe)
	if err != nil {
		return "", fmt.Errorf("error reading stderr: %s", err.Error())
	}

	// Wait for the k6 command to finish.
	if wErr := cmd.Wait(); wErr != nil {
		return "", fmt.Errorf("k6 command finished with error: %s", err.Error())
	}

	pattern1 := `###START->([^=]+)<-END###`
	respValue := findValueToPattern(string(errorOutputBytes), pattern1)
	if respValue == "" {
		respValue = findValueToPattern(string(outputBytes), pattern1)
	}

	//pattern2 := `###OTHER_START->([^=]+)<-OTHER_START###`
	//other := findValueToPattern(string(errorOutputBytes), pattern2)
	//other2 := findValueToPattern(string(outputBytes), pattern2)
	//
	//fmt.Println("other--->", other)
	//fmt.Println("other2--->", other2)

	return respValue, nil
}

func CreateScriptSnippet(req SyntheticCheck) string {

	k6Script := `

	import http from 'k6/http';
	import { check, sleep } from "k6";
	
	function accessJsonValue(jsonData, path) {
		try {
			const keys = path.split('.');
			let currentObject = jsonData;
			for (const key of keys) {
				if (currentObject.hasOwnProperty(key)) {
					currentObject = currentObject[key];
				} else {
					return undefined;
				}
			}
			return currentObject;
		} catch (error) {
			return undefined;
		}
	}

	const asserts = [] //##STEPS_ASSERTIONS 
	const steps = [] //##MULTI_STEPS 

	export default function () {
		let isfail = false
		const pattern = /{{\$(\d+)\.(.*?)}}/g
		const JSONPaths = {}
		const stepsResponse = {}
		const _assertions = {}
		for (const assert of asserts) {
			_assertions[assert.type] = {
				"type":   assert.type,
				"reason": assert.type.replace('_', ' ') + (assert.config.operator || '').replace('_', ' ') + ' ' + assert.config.value,
				"actual": "N/A",
				"status": 'FAIL',
			}
		}
	
		for (let i = 0; i < steps.length; i++) {
			const stepKey = 'step_' + i
			const step = steps[i]
			step.endpoint = step.endpoint
				.replace(/\u0026/g, "&")
				.replace(/%7B%7B%24/g, "{{$")
				.replace(/%7D%7D/g, "}}")
			const endpointMatches = step.endpoint.match(pattern)
			JSONPaths[stepKey] = endpointMatches && Array.isArray(endpointMatches) ? endpointMatches : []
			stepsResponse[stepKey] = {}
			const bodyMatches = step.request.http_payload.request_body.match(pattern)
			if (bodyMatches && Array.isArray(bodyMatches)) {
				JSONPaths[stepKey] = JSONPaths[stepKey].concat(bodyMatches)
			}
			let endpoint = step.endpoint
			let body = step.request.http_payload.request_body
			let headers = {
				'Content-Type': 'application/json'
			}
			if (step.request.http_headers && Array.isArray(step.request.http_headers)) {
				for (const header of step.request.http_headers) {
					if (header.name !== '' && header.value !== '') {
						headers[header.name] = header.value
					}
				}
				const headersMatches = JSON.stringify(headers).match(pattern)
				if (headersMatches && Array.isArray(headersMatches)) {
					JSONPaths[stepKey] = JSONPaths[stepKey].concat(headersMatches)
				}
			}
	
			if (i > 0) {
				const previousStepKey = 'step_'+(i - 1)
				if (typeof stepsResponse[previousStepKey] !== 'undefined' && typeof JSONPaths[stepKey] !== 'undefined') {
					let previousStep = stepsResponse[previousStepKey]
					for (let j = 0; j < JSONPaths[stepKey].length; j++) {
						let originalJSONPath = JSONPaths[stepKey][j]
						const splitPath = originalJSONPath.split('.')
						let _before = "^~*^*~^"
						if (splitPath.length > 0) {
							_before = splitPath[0]
							let _stepIndex = parseInt(_before.replace('{{$', ""))
							if (!isNaN(_stepIndex) && typeof stepsResponse['step_' + _stepIndex] !== 'undefined') {
								previousStep = stepsResponse['step_' + _stepIndex]
							}
						}
						const jsonPathKey = originalJSONPath.replace(_before + '.', '').replace('}}', '')
						let jsonPathValue = accessJsonValue(previousStep, jsonPathKey)
						if (typeof jsonPathValue !== 'undefined') {
							if (typeof jsonPathValue === 'object') {
								originalJSONPath = '"${originalJSONPath}"'
								jsonPathValue = JSON.stringify(jsonPathValue)
							}
						} else {
							jsonPathValue = ''
						}
	
						endpoint = endpoint.replace(originalJSONPath, jsonPathValue)
						body = body.replace(originalJSONPath, jsonPathValue)
						headers = Object.assign({}, JSON.parse(JSON.stringify(headers).replace(originalJSONPath, jsonPathValue)))
					}
				}
			}
	
			const response = http.request(
				step.request.http_method,
				endpoint,
				body,
				{ headers: headers }
			)

			try {
				const jsonResp = response.json()
				if (jsonResp) {
					stepsResponse[stepKey] = jsonResp
				}
			} catch (e) {
				stepsResponse[stepKey] = {
					"error": "An error occurred while parsing the response body",
					"message": "The response should be a valid JSON object",
				}
			}
			
			for (const assert of asserts) {
				if (assert.type === 'status_code') {
					const _op = assert.config.operator
					const _vl = parseInt(assert.config.value)
					let sOk = false
					_assertions[assert.type].actual = response.status
					if (_op === 'is') {
						sOk = check(response, {
							['status is ' + assert.config.value]: (r) => r.status === _vl,
						})
					} else if (_op === "is_not") {
						sOk = check(response, {
							['status is not' + assert.config.value]: (r) => r.status !== _vl,
						})
					} else if (_op === "contains") {
						sOk = check(response, {
							['status contains' + assert.config.value]: (r) => (r.status + '').indexOf(_vl) > -1,
						})
					} else if (_op === "not_contains") {
						sOk = check(response, {
							['status not contains' + assert.config.value]: (r) => (r.status + '').indexOf(_vl) === -1,
						})
					} else if (_op === "match_regex") {
						sOk = check(response, {
							['status match_regex' + assert.config.value]: (r) => (r.status + '').match(_vl),
						})
					} else if (_op === "not_match_regex") {
						sOk = check(response, {
							['status not match_regex' + assert.config.value]: (r) => !(r.status + '').match(_vl),
						})
					}
					if (sOk) {
						_assertions[assert.type].status = "PASS"
					} else {
						isfail = true
						_assertions[assert.type].status = "FAIL"
						_assertions[assert.type].reason = "assert failed, " + assert.type.replace('_', '') + " didn't matched"
						break
					}
				} else if (assert.type === 'response_time') {
					_assertions[assert.type].actual = response.timings.duration
					let sOk = false
					if (assert.config.operator === 'less_than') {
						sOk = check(response, {
							['response time is less than ' + assert.config.value]: (r) => r.timings.duration < parseInt(assert.config.value),
						})
					} else if (assert.config.operator === 'greater_than') {
						sOk = check(response, {
							['response time is greater than ' + assert.config.value]: (r) => r.timings.duration > parseInt(assert.config.value),
						})
					}
					if (sOk) {
						_assertions[assert.type].status = "PASS"
					} else {
						isfail = true
						_assertions[assert.type].status = "FAIL"
						_assertions[assert.type].reason = "assert failed, " + assert.type.replace('_', '') + " didn't matched"
						break
					}
				}
        	}

			if (isfail) {
				break
			}
		}
		console.log('###START->', {steps: stepsResponse, assertions: _assertions}, '<-END###')
	}

	`

	steps := make([]map[string]interface{}, 0)
	for _, step := range req.Request.HTTPMultiSteps {
		steps = append(steps, map[string]interface{}{
			"endpoint": step.Endpoint,
			"request": map[string]interface{}{
				"http_method":  step.Request.HTTPMethod,
				"http_headers": step.Request.HTTPHeaders,
				"http_payload": map[string]interface{}{
					"type":         step.Request.HTTPPayload.RequestBody.Type,
					"request_body": step.Request.HTTPPayload.RequestBody.Content,
				},
			},
		})
	}

	if len(steps) > 0 {
		stepsJson, _ := json.Marshal(steps)
		k6Script = strings.ReplaceAll(k6Script, "[] //##MULTI_STEPS", ""+string(stepsJson))

		assert, _ := json.Marshal(req.Request.Assertions.HTTP.Cases)
		k6Script = strings.ReplaceAll(k6Script, "[] //##STEPS_ASSERTIONS", ""+string(assert))
	}

	return k6Script
}
