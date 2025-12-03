package worker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type k6Scripter interface {
	execute(scriptSnippet string) (string, error)
}

type defaultK6Scripter struct{}

func findValueToPattern(input string, pattern string) (string, error) {
	val := ""
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(string(input))
	if len(match) == 2 {
		val = match[1]
	}
	re = regexp.MustCompile(`\\/"`)
	val = re.ReplaceAllString(val, `"`)
	return strconv.Unquote("\"" + val + "\"")
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
	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing k6 script: %s", err.Error())
	}

	pattern1 := `###START->(.*?)<-END###`
	return findValueToPattern(string(outputBytes), pattern1)

	//pattern2 := `###OTHER_START->([^=]+)<-OTHER_START###`
	//other := findValueToPattern(string(errorOutputBytes), pattern2)
	//other2 := findValueToPattern(string(outputBytes), pattern2)
	//
	//fmt.Println("other--->", other)
	//fmt.Println("other2--->", other2)
}

func CreateScriptSnippet(req SyntheticCheck) string {

	k6Script := `

	import http from 'k6/http';
	import { check, sleep } from "k6";
	import encoding from 'k6/encoding';

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

	const steps = [] //##MULTI_STEPS 

	export default function () {
		let isfail = false
		const pattern = /{{\$(\d+)\.(.*?)}}/g
		const JSONPaths = {}
		const stepsResponse = {}
		const stepsHeader = {}
		const assertions = {}

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
			stepsHeader[stepKey] = {}
			const bodyMatches = step.request.http_payload.request_body.match(pattern)
			if (bodyMatches && Array.isArray(bodyMatches)) {
				JSONPaths[stepKey] = JSONPaths[stepKey].concat(bodyMatches)
			}
			let endpoint = step.endpoint
			let body = step.request.http_payload.request_body
			let headers = {
				'Content-Type': step.request.http_payload.type
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
			if (step.request.http_payload.authentication.type === 'basic' && step.request.http_payload.authentication.basic.username !== '' && step.request.http_payload.authentication.basic.password !== '') {
				const credentials = step.request.http_payload.authentication.basic.username + ':' + step.request.http_payload.authentication.basic.password
				const encodedCredentials = encoding.b64encode(credentials)
				headers['Authorization'] = 'Basic ' + encodedCredentials
			}

			const cookies = {};
			const cookieHeaders = step.request.http_payload.cookies;

			for (let k = 0; k < cookieHeaders.length; k++) {
				const headerVal = cookieHeaders[k].trim();
				const cookieParts = headerVal.split('\t').join('').split('\n').join('').split('\r');
				const [cName, cValue] = cookieParts[0].split('=');
				cookies[cName] = cValue;
			}

			const requestOptions = {
				headers: headers,
				cookies: cookies,
			}

			const response = http.request(
				step.request.http_method,
				endpoint,
				body,
				requestOptions
			)
			let jsonResp = null;
			try {
				jsonResp = response.json()
				if (jsonResp) {
					stepsResponse[stepKey] = jsonResp;
					stepsHeader[stepKey] = response.headers;
				}
			} catch (e) {
				stepsResponse[stepKey] = {
					"status_code": response.status,
					"response_time": String(response.timings.duration) + 'ms',
					"message": "Response body is not json object",
				}
			}
			const _assertions = {}
			for (const assert of step.request.assertions) {
				_assertions[assert.type] = {
					"type":   assert.type,
					"reason": assert.type.replace('_', ' ') + ' ' + (assert.config.operator || '').replace('_', ' ') + ' ' + assert.config.value,
					"actual": "N/A",
					"status": 'FAIL',
				}
			}
			for (const assert of step.request.assertions) {
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
					} else if (_op === "not_contains" || _op === "does_not_contain") {
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
					}
				} else if (assert.type === 'body') {
				    const responseBody = jsonResp ? JSON.stringify(jsonResp) : "";
					let sOk = false
					if (assert.config.operator === 'is') {
						sOk = check(response, {
							['body is ' + assert.config.value]: (r) => responseBody === assert.config.value,
						})
					} else if (assert.config.operator === 'is_not') {
						sOk = check(response, {
							['body is not' + assert.config.value]: (r) => responseBody !== assert.config.value,
						})
					} else if (assert.config.operator === "contains") {
						sOk = check(response, {
							['body contains' + assert.config.value]: (r) => responseBody.indexOf(assert.config.value) > -1,
						})
					} else if (assert.config.operator === "not_contains" || assert.config.operator === "does_not_contain") {
						sOk = check(response, {
							['body not contains' + assert.config.value]: (r) => responseBody.indexOf(assert.config.value) === -1,
						})
					} else if (assert.config.operator === "match_regex") {
						sOk = check(response, {
							['body match_regex' + assert.config.value]: (r) => responseBody.match(_vl),
						})
					} else if (assert.config.operator === "not_match_regex") {
						sOk = check(response, {
							['body not match_regex' + assert.config.value]: (r) => !responseBody.match(_vl),
						})
					}
					if (sOk) {
						_assertions[assert.type].status = "PASS"
						_assertions[assert.type].actual = "Matched"
					} else {
						isfail = true
						_assertions[assert.type].status = "FAIL"
						_assertions[assert.type].actual = "Not Matched"
						_assertions[assert.type].reason = "should be " + assert.config.operator + " " + assert.config.value + " didn't matched"
					}
				}
        	}

			assertions[stepKey] = _assertions
		}
		console.log('###START->', {steps: stepsResponse, assertions: assertions, headers: stepsHeader}, '<-END###')
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
					"type":           step.Request.HTTPPayload.RequestBody.Type,
					"request_body":   step.Request.HTTPPayload.RequestBody.Content,
					"authentication": step.Request.HTTPPayload.Authentication,
					"cookies":        step.Request.HTTPPayload.Cookies,
				},
				"assertions": step.Request.Assertions.HTTP.Cases,
			},
		})
	}

	if len(steps) > 0 {
		stepsJson, _ := json.Marshal(steps)
		k6Script = strings.ReplaceAll(k6Script, "[] //##MULTI_STEPS", ""+string(stepsJson))
	}

	return k6Script
}
