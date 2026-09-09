package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/ohler55/ojg/jp"
)

const maxJSONAssertionActualLength = 1024

func getHTTPTestCaseJSONBodyAssertions(body string, assert CaseOptions, testStatusMsg []string) (map[string]string, testStatus, []string) {
	result := map[string]string{
		"reason": jsonAssertionReason(assert),
		"actual": "No match",
		"status": testStatusPass,
	}
	status := testStatus{status: testStatusOK}

	document, err := decodeJSONValue(body)
	if err != nil {
		return failJSONAssertion(result, status, testStatusMsg, "Invalid JSON", err)
	}

	path, err := jp.ParseString(strings.TrimSpace(assert.Config.Target))
	if err != nil {
		return failJSONAssertion(result, status, testStatusMsg, "Invalid JSONPath", err)
	}

	matches := path.Get(document)
	result["actual"] = formatJSONAssertionActual(matches)

	expected, err := expectedJSONValue(assert.Config.Value)
	if err != nil {
		return failJSONAssertion(result, status, testStatusMsg, "Invalid expected value", err)
	}

	passed, err := compareJSONPathMatches(matches, strings.TrimSpace(assert.Config.Operator), expected)
	if err != nil {
		return failJSONAssertion(result, status, testStatusMsg, "Invalid comparison", err)
	}
	if !passed {
		return failJSONAssertion(result, status, testStatusMsg, "JSON body assertion failed", nil)
	}

	return result, status, testStatusMsg
}

func failJSONAssertion(result map[string]string, status testStatus, messages []string, message string, cause error) (map[string]string, testStatus, []string) {
	status.status = testStatusFail
	result["status"] = testStatusFail
	if cause != nil {
		message += ": " + cause.Error()
	}
	result["reason"] = message + "; " + result["reason"]
	return result, status, append(messages, message)
}

func jsonAssertionReason(assert CaseOptions) string {
	reason := fmt.Sprintf("%s %s", assert.Config.Target, strings.ReplaceAll(assert.Config.Operator, "_", " "))
	if assert.Config.Operator != "is_null" && assert.Config.Operator != "is_not_null" {
		reason += " " + assert.Config.Value
	}
	return reason
}

func decodeJSONValue(value string) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.UseNumber()

	var decoded interface{}
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple JSON values")
	}
	return decoded, nil
}

func expectedJSONValue(value string) (interface{}, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}

	decoded, err := decodeJSONValue(trimmed)
	if err == nil {
		return decoded, nil
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return nil, err
	}
	return trimmed, nil
}

func compareJSONPathMatches(matches []interface{}, operator string, expected interface{}) (bool, error) {
	switch operator {
	case "is_null":
		if len(matches) == 0 {
			return true, nil
		}
		for _, actual := range matches {
			if actual != nil {
				return false, nil
			}
		}
		return true, nil
	case "is_not_null":
		for _, actual := range matches {
			if actual != nil {
				return true, nil
			}
		}
		return false, nil
	}

	if len(matches) == 0 {
		return false, nil
	}

	switch operator {
	case "equals", "contains", "greater_than", "less_than":
		for _, actual := range matches {
			matched, err := compareJSONValue(actual, operator, expected)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	case "not_equals", "not_contains":
		positiveOperator := strings.TrimPrefix(operator, "not_")
		for _, actual := range matches {
			matched, err := compareJSONValue(actual, positiveOperator, expected)
			if err != nil {
				return false, err
			}
			if matched {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported operator %q", operator)
	}
}

func compareJSONValue(actual interface{}, operator string, expected interface{}) (bool, error) {
	switch operator {
	case "equals":
		return jsonValuesEqual(actual, expected), nil
	case "contains":
		return jsonValueContains(actual, expected), nil
	case "greater_than", "less_than":
		actualNumber, actualOK := jsonNumber(actual)
		expectedNumber, expectedOK := jsonNumber(expected)
		if !actualOK || !expectedOK {
			return false, fmt.Errorf("%s requires numeric values", operator)
		}
		comparison := actualNumber.Cmp(expectedNumber)
		if operator == "greater_than" {
			return comparison > 0, nil
		}
		return comparison < 0, nil
	default:
		return false, fmt.Errorf("unsupported operator %q", operator)
	}
}

func jsonValuesEqual(actual interface{}, expected interface{}) bool {
	actualNumber, actualIsNumber := jsonNumber(actual)
	expectedNumber, expectedIsNumber := jsonNumber(expected)
	if actualIsNumber || expectedIsNumber {
		return actualIsNumber && expectedIsNumber && actualNumber.Cmp(expectedNumber) == 0
	}

	actualArray, actualIsArray := actual.([]interface{})
	expectedArray, expectedIsArray := expected.([]interface{})
	if actualIsArray || expectedIsArray {
		if !actualIsArray || !expectedIsArray || len(actualArray) != len(expectedArray) {
			return false
		}
		for index := range actualArray {
			if !jsonValuesEqual(actualArray[index], expectedArray[index]) {
				return false
			}
		}
		return true
	}

	actualObject, actualIsObject := actual.(map[string]interface{})
	expectedObject, expectedIsObject := expected.(map[string]interface{})
	if actualIsObject || expectedIsObject {
		if !actualIsObject || !expectedIsObject || len(actualObject) != len(expectedObject) {
			return false
		}
		for key, expectedValue := range expectedObject {
			actualValue, ok := actualObject[key]
			if !ok || !jsonValuesEqual(actualValue, expectedValue) {
				return false
			}
		}
		return true
	}

	return actual == expected
}

func jsonValueContains(actual interface{}, expected interface{}) bool {
	switch value := actual.(type) {
	case string:
		expectedString, ok := expected.(string)
		return ok && strings.Contains(value, expectedString)
	case []interface{}:
		if expectedValues, ok := expected.([]interface{}); ok {
			for _, expectedValue := range expectedValues {
				found := false
				for _, actualValue := range value {
					if jsonValuesEqual(actualValue, expectedValue) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
			return true
		}
		for _, actualValue := range value {
			if jsonValuesEqual(actualValue, expected) {
				return true
			}
		}
		return false
	case map[string]interface{}:
		expectedObject, ok := expected.(map[string]interface{})
		if !ok {
			return false
		}
		for key, expectedValue := range expectedObject {
			actualValue, exists := value[key]
			if !exists {
				return false
			}
			if nestedExpected, nested := expectedValue.(map[string]interface{}); nested {
				if !jsonValueContains(actualValue, nestedExpected) {
					return false
				}
				continue
			}
			if !jsonValuesEqual(actualValue, expectedValue) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func jsonNumber(value interface{}) (*big.Rat, bool) {
	var text string
	switch number := value.(type) {
	case json.Number:
		text = number.String()
	case float64:
		text = fmt.Sprintf("%.17g", number)
	case float32:
		text = fmt.Sprintf("%.9g", number)
	case int:
		text = fmt.Sprintf("%d", number)
	case int64:
		text = fmt.Sprintf("%d", number)
	default:
		return nil, false
	}

	rational, ok := new(big.Rat).SetString(text)
	return rational, ok
}

func formatJSONAssertionActual(matches []interface{}) string {
	if len(matches) == 0 {
		return "No match"
	}

	value := interface{}(matches)
	if len(matches) == 1 {
		value = matches[0]
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	actual := string(encoded)
	if len(actual) > maxJSONAssertionActualLength {
		return actual[:maxJSONAssertionActualLength] + "..."
	}
	return actual
}
