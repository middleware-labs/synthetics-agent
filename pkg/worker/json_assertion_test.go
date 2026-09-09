package worker

import (
	"strings"
	"testing"
)

func testJSONBodyCase(selector, operator, value string) CaseOptions {
	assertion := CaseOptions{Type: assertTypeHTTPJSONBody}
	assertion.Config.Target = selector
	assertion.Config.Operator = operator
	assertion.Config.Value = value
	return assertion
}

func TestJSONBodyAssertions(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		selector   string
		operator   string
		value      string
		wantStatus string
		wantActual string
		wantReason string
	}{
		{
			name:       "nested field equals string",
			body:       `{"data":{"status":"healthy"}}`,
			selector:   "$.data.status",
			operator:   "equals",
			value:      "healthy",
			wantStatus: testStatusPass,
			wantActual: `"healthy"`,
		},
		{
			name:       "wildcard contains a selected value",
			body:       `{"items":[{"id":"api"},{"id":"web"}]}`,
			selector:   "$.items[*].id",
			operator:   "contains",
			value:      "api",
			wantStatus: testStatusPass,
			wantActual: `["api","web"]`,
		},
		{
			name:       "filtered selector compares a number",
			body:       `{"items":[{"active":false,"count":0},{"active":true,"count":7}]}`,
			selector:   `$.items[?(@.active == true)].count`,
			operator:   "greater_than",
			value:      "5",
			wantStatus: testStatusPass,
			wantActual: "7",
		},
		{
			name:       "boolean target is typed",
			body:       `{"ready":true}`,
			selector:   "$.ready",
			operator:   "equals",
			value:      "true",
			wantStatus: testStatusPass,
			wantActual: "true",
		},
		{
			name:       "object containment uses a recursive subset",
			body:       `{"service":{"status":"ok","meta":{"region":"us","version":2}}}`,
			selector:   "$.service",
			operator:   "contains",
			value:      `{"meta":{"region":"us"}}`,
			wantStatus: testStatusPass,
		},
		{
			name:       "missing selector is null",
			body:       `{"status":"ok"}`,
			selector:   "$.error",
			operator:   "is_null",
			wantStatus: testStatusPass,
			wantActual: "No match",
		},
		{
			name:       "not contains checks every wildcard match",
			body:       `{"messages":["healthy","ready"]}`,
			selector:   "$.messages[*]",
			operator:   "not_contains",
			value:      "error",
			wantStatus: testStatusPass,
		},
		{
			name:       "failed comparison",
			body:       `{"count":2}`,
			selector:   "$.count",
			operator:   "greater_than",
			value:      "5",
			wantStatus: testStatusFail,
			wantReason: "JSON body assertion failed",
		},
		{
			name:       "invalid JSON",
			body:       `{"status":`,
			selector:   "$.status",
			operator:   "equals",
			value:      "ok",
			wantStatus: testStatusFail,
			wantReason: "Invalid JSON",
		},
		{
			name:       "invalid JSONPath",
			body:       `{"status":"ok"}`,
			selector:   "$.status[",
			operator:   "equals",
			value:      "ok",
			wantStatus: testStatusFail,
			wantReason: "Invalid JSONPath",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, status, _ := getHTTPTestCaseJSONBodyAssertions(
				test.body,
				testJSONBodyCase(test.selector, test.operator, test.value),
				nil,
			)

			if result["status"] != test.wantStatus || status.status != map[string]string{
				testStatusPass: testStatusOK,
				testStatusFail: testStatusFail,
			}[test.wantStatus] {
				t.Fatalf("unexpected statuses: result=%q check=%q", result["status"], status.status)
			}
			if test.wantActual != "" && result["actual"] != test.wantActual {
				t.Fatalf("actual = %q, want %q", result["actual"], test.wantActual)
			}
			if test.wantReason != "" && !strings.Contains(result["reason"], test.wantReason) {
				t.Fatalf("reason = %q, want containing %q", result["reason"], test.wantReason)
			}
		})
	}
}
