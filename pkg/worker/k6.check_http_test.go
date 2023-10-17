package worker

import (
	"fmt"
	"net/http"
	"testing"
)

type mockk6Scripter struct {
	respValue string
	exeErr    error
}

func (m *mockk6Scripter) execute(scriptSnippet string) (string, error) {
	return m.respValue, m.exeErr
}

func TestHTTPMultiStepRequest(t *testing.T) {
	tests := []struct {
		name           string
		c              SyntheticsModelCustom
		k6Scripter     k6Scripter
		wantStatus     testStatus
		wantAssertions []map[string]string
		wantTestBody   map[string]interface{}
	}{
		{
			name: "Test HTTP GET request",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						HTTPMultiTest: true,
						HTTPMultiSteps: []HTTPMultiStepsOptions{
							{
								StepName: "step1",
								Endpoint: "http://example.com",
								Request: HTTPMultiStepsRequest{
									HTTPMethod:  "GET",
									HTTPPayload: HTTPPayloadOptions{},
								},
							},
						},
					},
					Expect: SyntheticsExpectMeta{},
				},
			},

			k6Scripter: &mockk6Scripter{
				respValue: `{
					"steps": "step1",
					"multiStepPreview": true
				}`,

				exeErr: nil,
			},

			wantStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantAssertions: []map[string]string{},
			wantTestBody: map[string]interface{}{
				"headers":    make(map[string]string),
				"assertions": make([]map[string]string, 0),
				"statusCode": http.StatusFound,
				"method":     "",
				"url":        "",
				"authority":  "",
				"path":       "?",
				"tookMs":     "0 ms",
				"body":       "",
			},
		},
		{
			name: "Test HTTP MultiStep GET request error",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						HTTPMultiTest: true,
						HTTPMultiSteps: []HTTPMultiStepsOptions{
							{
								StepName: "step1",
								Endpoint: "http://example.com",
								Request: HTTPMultiStepsRequest{
									HTTPMethod:  "GET",
									HTTPPayload: HTTPPayloadOptions{},
								},
							},
						},
					},
					Expect: SyntheticsExpectMeta{},
				},
			},

			k6Scripter: &mockk6Scripter{
				respValue: `{
					"steps": "step1",
					"multiStepPreview": true
				}`,
				exeErr: fmt.Errorf("timeout"),
			},

			wantStatus: testStatus{
				status: testStatusFail,
				msg:    "error while executing script: timeout",
			},
			wantAssertions: []map[string]string{
				{
					"type":   "status_code",
					"reason": "Error while executing script",
					"actual": "N/A",
					"status": testStatusFail,
				},
				{
					"type":   "response_time",
					"reason": "Error while executing script",
					"actual": "N/A",
					"status": testStatusFail,
				},
			},
		},
		{
			name: "Test HTTP MultiStep GET request with test",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					CheckTestRequest: CheckTestRequest{
						URL: "http://example.com",
					},
					Request: SyntheticsRequestOptions{
						HTTPMultiTest: true,
						HTTPMultiSteps: []HTTPMultiStepsOptions{
							{
								StepName: "step1",
								Endpoint: "http://example.com",
								Request: HTTPMultiStepsRequest{
									HTTPMethod:  "GET",
									HTTPPayload: HTTPPayloadOptions{},
								},
							},
						},
					},
					Expect: SyntheticsExpectMeta{},
				},
			},

			k6Scripter: &mockk6Scripter{
				respValue: `{
					"steps": "step1",
					"multiStepPreview": true
				  }`,
				exeErr: fmt.Errorf("timeout"),
			},

			wantStatus: testStatus{
				status: testStatusOK,
			},
			wantAssertions: []map[string]string{},
			wantTestBody: map[string]interface{}{
				"multiStepPreview": true,
				"body":             "step1",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			protocolChecker, _ := newHTTPChecker(tt.c)
			checker := protocolChecker.(*httpChecker)
			if tt.k6Scripter != nil {
				checker.k6Scripter = tt.k6Scripter
			}

			status := checker.check()
			// check that the status is OK
			if status.status != tt.wantStatus.status &&
				status.msg != tt.wantStatus.msg {
				t.Fatalf("%s: expected status to be %v, but got %v (%s)",
					tt.name, tt.wantStatus, status.status, status.msg)
			}
			foundAssertions := 0
			for _, assertion := range checker.assertions {
				for _, wantAssertion := range tt.wantAssertions {
					if assertion["type"] == wantAssertion["type"] &&
						assertion["status"] == wantAssertion["status"] &&
						assertion["reason"] == wantAssertion["reason"] {
						foundAssertions++
					}
				}
			}

			if len(checker.assertions) != len(tt.wantAssertions) {
				t.Fatalf("%s: expected %v assertions, but got %v",
					tt.name, len(tt.wantAssertions), len(checker.assertions))
			}

			// check that all assertions are found
			if foundAssertions != len(tt.wantAssertions) {
				t.Fatalf("%s: expected %v assertions, but got %v",
					tt.name, len(tt.wantAssertions), foundAssertions)
			}

			// check that the test body is correct
			if len(tt.wantTestBody) > 0 {
				if len(checker.testBody) != len(tt.wantTestBody) {
					t.Fatalf("%s: expected %v test body, but got %v",
						tt.name, len(tt.wantTestBody), checker.testBody)
				}
			}

			// no need to test further if the status is not OK
			if status.status != testStatusOK {
				return
			}

		})
	}
}
