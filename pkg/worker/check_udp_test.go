package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestUDPProcessUDPResponse(t *testing.T) {
	type assertions struct {
		actual string
		reason string
		status string
	}
	tests := []struct {
		name            string
		c               SyntheticCheck
		inputTestStatus testStatus
		wantTestStatus  testStatus
		received        []byte

		expectedAssertions assertions
		expectedStatus     string
		expectedMsg        string
	}{
		{
			name: "response_time assertion passes",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							UDP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "response_time",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "less_than",
											Value:    "100",
										},
									},
								},
							},
						},
					},
				},
			},
			inputTestStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantTestStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			received: []byte{},
			expectedAssertions: assertions{
				actual: "0",
				reason: "should be less than 100",
				status: testStatusOK,
			},
			expectedStatus: udpStatusSuccessful,
			expectedMsg:    "",
		},
		{
			name: "response_time assertion fails",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							UDP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "response_time",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "greater_than",
											Value:    "100",
										},
									},
								},
							},
						},
					},
				},
			},
			inputTestStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantTestStatus: testStatus{
				status: testStatusFail,
				msg:    "assert failed, response_time didn't matched",
			},
			received: []byte{},
			expectedAssertions: assertions{
				actual: "100",
				reason: "should be greater than 100",
				status: testStatusFail,
			},
			expectedStatus: udpStatusFailed,
			expectedMsg:    "assert failed, response_time didn't matched",
		},
		{
			name: "receive_message assertion passes",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							UDP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "receive_message",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equal",
											Value:    "hello",
										},
									},
								},
							},
						},
					},
				},
			},

			inputTestStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantTestStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			received: []byte("hello"),
			expectedAssertions: assertions{
				actual: "Matched",
				reason: "should be equal hello",
				status: testStatusOK,
			},
			expectedStatus: udpStatusSuccessful,
			expectedMsg:    "",
		},
		{
			name: "receive_message assertion fails",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							UDP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "receive_message",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equal",
											Value:    "hello",
										},
									},
								},
							},
						},
					},
				},
			},

			inputTestStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},

			wantTestStatus: testStatus{
				status: testStatusFail,
				msg:    "assert failed, response message didn't matched",
			},
			received: []byte("Not Matched"),
			expectedAssertions: assertions{
				actual: "Not Matched",
				reason: "should be equal hello",
				status: testStatusFail,
			},
			expectedStatus: udpStatusFailed,
			expectedMsg:    "assert failed, response message didn't matched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := newUDPChecker(tt.c)
			if err != nil {
				t.Fatalf("Expected no error, but got: %v", err)
			}
			udpChecker, _ := checker.(*udpChecker)

			udpChecker.processUDPResponse(&tt.inputTestStatus, tt.received)

			// check that the status is OK
			if tt.wantTestStatus.status != tt.inputTestStatus.status &&
				tt.wantTestStatus.msg != tt.inputTestStatus.msg {
				t.Fatalf("%s: Expected status to be %v, but got %v", tt.name,
					tt.wantTestStatus, tt.inputTestStatus.status)
			}

			// no need to test further if the status is not OK
			if tt.inputTestStatus.status != testStatusOK {
				return
			}

			if udpChecker.c.Request.Assertions.UDP.Cases == nil {
				t.Fatalf("%s: assertions modified for test requests", tt.name)
			}

			if udpChecker.attrs.Len() == 0 {
				t.Fatalf("%s: attributes not set, length 0", tt.name)
			}

			var assertions []map[string]string
			assertionVal, ok := udpChecker.attrs.Get("assertions")
			if !ok {
				t.Fatalf("%s: assertions attribute not found", tt.name)
			}

			err = json.Unmarshal([]byte(assertionVal.AsString()), &assertions)
			if err != nil {
				t.Fatalf("%s: assertions attribute not a valid JSON string", tt.name)
			}

			if len(assertions) != len(udpChecker.c.Request.Assertions.UDP.Cases) {
				t.Fatalf("%s: assertions attribute does not have same number of cases as the request", tt.name)
			}

			for i, assert := range udpChecker.c.Request.Assertions.UDP.Cases {
				if assertions[i]["type"] != strings.ReplaceAll(assert.Type, "_", " ") {
					t.Fatalf("%s: assertions attribute not set to a JSON string with the correct type", tt.name)
				}

				if tt.expectedAssertions.actual != "" && assertions[i]["actual"] != tt.expectedAssertions.actual {
					t.Fatalf("%s: assertions 'acutal' with value '%s' does not match expected value '%s'", tt.name,
						assertions[i]["actual"], tt.expectedAssertions.actual)
				}

				if tt.expectedAssertions.reason != "" && assertions[i]["reason"] != tt.expectedAssertions.reason {
					t.Fatalf("%s: assertions 'reason' with value '%s' does not match expected value '%s'", tt.name,
						assertions[i]["reason"], tt.expectedAssertions.reason)
				}

				if tt.expectedAssertions.status != "" && assertions[i]["status"] != tt.expectedAssertions.status {
					t.Fatalf("%s: assertions 'status' with value '%s' does not match expected value '%s'", tt.name,
						assertions[i]["status"], tt.expectedAssertions.status)
				}
			}

			testBody := udpChecker.getTestResponseBody()

			tookMs := testBody["tookMs"].(string)
			actualTookMs := fmt.Sprintf("%.2f ms", udpChecker.timers["duration"])
			if udpChecker.c.CheckTestRequest.URL != "" &&
				tookMs != actualTookMs {
				t.Fatalf("%s: expected tookMs %v, but got %v", tt.name,
					tookMs, actualTookMs)
			}
			udpStatus := testBody["udp_status"].(string)
			if udpChecker.c.CheckTestRequest.URL != "" &&
				udpStatus != tt.expectedStatus {
				t.Fatalf("%s: expected udp_status %v, but got %v", tt.name,
					tt.expectedStatus, udpStatus)
			}
		})
	}
}

type mockUDPNetHelper struct {
	resolveUDPAddrErr  error
	dialUDPErr         error
	writeUDPMessageErr error
	readUDPMesssageErr error
	setReadDeadlineErr error
}

func (m *mockUDPNetHelper) resolveUDPAddr(address string) (*net.UDPAddr, error) {
	return &net.UDPAddr{}, m.resolveUDPAddrErr
}

func (m *mockUDPNetHelper) dialUDP(raddr *net.UDPAddr) (*net.UDPConn, error) {
	return &net.UDPConn{}, m.dialUDPErr
}

func (m *mockUDPNetHelper) writeUDPMessage(conn *net.UDPConn, b []byte) error {
	return m.writeUDPMessageErr
}

func (m *mockUDPNetHelper) readUDPMessage(conn *net.UDPConn, b []byte) error {
	return m.readUDPMesssageErr
}

func (m *mockUDPNetHelper) setUDPReadDeadline(conn *net.UDPConn, t time.Time) error {
	return m.setReadDeadlineErr
}

func TestUDPCheck(t *testing.T) {
	tests := []struct {
		name      string
		c         SyntheticCheck
		netHelper udpNetHelper
		expected  testStatus
	}{
		{
			name: "resolveUDPAddr error",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "1234",
						UDPPayload: UDPPayloadOptions{
							Message: "hello",
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},
			netHelper: &mockUDPNetHelper{
				resolveUDPAddrErr: errors.New("error resolving UDP address"),
			},
			expected: testStatus{
				status: testStatusError,
				msg:    "error resolving dns: error resolving UDP address",
			},
		},

		{
			name: "dialUDP error",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "1234",
						UDPPayload: UDPPayloadOptions{
							Message: "hello",
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},
			netHelper: &mockUDPNetHelper{
				dialUDPErr: errors.New("timeout"),
			},
			expected: testStatus{
				status: testStatusError,
				msg:    "error connecting udp: timeout",
			},
		},

		{
			name: "write udp message error",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "1234",
						UDPPayload: UDPPayloadOptions{
							Message: "hello",
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},
			netHelper: &mockUDPNetHelper{
				writeUDPMessageErr: errors.New("write error"),
			},
			expected: testStatus{
				status: testStatusError,
				msg:    "udp write message failed: write error",
			},
		},

		{
			name: "set UDP read deadline error",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "1234",
						UDPPayload: UDPPayloadOptions{
							Message: "hello",
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},
			netHelper: &mockUDPNetHelper{
				setReadDeadlineErr: errors.New("read deadline error"),
			},
			expected: testStatus{
				status: testStatusError,
				msg:    "conn SetUDPReadDeadline failed: read deadline error",
			},
		},

		{
			name: "read UDP message error",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "1234",
						UDPPayload: UDPPayloadOptions{
							Message: "hello",
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},
			netHelper: &mockUDPNetHelper{
				readUDPMesssageErr: errors.New("read error"),
			},
			expected: testStatus{
				status: testStatusError,
				msg:    "error reading message: read error",
			},
		},

		{
			name: "check success",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "1234",
						UDPPayload: UDPPayloadOptions{
							Message: "hello",
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},
			netHelper: &mockUDPNetHelper{},
			expected: testStatus{
				status: testStatusOK,
				msg:    "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := newUDPChecker(tt.c)
			if err != nil {
				t.Fatalf("Expected no error, but got: %v", err)
			}
			udpChecker, _ := checker.(*udpChecker)

			if tt.netHelper != nil {
				udpChecker.netHelper = tt.netHelper
			}

			gotStatus := udpChecker.check()
			if gotStatus.status != tt.expected.status {
				t.Fatalf("expected status %v, but got %v",
					tt.expected.status, gotStatus.status)
			}
			if gotStatus.msg != tt.expected.msg {
				t.Fatalf("expected msg %v, but got %v",
					tt.expected.msg, gotStatus.msg)
			}
		})
	}
}
