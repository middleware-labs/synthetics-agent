package worker

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestWsCheck(t *testing.T) {
	// create a new ws checker instance
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	tests := []struct {
		name           string
		c              SyntheticCheck
		wsHandler      func(w http.ResponseWriter, r *http.Request)
		expectedStatus testStatus
	}{
		{
			name: "test successful connection",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThan: 10,
					},
					Request: SyntheticsRequestOptions{
						WSPayload: WSPayloadOptions{
							Headers: []WSPayloadHeaders{
								{
									Name:  "Authorization",
									Value: "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
								},
							},
							Authentication: WSPayloadAuthentication{
								Username: "username",
								Password: "password",
							},
						},

						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test message",
							},
						},
					},
				},
			},

			wsHandler: func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					http.Error(w, fmt.Sprintf("cannot upgrade: %v", err), http.StatusInternalServerError)
				}
				// The event loop
				for {
					messageType, message, err := conn.ReadMessage()
					if err != nil {
						break
					}
					err = conn.WriteMessage(messageType, message)
					if err != nil {
						break
					}
				}

			},
			expectedStatus: testStatus{
				status: testStatusOK,
			},
		},

		{
			name: "dial error",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						WSPayload: WSPayloadOptions{
							Headers: []WSPayloadHeaders{
								{
									Name:  "Authorization",
									Value: "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
								},
							},
							Authentication: WSPayloadAuthentication{
								Username: "username",
								Password: "password",
							},
						},

						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test message",
							},
						},
					},
				},
			},

			wsHandler: nil,
			expectedStatus: testStatus{
				status: testStatusFail,
				msg:    "failed to connect websocket",
			},
		},
		{
			name: "io timeout error",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						WSPayload: WSPayloadOptions{
							Headers: []WSPayloadHeaders{
								{
									Name:  "Authorization",
									Value: "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
								},
							},
							Authentication: WSPayloadAuthentication{
								Username: "username",
								Password: "password",
							},
						},

						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test message",
							},
						},
					},
				},
			},

			wsHandler: func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					http.Error(w, fmt.Sprintf("cannot upgrade: %v", err), http.StatusInternalServerError)
				}
				// The event loop
				for {
					messageType, message, err := conn.ReadMessage()
					if err != nil {
						break
					}
					err = conn.WriteMessage(messageType, message)
					if err != nil {
						break
					}
				}

			},
			expectedStatus: testStatus{
				status: testStatusFail,
				msg:    "i/o timeout",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wsHandler != nil {
				srv := httptest.NewServer(http.HandlerFunc(tt.wsHandler))
				defer srv.Close()
				wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
				tt.c.Endpoint = wsURL
			} else {
				tt.c.Endpoint = "ws://localhost:8080"
			}

			checker := newWSChecker(tt.c).(*wsChecker)
			checker.wsDialer = websocket.DefaultDialer
			// test successful connection
			testStatus := checker.check()
			if !strings.Contains(testStatus.msg, tt.expectedStatus.msg) {
				t.Errorf("%s: expected status '%v', got '%v'", tt.name,
					tt.expectedStatus.msg, testStatus.msg)
			}
		})
	}

}
func TestFillWSAssertions(t *testing.T) {
	tests := []struct {
		name           string
		c              SyntheticCheck
		httpResp       *http.Response
		timers         map[string]float64
		expectedStatus testStatus
	}{
		{
			name: "response time assertion successful",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							WebSocket: AssertionsCasesOptions{
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

			httpResp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},

			expectedStatus: testStatus{
				status: testStatusOK,
			},
		},
		{
			name: "response time assertion failed",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							WebSocket: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "response_time",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "100",
										},
									},
								},
							},
						},
					},
				},
			},
			timers: map[string]float64{
				"duration": 200,
			},
			httpResp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},

			expectedStatus: testStatus{
				status: testStatusOK,
				msg:    "response time not matched with the condition",
			},
		},

		{
			name: "receive message assertion successful",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							WebSocket: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "received_message",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Value:    "test message",
										},
									},
								},
							},
						},
					},
				},
			},

			httpResp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},

			expectedStatus: testStatus{
				status: testStatusOK,
			},
		},

		{
			name: "receive message assertion failed",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							WebSocket: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "received_message",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Value:    "test ",
										},
									},
								},
							},
						},
					},
				},
			},

			httpResp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},

			expectedStatus: testStatus{
				status: testStatusOK,
				msg:    "received message not matched with the condition",
			},
		},
		{
			name: "header assertion successful",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							WebSocket: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Target:   "Content-Type",
											Operator: "equals",
											Value:    "application/json",
										},
									},
								},
							},
						},
					},
				},
			},

			httpResp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},

			expectedStatus: testStatus{
				status: testStatusOK,
			},
		},

		{
			name: "header assertion failed",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							WebSocket: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Target:   "Content-Type",
											Operator: "equals",
											Value:    "application/text",
										},
									},
								},
							},
						},
					},
				},
			},

			httpResp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},

			expectedStatus: testStatus{
				status: testStatusOK,
				msg:    "response header didn't matched with the condition",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := newWSChecker(tt.c).(*wsChecker)
			if tt.timers != nil {
				checker.timers = tt.timers
			}

			// test successful connection
			testStatus := checker.fillWSAssertions(tt.httpResp, "test message")
			if !strings.Contains(testStatus.msg, tt.expectedStatus.msg) {
				t.Errorf("%s: expected status '%v', got '%v'", tt.name,
					tt.expectedStatus.msg, testStatus.msg)
			}

		})
	}
}
