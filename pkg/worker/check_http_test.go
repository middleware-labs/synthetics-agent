package worker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

func TestHTTPChecker_checkHTTPSingleStepRequest(t *testing.T) {
	tests := []struct {
		name        string
		c           SyntheticsModelCustom
		httpClient  httpClient
		httpHandler http.HandlerFunc
		wantStatus  testStatus
	}{

		{
			name: "Test HTTP GET request",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{},
							},
						},
					},
					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
		},
		{
			name: "Test HTTP GET request auth failure",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{

						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{},
							},
						},
					},
				},
			},
			httpClient: &mockHTTPClient{
				err: fmt.Errorf("authentication failure"),
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusError,
				msg:    "authentication failure",
			},
		},
		{
			name: "Test HTTP GET request with body assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "Hello, client\n",
										},
									},
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is_not",
											Value:    "Hello, world\n",
										},
									},

									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "contains",
											Value:    "Hello",
										},
									},

									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "contains_not",
											Value:    "world",
										},
									},
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "match_regex",
											Value:    "cli",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
		},

		{
			name: "Test HTTP GET request with invalid body assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "Hello, world",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusFail,
				msg:    "",
			},
		},
		{
			name: "Test HTTP GET request with body hash assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "body_hash",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Target:   "md5",
											Value:    "d32da7152864375f6fb7fce78877a98c",
										},
									},
									{
										Type: "body_hash",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Target:   "sha1",
											Value:    "d82302cc5308b027b784c9f607f4ebba39301204",
										},
									},
									{
										Type: "body_hash",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Target:   "sha256",
											Value:    "baff478af5e0a1ffbfcaca5d1a3b8993872e9f542cf1a5f82dd49c3eaed76c1c",
										},
									},
									{
										Type: "body_hash",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Target:   "sha512",
											Value:    "d99982ab545323e0f284af46c264e1791b09e2eb90220981565f6a59e76385252f63d86e76990c65a67d72bc9114d25957e348402f7305bdb638f16bfbabd9ec",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
		},

		{
			name: "Test HTTP GET request with invalid body hash assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "body_hash",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Target:   "md5",
											Value:    "invalidhash",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusFail,
				msg:    "",
			},
		},

		{
			name: "Test HTTP GET request with header assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Target:   "Content-Type",
											Value:    "text/plain; charset=utf-8",
										},
									},
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is_not",
											Target:   "Content-Type",
											Value:    "text/json; charset=utf-8",
										},
									},

									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "contains",
											Target:   "Content-Type",
											Value:    "plain",
										},
									},

									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "contains_not",
											Target:   "Content-Type",
											Value:    "json",
										},
									},
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "match_regex",
											Target:   "Content-Type",
											Value:    "utf-8",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
		},

		{
			name: "Test HTTP GET request with invalid header assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Target:   "Content-Type",
											Value:    "text/json; charset=utf-8",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusFail,
				msg:    "",
			},
		},

		{
			name: "Test HTTP GET request with response time assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "response_time",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "less_than",
											Value:    "1000",
										},
									},

									{
										Type: "response_time",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "greather_than",
											Value:    "0",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
		},

		{
			name: "Test HTTP GET request with invalid reponse time assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "response_time",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "100000",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusFail,
				msg:    "",
			},
		},
		{
			name: "Test HTTP GET request with status code assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "200",
										},
									},
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "less_than",
											Value:    "300",
										},
									},

									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "greather_than",
											Value:    "199",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
		},
		{
			name: "Test HTTP GET request with invalid status code assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "100000",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			},
			wantStatus: testStatus{
				status: testStatusFail,
				msg:    "",
			},
		},
		{
			name: "Test HTTP GET request with failure",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{

					Endpoint: "http://127.0.0.1",
					Request: SyntheticsRequestOptions{
						HTTPPayload: HTTPPayloadOptions{},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is_not",
											Value:    "Hello, world\n",
										},
									},
								},
							},
						},
					},

					Expect: SyntheticsExpectMeta{},
				},
			},
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			},
			wantStatus: testStatus{
				status: testStatusFail,
				msg:    "response code is not 2XX, received response code: 500",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			protocolChecker, _ := newHTTPChecker(tt.c)
			checker := protocolChecker.(*httpChecker)
			if tt.httpClient != nil {
				checker.client = tt.httpClient
			}
			mockServer := httptest.NewServer(tt.httpHandler)
			defer mockServer.Close()

			// set the endpoint to the mock server URL
			checker.c.Endpoint = mockServer.URL

			// call the checkHTTPSingleStepRequest method
			status := checker.check()
			// check that the status is OK
			if status.status != tt.wantStatus.status && status.msg != tt.wantStatus.msg {
				t.Fatalf("Expected status to be %v, but got %v",
					tt.wantStatus, status.status)
			}

			// no need to test further if the status is not OK
			if status.status != testStatusOK {
				return
			}

			// check that the response body is correct
			expectedBody := "Hello, client\n"
			if checker.testBody["body"] != expectedBody {
				t.Fatalf("Expected response body to be %q, but got %q", expectedBody, checker.testBody["body"])
			}

			// check that the status code is correct
			expectedStatusCode := http.StatusOK
			if checker.testBody["statusCode"] != expectedStatusCode {
				t.Fatalf("Expected status code to be %d, but got %d", expectedStatusCode, checker.testBody["statusCode"])
			}

			// check that the headers are correct
			expectedHeaders := map[string]string{
				"Content-Type":   "text/plain; charset=utf-8",
				"Content-Length": "14",
			}

			testBodyHeaders, ok := checker.testBody["headers"].(map[string]string)
			if !ok {
				t.Fatalf("Expected headers to be a map[string]interface{}, but got %T", checker.testBody["headers"])
			}

			for k, v := range expectedHeaders {
				cv, ok := testBodyHeaders[k]
				if !ok || cv != v {
					t.Fatalf("Expected header %q to be %q, but got %q", k, v, cv)
				}
			}
		})
	}
}

func TestBuildHttpRequest(t *testing.T) {
	tests := []struct {
		name       string
		c          SyntheticsModelCustom
		httpClient httpClient
		method     string
		errMsg     string
	}{
		{
			name: "Test HTTP GET request",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "GET",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test",
								Type:    "text/plain",
							},
							Cookies: "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type: "basic",
								Basic: Basic{
									Username: "user",
									Password: "pass",
								},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{
							{
								Name:  "X-Test-Header",
								Value: "test",
							},
						},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "200",
										},
									},
								},
							},
						},
					},
				},
			},
			method: "GET",
		},
		{
			name: "Test HTTP POST request",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "POST",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test",
								Type:    "text/plain",
							},
							Cookies: "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type: "basic",
								Basic: Basic{
									Username: "user",
									Password: "pass",
								},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{
							{
								Name:  "X-Test-Header",
								Value: "test",
							},
						},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`

											Target string `json:"target"`

											Value string `json:"value"`
										}{
											Operator: "is",
											Value:    "200",
										},
									},
								},
							},
						},
					},
				},
			},
			method: "POST",
		},
		{
			name: "Test HTTP PUT request",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "PUT",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test",
								Type:    "text/plain",
							},
							Cookies: "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type: "basic",
								Basic: Basic{
									Username: "user",
									Password: "pass",
								},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{
							{
								Name:  "X-Test-Header",
								Value: "test",
							},
						},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`

											Target string `json:"target"`

											Value string `json:"value"`
										}{
											Operator: "is",
											Value:    "200",
										},
									},
								},
							},
						},
					},
				},
			},
			method: "PUT",
		},
		{
			name: "Test HTTP request with invalid method",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "%",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "GET",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test",
								Type:    "text/plain",
							},
							Cookies: "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type: "basic",
								Basic: Basic{
									Username: "user",
									Password: "pass",
								},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{
							{
								Name:  "X-Test-Header",
								Value: "test",
							},
						},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "200",
										},
									},
								},
							},
						},
					},
				},
			},
			method: "GET",
			errMsg: "parse \"%\": invalid URL escape \"%\"",
		},
		{
			name: "Test HTTP GET request http client error",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "GET",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test",
								Type:    "text/plain",
							},
							Cookies: "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type: "digest",
								Digest: Digest{
									Username: "user",
									Password: "pass",
								},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{
							{
								Name:  "X-Test-Header",
								Value: "test",
							},
						},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "200",
										},
									},
								},
							},
						},
					},
				},
			},
			httpClient: &mockHTTPClient{
				err: errors.New("http client error"),
			},

			method: "GET",
			errMsg: "error while requesting preauth: http client error",
		},

		{
			name: "Test HTTP GET request status code should be unauthorized",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "GET",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{
								Content: "test",
								Type:    "text/plain",
							},
							Cookies: "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type: "digest",
								Digest: Digest{
									Username: "user",
									Password: "pass",
								},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{
							{
								Name:  "X-Test-Header",
								Value: "test",
							},
						},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "is",
											Value:    "200",
										},
									},
								},
							},
						},
					},
				},
			},
			httpClient: &mockHTTPClient{
				response: &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte("Hello, client"))),
				},
			},

			method: "GET",
			errMsg: "recieved status code '200' while preauth but expected 401",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			protocolChecker, err := newHTTPChecker(tt.c)
			if err != nil && err.Error() != tt.errMsg {
				t.Fatalf("Unexpected error: got %v, want %v",
					err.Error(), tt.errMsg)
			}

			if err != nil {
				return
			}

			checker := protocolChecker.(*httpChecker)
			if tt.httpClient != nil {
				checker.client = tt.httpClient
			}

			req, err := checker.buildHttpRequest(true)
			if err != nil && err.Error() != tt.errMsg {
				t.Fatalf("Unexpected error: got %v, want %v",
					err.Error(), tt.errMsg)
			}

			if err != nil {
				return
			}

			if req.Method != tt.method {
				t.Fatalf("Unexpected method: %v", req.Method)
			}

			if req.URL.String() != "https://example.com" {
				t.Fatalf("Unexpected URL: %v", req.URL.String())
			}

			if req.Header.Get("Content-Type") != "text/plain" {
				t.Fatalf("Unexpected Content-Type header: %v",
					req.Header.Get("Content-Type"))
			}

			if req.Header.Get("Set-Cookie") != "cookie1=value1" {
				t.Fatalf("Unexpected Set-Cookie header: %v", req.Header.Get("Set-Cookie"))
			}

		})
	}
}
