package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockHTTPClient returns a fixed response/error on every call.
type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

// mockHTTPClientSequence returns different response/error per call, in order.
// Once the slice is exhausted every subsequent call returns the last entry.
type mockHTTPClientSequence struct {
	calls    int
	responses []*http.Response
	errors    []error
}

func (m *mockHTTPClientSequence) Do(req *http.Request) (*http.Response, error) {
	idx := m.calls
	if idx >= len(m.responses) {
		idx = len(m.responses) - 1
	}
	m.calls++
	return m.responses[idx], m.errors[idx]
}

// ---------------------------------------------------------------------------
// isEOFError unit tests
// ---------------------------------------------------------------------------

func TestIsEOFError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "EOF error",
			err:  errors.New("EOF"),
			want: true,
		},
		{
			name: "EOF wrapped in url error",
			err:  errors.New("Get \"http://example.com\": EOF"),
			want: true,
		},
		{
			name: "connection reset by peer",
			err:  errors.New("read tcp: connection reset by peer"),
			want: true,
		},
		{
			name: "broken pipe",
			err:  errors.New("write tcp: broken pipe"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("authentication failure"),
			want: false,
		},
		{
			name: "timeout error",
			err:  context.DeadlineExceeded,
			want: false,
		},
		{
			name: "context deadline exceeded string",
			err:  errors.New("context deadline exceeded"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEOFError(tt.err)
			if got != tt.want {
				t.Fatalf("isEOFError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// checkHTTPSingleStepRequest — EOF retry tests
// ---------------------------------------------------------------------------

func TestHTTPSingleStepRequest_EOFRetrySuccess(t *testing.T) {
	// First call returns EOF, second call succeeds — overall result must be OK.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer mockServer.Close()

	c := SyntheticCheck{
		SyntheticsModel: SyntheticsModel{
			Endpoint: mockServer.URL,
			Request: SyntheticsRequestOptions{
				HTTPPayload: HTTPPayloadOptions{},
				Assertions: AssertionsOptions{
					HTTP: AssertionsCasesOptions{Cases: []CaseOptions{}},
				},
			},
			Expect: SyntheticsExpectMeta{},
		},
	}

	protocolChecker, _ := newHTTPChecker(c)
	checker := protocolChecker.(*httpChecker)

	// Sequence: EOF on first attempt, real response on second.
	checker.client = &mockHTTPClientSequence{
		responses: []*http.Response{
			nil,
			{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
				Body:       io.NopCloser(strings.NewReader("Hello, client\n")),
			},
		},
		errors: []error{
			errors.New("EOF"),
			nil,
		},
	}

	status := checker.check()
	if status.status != testStatusOK {
		t.Fatalf("expected testStatusOK after EOF retry, got %v: %s", status.status, status.msg)
	}
}

func TestHTTPSingleStepRequest_EOFRetryExhausted(t *testing.T) {
	// Both attempts return EOF — must result in an error with the stale-connection message.
	c := SyntheticCheck{
		SyntheticsModel: SyntheticsModel{
			Endpoint: "http://127.0.0.1:19999", // nothing listening here
			Request: SyntheticsRequestOptions{
				HTTPPayload: HTTPPayloadOptions{},
				Assertions: AssertionsOptions{
					HTTP: AssertionsCasesOptions{Cases: []CaseOptions{}},
				},
			},
			Expect: SyntheticsExpectMeta{},
		},
	}

	protocolChecker, _ := newHTTPChecker(c)
	checker := protocolChecker.(*httpChecker)

	checker.client = &mockHTTPClientSequence{
		responses: []*http.Response{nil, nil},
		errors: []error{
			errors.New("EOF"),
			errors.New("EOF"),
		},
	}

	status := checker.check()
	if status.status != testStatusError {
		t.Fatalf("expected testStatusError after both attempts EOF, got %v", status.status)
	}
	if !strings.Contains(status.msg, "stale connection") {
		t.Fatalf("expected stale connection message, got: %s", status.msg)
	}
}

func TestHTTPSingleStepRequest_ConnectionResetRetrySuccess(t *testing.T) {
	// "connection reset by peer" is also an EOF-class error and should be retried.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer mockServer.Close()

	c := SyntheticCheck{
		SyntheticsModel: SyntheticsModel{
			Endpoint: mockServer.URL,
			Request: SyntheticsRequestOptions{
				HTTPPayload: HTTPPayloadOptions{},
				Assertions: AssertionsOptions{
					HTTP: AssertionsCasesOptions{Cases: []CaseOptions{}},
				},
			},
			Expect: SyntheticsExpectMeta{},
		},
	}

	protocolChecker, _ := newHTTPChecker(c)
	checker := protocolChecker.(*httpChecker)

	checker.client = &mockHTTPClientSequence{
		responses: []*http.Response{
			nil,
			{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
				Body:       io.NopCloser(strings.NewReader("Hello, client\n")),
			},
		},
		errors: []error{
			errors.New("read tcp: connection reset by peer"),
			nil,
		},
	}

	status := checker.check()
	if status.status != testStatusOK {
		t.Fatalf("expected testStatusOK after connection-reset retry, got %v: %s", status.status, status.msg)
	}
}

func TestHTTPSingleStepRequest_NonEOFErrorNoRetry(t *testing.T) {
	// A non-EOF error (e.g. auth failure) must NOT be retried.
	seq := &mockHTTPClientSequence{
		responses: []*http.Response{nil, nil},
		errors: []error{
			errors.New("authentication failure"),
			errors.New("authentication failure"),
		},
	}

	c := SyntheticCheck{
		SyntheticsModel: SyntheticsModel{
			Endpoint: "http://127.0.0.1",
			Request: SyntheticsRequestOptions{
				HTTPPayload: HTTPPayloadOptions{},
				Assertions: AssertionsOptions{
					HTTP: AssertionsCasesOptions{Cases: []CaseOptions{}},
				},
			},
			Expect: SyntheticsExpectMeta{},
		},
	}

	protocolChecker, _ := newHTTPChecker(c)
	checker := protocolChecker.(*httpChecker)
	checker.client = seq

	status := checker.check()

	if status.status != testStatusError {
		t.Fatalf("expected testStatusError, got %v", status.status)
	}
	// Must have stopped after exactly 1 call (no retry for non-EOF).
	if seq.calls != 1 {
		t.Fatalf("expected exactly 1 client call for non-EOF error, got %d", seq.calls)
	}
	if strings.Contains(status.msg, "stale connection") {
		t.Fatalf("non-EOF error should not produce stale-connection message, got: %s", status.msg)
	}
}

// ---------------------------------------------------------------------------
// Error message tests
// ---------------------------------------------------------------------------

func TestHTTPSingleStepRequest_TimeoutErrorMessage(t *testing.T) {
	c := SyntheticCheck{
		SyntheticsModel: SyntheticsModel{
			Endpoint: "http://127.0.0.1",
			Request: SyntheticsRequestOptions{
				HTTPPayload: HTTPPayloadOptions{},
				Assertions: AssertionsOptions{
					HTTP: AssertionsCasesOptions{Cases: []CaseOptions{}},
				},
			},
			Expect: SyntheticsExpectMeta{},
		},
	}

	protocolChecker, _ := newHTTPChecker(c)
	checker := protocolChecker.(*httpChecker)
	checker.client = &mockHTTPClient{
		err: fmt.Errorf("Get \"http://127.0.0.1\": context deadline exceeded"),
	}

	status := checker.check()
	if status.status != testStatusError {
		t.Fatalf("expected testStatusError, got %v", status.status)
	}
	if !strings.Contains(status.msg, "TIMEOUT") {
		t.Fatalf("expected TIMEOUT in message, got: %s", status.msg)
	}
}

func TestHTTPSingleStepRequest_EOFErrorMessage(t *testing.T) {
	c := SyntheticCheck{
		SyntheticsModel: SyntheticsModel{
			Endpoint: "http://127.0.0.1",
			Request: SyntheticsRequestOptions{
				HTTPPayload: HTTPPayloadOptions{},
				Assertions: AssertionsOptions{
					HTTP: AssertionsCasesOptions{Cases: []CaseOptions{}},
				},
			},
			Expect: SyntheticsExpectMeta{},
		},
	}

	protocolChecker, _ := newHTTPChecker(c)
	checker := protocolChecker.(*httpChecker)

	// Both attempts fail with EOF so we reach the error handler.
	checker.client = &mockHTTPClientSequence{
		responses: []*http.Response{nil, nil},
		errors:    []error{errors.New("EOF"), errors.New("EOF")},
	}

	status := checker.check()
	if status.status != testStatusError {
		t.Fatalf("expected testStatusError, got %v", status.status)
	}
	if !strings.Contains(status.msg, "stale connection") {
		t.Fatalf("expected stale connection message, got: %s", status.msg)
	}
}

func TestHTTPSingleStepRequest_GenericErrorMessage(t *testing.T) {
	c := SyntheticCheck{
		SyntheticsModel: SyntheticsModel{
			Endpoint: "http://127.0.0.1",
			Request: SyntheticsRequestOptions{
				HTTPPayload: HTTPPayloadOptions{},
				Assertions: AssertionsOptions{
					HTTP: AssertionsCasesOptions{Cases: []CaseOptions{}},
				},
			},
			Expect: SyntheticsExpectMeta{},
		},
	}

	protocolChecker, _ := newHTTPChecker(c)
	checker := protocolChecker.(*httpChecker)
	checker.client = &mockHTTPClient{
		err: errors.New("some unexpected network error"),
	}

	status := checker.check()
	if status.status != testStatusError {
		t.Fatalf("expected testStatusError, got %v", status.status)
	}
	if !strings.Contains(status.msg, "some unexpected network error") {
		t.Fatalf("expected original error in message, got: %s", status.msg)
	}
}

// ---------------------------------------------------------------------------
// Existing tests (unchanged logic, fixed body-check for non-JSON responses)
// ---------------------------------------------------------------------------

func TestHTTPSingleStepRequest(t *testing.T) {
	tests := []struct {
		name        string
		c           SyntheticCheck
		httpClient  httpClient
		httpHandler http.HandlerFunc
		wantStatus  testStatus
	}{
		{
			name: "Test HTTP GET request",
			c: SyntheticCheck{
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
			c: SyntheticCheck{
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
			c: SyntheticCheck{
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
										}{Operator: "is", Value: "Hello, client\n"},
									},
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is_not", Value: "Hello, world\n"},
									},
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "contains", Value: "Hello"},
									},
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "contains_not", Value: "world"},
									},
									{
										Type: "body",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "match_regex", Value: "cli"},
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
			wantStatus: testStatus{status: testStatusOK, msg: ""},
		},
		{
			name: "Test HTTP GET request with invalid body assertion",
			c: SyntheticCheck{
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
										}{Operator: "is", Value: "Hello, world"},
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
			wantStatus: testStatus{status: testStatusFail, msg: ""},
		},
		{
			name: "Test HTTP GET request with body hash assertion",
			c: SyntheticCheck{
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
										}{Operator: "is", Target: "md5", Value: "d32da7152864375f6fb7fce78877a98c"},
									},
									{
										Type: "body_hash",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Target: "sha1", Value: "d82302cc5308b027b784c9f607f4ebba39301204"},
									},
									{
										Type: "body_hash",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Target: "sha256", Value: "baff478af5e0a1ffbfcaca5d1a3b8993872e9f542cf1a5f82dd49c3eaed76c1c"},
									},
									{
										Type: "body_hash",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Target: "sha512", Value: "d99982ab545323e0f284af46c264e1791b09e2eb90220981565f6a59e76385252f63d86e76990c65a67d72bc9114d25957e348402f7305bdb638f16bfbabd9ec"},
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
			wantStatus: testStatus{status: testStatusOK, msg: ""},
		},
		{
			name: "Test HTTP GET request with invalid body hash assertion",
			c: SyntheticCheck{
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
										}{Operator: "is", Target: "md5", Value: "invalidhash"},
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
			wantStatus: testStatus{status: testStatusFail, msg: ""},
		},
		{
			name: "Test HTTP GET request with header assertion",
			c: SyntheticCheck{
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
										}{Operator: "is", Target: "Content-Type", Value: "text/plain; charset=utf-8"},
									},
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is_not", Target: "Content-Type", Value: "text/json; charset=utf-8"},
									},
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "contains", Target: "Content-Type", Value: "plain"},
									},
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "contains_not", Target: "Content-Type", Value: "json"},
									},
									{
										Type: "header",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "match_regex", Target: "Content-Type", Value: "utf-8"},
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
			wantStatus: testStatus{status: testStatusOK, msg: ""},
		},
		{
			name: "Test HTTP GET request with invalid header assertion",
			c: SyntheticCheck{
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
										}{Operator: "is", Target: "Content-Type", Value: "text/json; charset=utf-8"},
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
			wantStatus: testStatus{status: testStatusFail, msg: ""},
		},
		{
			name: "Test HTTP GET request with response time assertion",
			c: SyntheticCheck{
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
										}{Operator: "less_than", Value: "1000"},
									},
									{
										Type: "response_time",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "greather_than", Value: "0"},
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
			wantStatus: testStatus{status: testStatusOK, msg: ""},
		},
		{
			name: "Test HTTP GET request with invalid response time assertion",
			c: SyntheticCheck{
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
										}{Operator: "is", Value: "100000"},
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
			wantStatus: testStatus{status: testStatusFail, msg: ""},
		},
		{
			name: "Test HTTP GET request with status code assertion",
			c: SyntheticCheck{
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
										}{Operator: "is", Value: "200"},
									},
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "less_than", Value: "300"},
									},
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "greather_than", Value: "199"},
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
			wantStatus: testStatus{status: testStatusOK, msg: ""},
		},
		{
			name: "Test HTTP GET request with invalid status code assertion",
			c: SyntheticCheck{
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
										}{Operator: "is", Value: "100000"},
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
			wantStatus: testStatus{status: testStatusFail, msg: ""},
		},
		{
			name: "Test HTTP GET request with failure",
			c: SyntheticCheck{
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
										}{Operator: "is_not", Value: "Hello, world\n"},
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
			// FIX: original test checked body content but the handler returns
			// text/plain — the body field is only set for application/json
			// responses. The real failure here is the non-2XX status code.
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

			checker.c.Endpoint = mockServer.URL

			status := checker.check()
			if status.status != tt.wantStatus.status && status.msg != tt.wantStatus.msg {
				t.Fatalf("Expected status to be %v, but got %v (msg: %s)",
					tt.wantStatus, status.status, status.msg)
			}

			if status.status != testStatusOK {
				return
			}

			expectedStatusCode := http.StatusOK
			if checker.testBody["statusCode"] != expectedStatusCode {
				t.Fatalf("Expected status code to be %d, but got %d",
					expectedStatusCode, checker.testBody["statusCode"])
			}

			expectedHeaders := map[string]string{
				"Content-Type":   "text/plain; charset=utf-8",
				"Content-Length": "14",
			}
			testBodyHeaders, ok := checker.testBody["headers"].(map[string]string)
			if !ok {
				t.Fatalf("Expected headers to be map[string]string, got %T",
					checker.testBody["headers"])
			}
			for k, v := range expectedHeaders {
				cv, ok := testBodyHeaders[k]
				if !ok || cv != v {
					t.Fatalf("Expected header %q = %q, got %q", k, v, cv)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildHttpRequest (unchanged from original)
// ---------------------------------------------------------------------------

func TestBuildHttpRequest(t *testing.T) {
	tests := []struct {
		name       string
		c          SyntheticCheck
		httpClient httpClient
		method     string
		errMsg     string
	}{
		{
			name: "Test HTTP GET request",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "GET",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{Content: "test", Type: "text/plain"},
							Cookies:     "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type:  "basic",
								Basic: Basic{Username: "user", Password: "pass"},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{{Name: "X-Test-Header", Value: "test"}},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Value: "200"},
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
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "POST",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{Content: "test", Type: "text/plain"},
							Cookies:     "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type:  "basic",
								Basic: Basic{Username: "user", Password: "pass"},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{{Name: "X-Test-Header", Value: "test"}},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Value: "200"},
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
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "PUT",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{Content: "test", Type: "text/plain"},
							Cookies:     "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type:  "basic",
								Basic: Basic{Username: "user", Password: "pass"},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{{Name: "X-Test-Header", Value: "test"}},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Value: "200"},
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
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "%",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "GET",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{Content: "test", Type: "text/plain"},
							Cookies:     "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type:  "basic",
								Basic: Basic{Username: "user", Password: "pass"},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{{Name: "X-Test-Header", Value: "test"}},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Value: "200"},
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
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "GET",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{Content: "test", Type: "text/plain"},
							Cookies:     "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type:   "digest",
								Digest: Digest{Username: "user", Password: "pass"},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{{Name: "X-Test-Header", Value: "test"}},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Value: "200"},
									},
								},
							},
						},
					},
				},
			},
			httpClient: &mockHTTPClient{err: errors.New("http client error")},
			method:     "GET",
			errMsg:     "error while requesting preauth: http client error",
		},
		{
			name: "Test HTTP GET request status code should be unauthorized",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "https://example.com",
					Request: SyntheticsRequestOptions{
						HTTPMethod: "GET",
						HTTPPayload: HTTPPayloadOptions{
							RequestBody: RequestBody{Content: "test", Type: "text/plain"},
							Cookies:     "cookie1=value1\ncookie2=value2",
							Authentication: Authentication{
								Type:   "digest",
								Digest: Digest{Username: "user", Password: "pass"},
							},
						},
						HTTPHeaders: []HTTPHeadersOptions{{Name: "X-Test-Header", Value: "test"}},
						Assertions: AssertionsOptions{
							HTTP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "status_code",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{Operator: "is", Value: "200"},
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
				t.Fatalf("Unexpected error: got %v, want %v", err.Error(), tt.errMsg)
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
				t.Fatalf("Unexpected error: got %v, want %v", err.Error(), tt.errMsg)
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
				t.Fatalf("Unexpected Content-Type header: %v", req.Header.Get("Content-Type"))
			}
			if req.Header.Get("Cookie") != "cookie1=value1" {
				t.Fatalf("Unexpected Cookie header: %v", req.Header.Get("Cookie"))
			}
		})
	}
}
