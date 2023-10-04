package worker

import (
	"errors"
	"net"
	"testing"
	"time"
)

type mockNetter struct {
	ips []net.IP
	err error
}

func (n *mockNetter) lookupIP(host string) ([]net.IP, error) {
	return n.ips, n.err
}

func (n *mockNetter) dialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return nil, nil
}

func (n *mockNetter) connClose(conn net.Conn) error {
	return nil
}

func TestTCPChecker_check(t *testing.T) {

	tests := []struct {
		name       string
		c          SyntheticsModelCustom
		netter     netter
		want       testStatus
		wantErrMsg string
	}{
		{
			name: "OK",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "80",
						Assertions: AssertionsOptions{
							TCP: AssertionsCasesOptions{
								Cases: []CaseOptions{},
							},
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},

			netter: &mockNetter{
				ips: []net.IP{net.ParseIP("127.0.0.1")},
				err: nil,
			},
			want: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantErrMsg: "",
		},
		{
			name: "DNSResolutionError",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "80",
						Assertions: AssertionsOptions{
							TCP: AssertionsCasesOptions{
								Cases: []CaseOptions{},
							},
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},

			netter: &mockNetter{
				ips: nil,
				err: errors.New("DNS resolution error"),
			},
			want: testStatus{
				status: testStatusError,
				msg:    "error resolving dns: DNS resolution error",
			},
			wantErrMsg: "",
		},
		{
			name: "ConnectionError",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "80",
						Assertions: AssertionsOptions{
							TCP: AssertionsCasesOptions{
								Cases: []CaseOptions{},
							},
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},
			netter: &mockNetter{
				ips: []net.IP{net.ParseIP("127.0.0.1")},
				err: errors.New("TCP connection error"),
			},
			want: testStatus{
				status: testStatusError,
				msg:    "error resolving dns: TCP connection error",
			},
			wantErrMsg: "",
		},
		{
			name: "ConnectionTimeout",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Port: "80",
						Assertions: AssertionsOptions{
							TCP: AssertionsCasesOptions{
								Cases: []CaseOptions{},
							},
						},
					},
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 5,
					},
				},
			},
			netter: &mockNetter{
				ips: []net.IP{net.ParseIP("127.0.0.1")},
				err: errors.New(tcpStatusTimeout),
			},
			want: testStatus{
				status: testStatusError,
				msg:    "error resolving dns: timeout",
			},
			wantErrMsg: "timeout",
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			checker := newTCPChecker(tt.c).(*tcpChecker)
			checker.netter = tt.netter

			got := checker.check()
			if got.status != tt.want.status {
				t.Fatalf("Expected status to be %s, but got %s", tt.want.status, got.status)
			}

			if got.msg != tt.want.msg {
				t.Fatalf("Expected msg to be %s, but got %s", tt.want.msg, got.msg)
			}

			connErr, ok := checker.attrs.Get("connection.error")
			if ok && connErr.AsString() != tt.wantErrMsg {
				t.Fatalf("Expected connection.error to be '%s', but got '%s'",
					tt.wantErrMsg, connErr.AsString())
			}
		})
	}
}
