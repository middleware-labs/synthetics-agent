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

func (n *mockNetter) LookupIP(host string) ([]net.IP, error) {
	return n.ips, n.err
}

func (n *mockNetter) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return nil, nil
}

func (n *mockNetter) ConnClose(conn net.Conn) error {
	return nil
}

func TestTCPCheck(t *testing.T) {

	tests := []struct {
		name       string
		c          SyntheticCheck
		netter     Netter
		want       testStatus
		wantErrMsg string
	}{
		{
			name: "OK",
			c: SyntheticCheck{
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
						ResponseTimeLessThan: 5,
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
			c: SyntheticCheck{
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
						ResponseTimeLessThan: 5,
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
			c: SyntheticCheck{
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
						ResponseTimeLessThan: 5,
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
			c: SyntheticCheck{
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
						ResponseTimeLessThan: 5,
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
			checker, err := newTCPChecker(tt.c)
			if err != nil {
				t.Fatalf("Expected no error, but got: %v", err)
			}
			tcpChecker, _ := checker.(*tcpChecker)
			tcpChecker.netter = tt.netter

			got := tcpChecker.check()
			if got.status != tt.want.status {
				t.Fatalf("Expected status to be %s, but got %s", tt.want.status, got.status)
			}

			if got.msg != tt.want.msg {
				t.Fatalf("Expected msg to be %s, but got %s", tt.want.msg, got.msg)
			}

			connErr, ok := tcpChecker.attrs.Get("connection.error")
			if ok && connErr.AsString() != tt.wantErrMsg {
				t.Fatalf("Expected connection.error to be '%s', but got '%s'",
					tt.wantErrMsg, connErr.AsString())
			}
		})
	}
}
