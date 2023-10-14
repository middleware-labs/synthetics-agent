package worker

import (
	"context"
	"net"
	"testing"
)

type mockResolver struct {
	errLookupIP    error
	errLookupTXT   error
	errLookupNS    error
	errLookupMX    error
	errLookupCNAME error

	ips   []net.IP
	txt   []string
	ns    []*net.NS
	mx    []*net.MX
	cname string
}

func (r *mockResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return r.ips, r.errLookupIP
}

func (r *mockResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return r.txt, r.errLookupTXT
}

func (r *mockResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return r.ns, r.errLookupNS
}

func (r *mockResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	mxs := []*net.MX{}
	mxs = append(mxs, r.mx...)
	return mxs, r.errLookupMX
}

func (r *mockResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return r.cname, r.errLookupCNAME
}

func TestDNSFillAssertions(t *testing.T) {
	tests := []struct {
		name     string
		c        SyntheticsModelCustom
		resolver *mockResolver
		ips      []net.IP
		want     testStatus
		wantErr  bool
	}{
		{
			name: "DNS response time assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSResponseTime,
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
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantErr: false,
		},
		{
			name: "DNS every available record assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSEveryAvailableRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_a",
											Value:    "192.168.1.1",
										},
									},
								},
							},
						},
					},
				},
			},
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantErr: false,
		},
		{
			name: "DNS at least one record assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_a",
											Value:    "192.168.1.1",
										},
									},
								},
							},
						},
					},
				},
			},
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantErr: false,
		},
		{
			name: "DNS CNAME record assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`

											Value string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_cname",
											Value:    "cname.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				cname: "cname.example.com",
			},
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantErr: false,
		},

		{
			name: "DNS CNAME record assertion failure",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`

											Value string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_cname",
											Value:    "cname.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				cname: "cname2.example.com",
			},
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusFail,
				msg:    "assertion failed with cname2.example.com",
			},
			wantErr: false,
		},
		{
			name: "DNS CNAME record assertion resolver error",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`

											Value string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_cname",
											Value:    "cname.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				errLookupCNAME: &net.DNSError{
					Err: "resolver error",
				},
			},
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusFail,
				msg:    "no record matched with given condition ",
			},
			wantErr: false,
		},

		{
			name: "DNS MX record assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_mx",
											Value:    "mx.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				mx: []*net.MX{
					{
						Host: "mx.example.com",
						Pref: 1,
					},
				},
			},
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantErr: false,
		},
		{
			name: "DNS MX record assertion failure",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_mx",
											Value:    "mx2.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				mx: []*net.MX{
					{
						Host: "mx.example.com",
						Pref: 1,
					},
				},
			},
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusFail,
				msg:    "assertion failed with mx.example.com",
			},
			wantErr: false,
		},

		{
			name: "DNS MX record resolver error",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_mx",
											Value:    "mx.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				errLookupMX: &net.DNSError{
					Err: "resolver error",
				},
				mx: []*net.MX{
					{
						Host: "mx.example.com",
						Pref: 1,
					},
				},
			},
			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusFail,
				msg:    "no record matched with given condition ",
			},
			wantErr: false,
		},
		{
			name: "DNS NS record assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",

					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_ns",
											Value:    "ns.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				ns: []*net.NS{
					{
						Host: "ns.example.com",
					},
				},
			},

			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantErr: false,
		},
		{
			name: "DNS NS record resolver error",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",

					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_ns",
											Value:    "ns.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				errLookupNS: &net.DNSError{
					Err: "resolver error",
				},
				ns: []*net.NS{
					{
						Host: "ns.example.com",
					},
				},
			},

			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusFail,
				msg:    "no record matched with given condition ",
			},
			wantErr: false,
		},
		{
			name: "DNS NS record assertion failure",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",

					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_ns",
											Value:    "ns2.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{

				ns: []*net.NS{
					{
						Host: "ns.example.com",
					},
				},
			},

			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusFail,
				msg:    "assertion failed with ns.example.com",
			},
			wantErr: false,
		},
		{
			name: "DNS TXT record assertion",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_txt",
											Value:    "txt.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				txt: []string{
					"txt.example.com",
				},
			},

			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			wantErr: false,
		},

		{
			name: "DNS TXT record assertion failure",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_txt",
											Value:    "txt2.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				txt: []string{
					"txt.example.com",
				},
			},

			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusFail,
				msg:    "assertion failed with txt.example.com",
			},
			wantErr: false,
		},
		{
			name: "DNS TXT record resolver error",
			c: SyntheticsModelCustom{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							DNS: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: assertTypeDNSAtLeastOneRecord,
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "equals",
											Target:   "of_type_txt",
											Value:    "txt2.example.com",
										},
									},
								},
							},
						},
					},
				},
			},

			resolver: &mockResolver{
				errLookupTXT: &net.DNSError{
					Err: "resolver error",
				},
				txt: []string{
					"txt.example.com",
				},
			},

			ips: []net.IP{
				net.ParseIP("192.168.1.1"),
			},
			want: testStatus{
				status: testStatusFail,
				msg:    "no record matched with given condition ",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		checker := &dnsChecker{
			c:        tt.c,
			resolver: tt.resolver,
		}
		t.Run(tt.name, func(t *testing.T) {
			got := checker.fillAssertions(tt.ips)
			if got.status != tt.want.status {
				t.Fatalf("%s: gotStatus = %v (%s), want %v (%s)",
					tt.name, got.status, got.msg, tt.want.status,
					tt.want.msg)
			}
			if got.msg != tt.want.msg {
				t.Fatalf("%s: gotMsg %v, want %v",
					tt.name, got.msg, tt.want.msg)
			}
		})
	}
}

func TestLookupTXT(t *testing.T) {
	tests := []struct {
		name       string
		resolver   *mockResolver
		asrCount   int
		wantErrMsg string
		wantTXT    []string
	}{
		{
			name: "Single TXT record",
			resolver: &mockResolver{
				txt: []string{
					"txt.example.com",
				},
			},
			wantTXT: []string{
				"txt.example.com",
			},
		},
		{
			name: "TXT record with error",
			resolver: &mockResolver{
				errLookupTXT: &net.DNSError{
					Err: "resolver error",
				},
				txt: []string{
					"txt.example.com",
				},
			},
			wantErrMsg: "lookup : resolver error",
			wantTXT: []string{
				"txt.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := context.Background()
			endpoint := "middleware.io"
			txts, asr, err := lookupTXT(ctx, endpoint, tt.resolver)
			if err != nil && err.Error() != tt.wantErrMsg {
				t.Fatalf("%s: expected '%v', but got '%v'",
					tt.name, tt.wantErrMsg, err)
			}

			if err == nil && tt.wantErrMsg != "" {
				t.Fatalf("%s: expected '%v', but got '%v'",
					tt.name, tt.wantErrMsg, err)
			}

			if err != nil {
				return
			}

			for _, txt := range txts {
				found := false
				for _, wantTXT := range tt.wantTXT {
					if txt == wantTXT {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s: expected %v, but got %v",
						tt.name, tt.wantTXT, txt)
				}
			}
			if len(asr) != 2 {
				t.Fatalf("%s: expected two MX assertions, but got %v",
					tt.name, asr)
			}
		})
	}

}
func TestLookupNS(t *testing.T) {
	tests := []struct {
		name       string
		resolver   *mockResolver
		asrCount   int
		wantErrMsg string
		wantNS     []*net.NS
	}{
		{
			name: "NS record with one authoritative server",
			resolver: &mockResolver{
				ns: []*net.NS{
					{
						Host: "ns.example.com",
					},
				},
			},
			wantNS: []*net.NS{
				{
					Host: "ns.example.com",
				},
			},
		},
		{
			name: "NS record with multiple authoritative servers",
			resolver: &mockResolver{
				ns: []*net.NS{
					{
						Host: "ns.example.com",
					},
					{
						Host: "ns2.example.com",
					},
				},
			},
			wantNS: []*net.NS{
				{
					Host: "ns2.example.com",
				},
				{
					Host: "ns.example.com",
				},
			},
		},
		{
			name: "NS record with error",
			resolver: &mockResolver{
				errLookupNS: &net.DNSError{
					Err: "resolver error",
				},
				ns: []*net.NS{
					{
						Host: "ns.example.com",
					},
				},
			},
			wantErrMsg: "lookup : resolver error",
			wantNS: []*net.NS{
				{
					Host: "ns.example.com",
				},
				{
					Host: "ns2.example.com",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := context.Background()
			endpoint := "middleware.io"
			ns, asr, err := lookupNS(ctx, endpoint, tt.resolver)
			if err != nil && err.Error() != tt.wantErrMsg {
				t.Fatalf("%s: expected '%v', but got '%v'",
					tt.name, tt.wantErrMsg, err)
			}

			if err == nil && tt.wantErrMsg != "" {
				t.Fatalf("%s: expected '%v', but got '%v'",
					tt.name, tt.wantErrMsg, err)
			}

			if err != nil {
				return
			}

			for _, host := range ns {
				found := false
				for _, wantHost := range tt.wantNS {
					if host == wantHost.Host {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s: expected %v, but got %v",
						tt.name, tt.wantNS, ns)
				}
			}

			if len(asr) != 2 {
				t.Fatalf("%s: expected two MX assertions, but got %v",
					tt.name, asr)
			}
		})
	}
}

func TestLookupMX(t *testing.T) {
	tests := []struct {
		name       string
		resolver   *mockResolver
		asrCount   int
		wantErrMsg string
		wantMX     []*net.MX
	}{
		{
			name: "MX record with one host",
			resolver: &mockResolver{
				mx: []*net.MX{
					{
						Host: "mx.example.com",
						Pref: 1,
					},
				},
			},
			wantMX: []*net.MX{
				{
					Host: "mx.example.com",
					Pref: 1,
				},
			},
		},
		{
			name: "MX record with multiple hosts",
			resolver: &mockResolver{
				mx: []*net.MX{
					{
						Host: "mx.example.com",
						Pref: 1,
					},
					{
						Host: "mx2.example.com",
						Pref: 2,
					},
				},
			},
			wantMX: []*net.MX{
				{
					Host: "mx2.example.com",
					Pref: 2,
				},
				{
					Host: "mx.example.com",
					Pref: 1,
				},
			},
		},

		{
			name: "MX record with error",
			resolver: &mockResolver{
				errLookupMX: &net.DNSError{
					Err: "resolver error",
				},
				mx: []*net.MX{
					{
						Host: "mx.example.com",
						Pref: 1,
					},
				},
			},
			wantErrMsg: "lookup : resolver error",
			wantMX: []*net.MX{
				{
					Host: "mx.example.com",
					Pref: 1,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := context.Background()
			endpoint := "middleware.io"
			hosts, asr, err := lookupMX(ctx, endpoint, tt.resolver)
			if err != nil && err.Error() != tt.wantErrMsg {
				t.Fatalf("%s: expected '%v', but got '%v'",
					tt.name, tt.wantErrMsg, err)
			}

			if err == nil && tt.wantErrMsg != "" {
				t.Fatalf("%s: expected '%v', but got '%v'",
					tt.name, tt.wantErrMsg, err)
			}

			if err != nil {
				return
			}

			for _, host := range hosts {
				found := false
				for _, wantHost := range tt.wantMX {
					if host == wantHost.Host {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s: expected %v, but got %v",
						tt.name, tt.wantMX, hosts)
				}
			}

			if len(asr) != 2 {
				t.Fatalf("%s: expected two MX assertions, but got %v",
					tt.name, asr)
			}
		})
	}
}
func TestLookupCNAME(t *testing.T) {
	tests := []struct {
		name       string
		resolver   *mockResolver
		asrCount   int
		wantErrMsg string
		wantCNAME  []string
	}{
		{
			name: "cname lookup with one record",
			resolver: &mockResolver{
				cname: "cname.example.com",
			},
			wantCNAME: []string{
				"cname.example.com",
			},
		},
		{
			name: "cname lookup with error",
			resolver: &mockResolver{
				errLookupCNAME: &net.DNSError{
					Err: "resolver error",
				},
			},
			wantErrMsg: "lookup : resolver error",
			wantCNAME:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := context.Background()
			endpoint := "middleware.io"
			cnames, asr, err := lookupCNAME(ctx, endpoint, tt.resolver)
			if err != nil && err.Error() != tt.wantErrMsg {
				t.Fatalf("%s: expected '%v', but got '%v'",
					tt.name, tt.wantErrMsg, err)
			}

			if err == nil && tt.wantErrMsg != "" {
				t.Fatalf("%s: expected '%v', but got '%v'",
					tt.name, tt.wantErrMsg, err)
			}

			if err != nil {
				return
			}

			for _, host := range cnames {
				found := false
				for _, wantHost := range tt.wantCNAME {
					if host == wantHost {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s: expected %v, but got %v",
						tt.name, tt.wantCNAME, cnames)
				}
			}

			if len(asr) != 2 {
				t.Fatalf("%s: expected two MX assertions, but got %v",
					tt.name, asr)
			}
		})
	}
}
