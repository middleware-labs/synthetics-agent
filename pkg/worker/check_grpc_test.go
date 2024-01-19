package worker

import (
	"errors"
	grpccheckerhelper "github.com/middleware-labs/synthetics-agent/pkg/worker/grpc-checker"
	"strings"
	"testing"

	"context"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

var rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJAI/M7BYjwB+uMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJ
hPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNa
rtNuC+BdZ1tMuVCPFZcCAwEAAaNQME4wHQYDVR0OBBYEFJvKs8RfJaXTH08W+SGv
zQyKn0H8MB8GA1UdIwQYMBaAFJvKs8RfJaXTH08W+SGvzQyKn0H8MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADQQBJlffJHybjDGxRMqaRmDhX0+6v02TUKZsW
r5QuVbpQhH6u+0UgcW0jp9QwpxoPTLTWGXEWBBBurxFwiCBhkQ+V
-----END CERTIFICATE-----
`

var rsaKeyPEM = testingKey(`-----BEGIN RSA TESTING KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END RSA TESTING KEY-----
`)

func TestBuildCredentials(t *testing.T) {
	tests := []struct {
		name        string
		skipVerify  bool
		caCerts     string
		clientCert  string
		clientKey   string
		serverName  string
		expectedErr bool
	}{
		{
			name:       "Skip verify is true",
			skipVerify: true,
		},
		{
			name:        "Invalid caCerts path",
			caCerts:     "invalid/path/to/caCerts",
			expectedErr: true,
		},
		{
			name:        "Invalid clientCert and clientKey paths",
			clientCert:  "invalid/path/to/clientCert",
			clientKey:   "invalid/path/to/clientKey",
			expectedErr: true,
		},
		{
			name:        "Valid credentials creation",
			caCerts:     "",
			clientCert:  rsaCertPEM,
			clientKey:   rsaKeyPEM,
			serverName:  "example.com",
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := grpccheckerhelper.BuildCredentialsTLS(tt.caCerts, tt.clientCert, tt.clientKey, tt.serverName)
			if tt.expectedErr {
				if err == nil {
					t.Fatalf("buildCredentials(%v, %q, %q, %q, %q) did not return an error", tt.skipVerify, tt.caCerts, tt.clientCert, tt.clientKey, tt.serverName)
				}
			} else {
				if err != nil {
					t.Fatalf("buildCredentials(%v, %q, %q, %q, %q) returned error: %v", tt.skipVerify, tt.caCerts, tt.clientCert, tt.clientKey, tt.serverName, err)
				}
				if creds == nil {
					t.Fatalf("buildCredentials(%v, %q, %q, %q, %q) returned nil credentials", tt.skipVerify, tt.caCerts, tt.clientCert, tt.clientKey, tt.serverName)
				}

				if creds.Info().SecurityProtocol != "tls" {
					t.Fatalf("buildCredentials(%v, %q, %q, %q, %q) returned credentials with wrong security protocol: %q",
						tt.skipVerify, tt.caCerts, tt.clientCert, tt.clientKey, tt.serverName, creds.Info().SecurityProtocol)
				}

				if creds.Info().ServerName != tt.serverName {
					t.Fatalf("buildCredentials(%v, %q, %q, %q, %q) returned credentials with wrong server name: %q", tt.skipVerify, tt.caCerts, tt.clientCert, tt.clientKey, tt.serverName, creds.Info().ServerName)
				}

			}
		})
	}
}

type mockHealthClient struct {
	checkErr   error
	grpcStatus healthpb.HealthCheckResponse_ServingStatus
}

func (m *mockHealthClient) Check(ctx context.Context,
	in *healthpb.HealthCheckRequest, opts ...grpc.CallOption) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{
		Status: m.grpcStatus,
	}, m.checkErr

}

func (m *mockHealthClient) Watch(ctx context.Context,
	in *healthpb.HealthCheckRequest, opts ...grpc.CallOption) (healthpb.Health_WatchClient, error) {
	return nil, nil
}

func TestProcessGRPCHealthCheck(t *testing.T) {

	tests := []struct {
		name              string
		ctx               context.Context
		healthClient      healthpb.HealthClient
		c                 SyntheticCheck
		timers            map[string]float64
		expectedStatusMsg string
	}{
		{
			name: "successful health check",
			ctx:  context.Background(),
			healthClient: &mockHealthClient{
				grpcStatus: healthpb.HealthCheckResponse_SERVING,
			},
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 10,
					},
					Request: SyntheticsRequestOptions{
						GRPCPayload: GRPCPayloadOptions{
							Metadata: []struct {
								Name  string `json:"name"`
								Value string `json:"value"`
							}{
								{Name: "key1", Value: "value1"},
								{Name: "key2", Value: "value2"},
							},
						},
					},
				},
			},
			timers:            map[string]float64{},
			expectedStatusMsg: "",
		},
		{
			name: "failed health check not serving",
			ctx:  context.Background(),
			healthClient: &mockHealthClient{
				grpcStatus: healthpb.HealthCheckResponse_NOT_SERVING,
			},
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 10,
					},
					Request: SyntheticsRequestOptions{
						GRPCPayload: GRPCPayloadOptions{
							Metadata: []struct {
								Name  string `json:"name"`
								Value string `json:"value"`
							}{
								{Name: "key1", Value: "value1"},
								{Name: "key2", Value: "value2"},
							},
						},
					},
				},
			},
			timers:            map[string]float64{},
			expectedStatusMsg: "service unhealthy (responded with \"NOT_SERVING\")",
		},

		{
			name: "failed health check error",
			ctx:  context.Background(),
			healthClient: &mockHealthClient{
				checkErr:   errors.New("error in health check"),
				grpcStatus: healthpb.HealthCheckResponse_NOT_SERVING,
			},
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Expect: SyntheticsExpectMeta{
						ResponseTimeLessThen: 10,
					},
					Request: SyntheticsRequestOptions{
						GRPCPayload: GRPCPayloadOptions{
							Metadata: []struct {
								Name  string `json:"name"`
								Value string `json:"value"`
							}{
								{Name: "key1", Value: "value1"},
								{Name: "key2", Value: "value2"},
							},
						},
					},
				},
			},
			timers:            map[string]float64{},
			expectedStatusMsg: "error: rpc failed, status is not OK error in health check",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := newGRPCChecker(tt.c).(*grpcChecker)

			actualStatus := checker.check()

			if actualStatus.msg != tt.expectedStatusMsg {
				t.Fatalf("%s:returned status message %q, expected %q", tt.name,
					actualStatus.msg, tt.expectedStatusMsg)
			}

			if actualStatus.status != testStatusOK {
				return
			}

		})
	}
}
