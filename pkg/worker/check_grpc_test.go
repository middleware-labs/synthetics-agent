package worker

/*import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

func TestBuildCredentials(t *testing.T) {
	// Test case 1: skipVerify is true
	creds, err := buildCredentials(true, "", "", "", "")
	if err != nil {
		t.Errorf("buildCredentials(true, \"\", \"\", \"\", \"\") returned error: %v", err)
	}
	if _, ok := creds.(*credentials.TLS); !ok {
		t.Errorf("buildCredentials(true, \"\", \"\", \"\", \"\") returned wrong type of credentials: %T", creds)
	}

	// Test case 2: caCerts is invalid
	_, err = buildCredentials(false, "invalid/path/to/caCerts", "", "", "")
	if err == nil {
		t.Error("buildCredentials(false, \"invalid/path/to/caCerts\", \"\", \"\", \"\") did not return an error")
	}

	// Test case 3: clientCert and clientKey are invalid
	_, err = buildCredentials(false, "", "invalid/path/to/clientCert", "invalid/path/to/clientKey", "")
	if err == nil {
		t.Error("buildCredentials(false, \"\", \"invalid/path/to/clientCert\", \"invalid/path/to/clientKey\", \"\") did not return an error")
	}

	// Test case 4: successful credentials creation
	// Create temporary files for clientCert and clientKey
	clientCertFile, err := ioutil.TempFile("", "clientCert")
	if err != nil {
		t.Fatalf("Failed to create temporary file for clientCert: %v", err)
	}
	defer os.Remove(clientCertFile.Name())

	clientKeyFile, err := ioutil.TempFile("", "clientKey")
	if err != nil {
		t.Fatalf("Failed to create temporary file for clientKey: %v", err)
	}
	defer os.Remove(clientKeyFile.Name())

	// Write dummy data to the temporary files
	clientCertFile.WriteString("dummy client cert data")
	clientKeyFile.WriteString("dummy client key data")

	// Create temporary file for caCerts
	caCertsFile, err := ioutil.TempFile("", "caCerts")
	if err != nil {
		t.Fatalf("Failed to create temporary file for caCerts: %v", err)
	}
	defer os.Remove(caCertsFile.Name())

	// Write dummy data to the temporary file
	caCertsFile.WriteString("dummy ca certs data")

	// Create credentials
	creds, err = buildCredentials(false, caCertsFile.Name(), clientCertFile.Name(), clientKeyFile.Name(), "example.com")
	if err != nil {
		t.Errorf("buildCredentials(false, %q, %q, %q, \"example.com\") returned error: %v", caCertsFile.Name(), clientCertFile.Name(), clientKeyFile.Name(), err)
	}
	if _, ok := creds.(*credentials.TLS); !ok {
		t.Errorf("buildCredentials(false, %q, %q, %q, \"example.com\") returned wrong type of credentials: %T", caCertsFile.Name(), clientCertFile.Name(), clientKeyFile.Name(), creds)
	}

	// Verify that the credentials were created correctly
	tlsCreds := creds.(*credentials.TLS)
	if len(tlsCreds.Config.Certificates) != 1 {
		t.Errorf("buildCredentials(false, %q, %q, %q, \"example.com\") did not load the client cert/key pair correctly", caCertsFile.Name(), clientCertFile.Name(), clientKeyFile.Name())
	}
	if !tlsCreds.Config.InsecureSkipVerify {
		t.Errorf("buildCredentials(false, %q, %q, %q, \"example.com\") did not set InsecureSkipVerify correctly", caCertsFile.Name(), clientCertFile.Name(), clientKeyFile.Name())
	}
	if len(tlsCreds.Config.RootCAs.Subjects()) != 1 {
		t.Errorf("buildCredentials(false, %q, %q, %q, \"example.com\") did not load the root CA certs correctly", caCertsFile.Name(), clientCertFile.Name(), clientKeyFile.Name())
	}
	if tlsCreds.Config.ServerName != "example.com" {
		t.Errorf("buildCredentials(false, %q, %q, %q, \"example.com\") did not set ServerName correctly", caCertsFile.Name(), clientCertFile.Name(), clientKeyFile.Name())
	}
}
func TestProcessGRPCError(t *testing.T) {
	c := SyntheticCheck{
		Request: SyntheticCheckRequest{
			Assertions: SyntheticCheckRequestAssertions{
				GRPC: SyntheticCheckRequestAssertionsGRPC{
					Cases: []SyntheticCheckRequestAssertionsGRPCCase{
						{
							Type: "some_type",
						},
						{
							Type: "another_type",
						},
					},
				},
			},
		},
	}
	testStatus := testStatusFail
	timers := map[string]float64{
		"timer1": 1.0,
		"timer2": 2.0,
	}
	expectedAssertions := []map[string]string{
		{
			"status": testStatusFail,
			"reason": "previous step failed",
			"actual": "N/A",
			"type":   "some_type",
		},
		{
			"status": testStatusFail,
			"reason": "previous step failed",
			"actual": "N/A",
			"type":   "another_type",
		},
	}
	expectedAttrs := pcommon.NewMap()
	resultStr, _ := json.Marshal(expectedAssertions)
	expectedAttrs.PutStr("assertions", string(resultStr))

	// Call the function being tested
	processGRPCError(testStatus, c, timers)

	// Check that the expected attributes were set
	if !reflect.DeepEqual(c.Attrs, expectedAttrs) {
		t.Errorf("processGRPCError did not set the expected attributes. Got: %v, want: %v", c.Attrs, expectedAttrs)
	}
}

func TestProcessGRPCHealthCheck(t *testing.T) {
	// Set up a mock gRPC server
	mockServer := grpc.NewServer()
	defer mockServer.Stop()

	// Register a mock health service on the server
	mockHealthService := &mockHealthServer{}
	healthpb.RegisterHealthServer(mockServer, mockHealthService)

	// Start the server
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start mock gRPC server: %v", err)
	}
	go mockServer.Serve(listener)
	defer listener.Close()

	// Set up a gRPC client connection to the mock server
	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial mock gRPC server: %v", err)
	}
	defer conn.Close()

	// Set up a test case
	ctx := context.Background()
	c := SyntheticCheck{
		Expect: SyntheticCheckExpect{
			ResponseTimeLessThen: 5,
		},
		Request: SyntheticCheckRequest{
			GRPCPayload: SyntheticCheckRequestGRPCPayload{
				Metadata: []SyntheticCheckRequestGRPCPayloadMetadata{
					{Name: "foo", Value: "bar"},
				},
			},
		},
	}
	timers := make(map[string]float64)

	// Test case 1: successful health check
	mockHealthService.resp = &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}
	status := processGRPCHealthCheck(ctx, conn, c, timers)
	if status.status != testStatusOK {
		t.Errorf("processGRPCHealthCheck returned unexpected status: %v", status.status)
	}
	if len(mockHealthService.reqMd) != 1 || mockHealthService.reqMd[0].Get("foo") != "bar" {
		t.Errorf("processGRPCHealthCheck did not set metadata correctly: %v", mockHealthService.reqMd)
	}
	if len(mockHealthService.req.Service) != 0 {
		t.Errorf("processGRPCHealthCheck did not set service name correctly: %v", mockHealthService.req.Service)
	}
	if len(timers) != 1 || timers["duration"] == 0 {
		t.Errorf("processGRPCHealthCheck did not set timers correctly: %v", timers)
	}

	// Test case 2: health check returns non-serving status
	mockHealthService.resp = &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_NOT_SERVING}
	status = processGRPCHealthCheck(ctx, conn, c, timers)
	if status.status != testStatusFail {
		t.Errorf("processGRPCHealthCheck returned unexpected status: %v", status.status)
	}
	if status.msg != "service unhealthy (responded with \"NOT_SERVING\")" {
		t.Errorf("processGRPCHealthCheck returned unexpected message: %v", status.msg)
	}

	// Test case 3: health check returns error
	mockHealthService.err = statusError{code: codes.Internal, msg: "internal error"}
	status = processGRPCHealthCheck(ctx, conn, c, timers)
	if status.status != testStatusError {
		t.Errorf("processGRPCHealthCheck returned unexpected status: %v", status.status)
	}
	if status.msg != "rpc error: code = Internal desc = internal error" {
		t.Errorf("processGRPCHealthCheck returned unexpected message: %v", status.msg)
	}
}
func TestProcessGRPCBehaviourCheck(t *testing.T) {
	// Set up a mock gRPC server
	mockServer := grpc.NewServer()
	defer mockServer.Stop()

	// Register a mock service on the server
	mockService := &mockService{}
	RegisterMockServiceServer(mockServer, mockService)

	// Start the server
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start mock gRPC server: %v", err)
	}
	go mockServer.Serve(listener)
	defer listener.Close()

	// Set up a gRPC client connection to the mock server
	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial mock gRPC server: %v", err)
	}
	defer conn.Close()

	// Set up the test case
	ctx := context.Background()
	c := SyntheticCheck{
		Request: SyntheticCheckRequest{
			GRPCPayload: SyntheticCheckRequestGRPCPayload{
				ServiceDefinition: "mock.MockService",
				MethodSelection:   "Echo",
				Message:           `{"value": "hello"}`,
			},
			Expect: SyntheticCheckRequestExpect{
				ResponseTimeLessThen: 5,
			},
		},
	}
	timers := make(map[string]float64)

	// Call the function being tested
	_, err = processGRPCBehaviourCheck(ctx, conn, c, timers)

	// Check that the function returned no error
	if err != nil {
		t.Errorf("processGRPCBehaviourCheck returned an error: %v", err)
	}

	// Check that the expected timers were set
	if _, ok := timers["duration"]; !ok {
		t.Errorf("processGRPCBehaviourCheck did not set the expected timer 'duration'")
	}
	if _, ok := timers["duration_resolve"]; !ok {
		t.Errorf("processGRPCBehaviourCheck did not set the expected timer 'duration_resolve'")
	}

	// Check that the mock service was called with the expected arguments
	if !reflect.DeepEqual(mockService.lastRequest, &MockRequest{Value: "hello"}) {
		t.Errorf("processGRPCBehaviourCheck did not call the mock service with the expected arguments. Got: %v, want: %v", mockService.lastRequest, &MockRequest{Value: "hello"})
	}
}*/
