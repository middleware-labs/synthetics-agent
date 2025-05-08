package worker

import (
	"errors"
	"fmt"
	"testing"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type mockPinger struct {
	runErr error
	stats  *probing.Statistics
	size   int
}

func (p *mockPinger) Run() error {
	if p.runErr != nil {
		return p.runErr
	}
	return nil
}

func (p *mockPinger) Statistics() *probing.Statistics {
	return p.stats
}

func (p *mockPinger) GetSize() int {
	return p.size
}

func getMockPinger(stats *probing.Statistics, runErr error) pinger {
	return &mockPinger{
		runErr: runErr,
		stats:  stats,
	}
}

func TestICMPCheck(t *testing.T) {
	// create a new ICMP checker instance
	tests := []struct {
		name        string
		stats       *probing.Statistics
		c           SyntheticCheck
		pingerErr   error
		wantDetails map[string]float64
		status      string
		msg         string
	}{
		{
			name: "icmp check with no assertions",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{
						ICMPPayload: ICMPPayloadOptions{
							PingsPerTest: 3,
						},
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{},
							},
						},
					},
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			stats: &probing.Statistics{
				PacketsSent: 5,
				PacketsRecv: 5,
				MinRtt:      time.Duration(2 * time.Second),
				MaxRtt:      time.Duration(5 * time.Second),
				AvgRtt:      0,
				StdDevRtt:   0,
				PacketLoss:  3,
			},
			pingerErr: nil,
			status:    testStatusOK,
			msg:       "",
		},
		{
			name: "pinger error",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "127.0.0.1",
					Request: SyntheticsRequestOptions{

						ICMPPayload: ICMPPayloadOptions{
							PingsPerTest: 3,
						},
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "latency",
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
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			pingerErr: errors.New("send packet: operation not permitted"),
			status:    testStatusError,
			msg:       "error running ping send packet: operation not permitted",
		},
		{
			name: "icmp check with latency assertion",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "127.0.0.1",
					Request: SyntheticsRequestOptions{

						ICMPPayload: ICMPPayloadOptions{
							PingsPerTest: 3,
						},
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "latency",
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
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			pingerErr: nil,
			stats: &probing.Statistics{
				PacketsSent: 5,
				PacketsRecv: 5,
				MinRtt:      time.Duration(2 * time.Second),
				MaxRtt:      time.Duration(5 * time.Second),
				AvgRtt:      0,
				StdDevRtt:   0,
				PacketLoss:  3,
			},
			status: testStatusOK,
			msg:    "",
		},
		{
			name: "icmp check with packet loss assertion",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{

						ICMPPayload: ICMPPayloadOptions{
							PingsPerTest: 3,
						},
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "packet_loss",
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
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			stats: &probing.Statistics{
				PacketsSent: 5,
				PacketsRecv: 5,
				MinRtt:      time.Duration(2 * time.Second),
				MaxRtt:      time.Duration(5 * time.Second),
				AvgRtt:      0,
				StdDevRtt:   0,
				PacketLoss:  4,
			},
			pingerErr: nil,
			status:    testStatusOK,
			msg:       "",
		},
		{
			name: "icmp check with packet received assertion",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{

						ICMPPayload: ICMPPayloadOptions{
							PingsPerTest: 3,
						},
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "packets_received",
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
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			stats: &probing.Statistics{
				PacketsSent: 5,
				PacketsRecv: 5,
				MinRtt:      time.Duration(2 * time.Second),
				MaxRtt:      time.Duration(5 * time.Second),
				AvgRtt:      0,
				StdDevRtt:   0,
				PacketLoss:  4,
			},
			pingerErr: nil,
			status:    testStatusOK,
		},
		{
			name: "icmp check with multiple assertions",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{

						ICMPPayload: ICMPPayloadOptions{
							PingsPerTest: 3,
						},
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "latency",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "less_than",
											Value:    "100",
										},
									},
									{
										Type: "packet_loss",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "less_than",
											Value:    "100",
										},
									},
									{

										Type: "packets_received",
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
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			stats: &probing.Statistics{
				PacketsSent: 5,
				PacketsRecv: 5,
				MinRtt:      time.Duration(2 * time.Second),
				MaxRtt:      time.Duration(5 * time.Second),
				AvgRtt:      0,
				StdDevRtt:   0,
				PacketLoss:  4,
			},
			pingerErr: nil,
			status:    testStatusOK,
		},
		{
			name: "icmp check with latency assertion that fails",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					Endpoint: "example.com",
					Request: SyntheticsRequestOptions{

						ICMPPayload: ICMPPayloadOptions{
							PingsPerTest: 3,
						},
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "latency",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "less_than",
											Value:    "1",
										},
									},
								},
							},
						},
					},
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			stats: &probing.Statistics{
				PacketsSent: 5,
				PacketsRecv: 5,
				MinRtt:      time.Duration(2 * time.Second),
				MaxRtt:      time.Duration(5 * time.Second),
				AvgRtt:      0,
				StdDevRtt:   0,
				PacketLoss:  4,
			},
			pingerErr: nil,
			status:    testStatusOK,
		},

		{
			name: "icmp check with multiple assertions with test request",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Request: SyntheticsRequestOptions{

						ICMPPayload: ICMPPayloadOptions{
							PingsPerTest: 3,
						},
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "latency",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "less_than",
											Value:    "100",
										},
									},
									{
										Type: "packet_loss",
										Config: struct {
											Operator string `json:"operator"`
											Target   string `json:"target"`
											Value    string `json:"value"`
										}{
											Operator: "less_than",
											Value:    "100",
										},
									},
									{

										Type: "packets_received",
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
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			stats: &probing.Statistics{
				PacketsSent: 5,
				PacketsRecv: 5,
				MinRtt:      time.Duration(2 * time.Second),
				MaxRtt:      time.Duration(5 * time.Second),
				AvgRtt:      0,
				StdDevRtt:   0,
				PacketLoss:  4,
			},
			pingerErr: nil,
			status:    testStatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pinger := getMockPinger(test.stats, test.pingerErr)
			icmpChecker := newICMPChecker(test.c, pinger).(*icmpChecker)
			status := icmpChecker.check()
			if status.status != test.status || status.msg != test.msg {
				t.Errorf("%s: expected status to be %s (%s), but got %s (%s)",
					test.name, test.status, test.msg, status.status, status.msg)
			}

			// no need to test results if the status is not OK
			if status.status != testStatusOK {
				return
			}

			// Test request
			if test.c.IsPreviewRequest {
				testBody := icmpChecker.getTestResponseBody()
				if testBody["rcmp_status"] != "SUCCESSFUL" {
					t.Fatalf("%s: expected test status to be SUCCESSFUL, but got %s",
						test.name, testBody["rcmp_status"])
				}

				packetMessage := fmt.Sprintf("%d packets sent, %d packets received, %f%% packet loss",
					test.stats.PacketsSent, test.stats.PacketsRecv, test.stats.PacketLoss)
				if testBody["packet"] != packetMessage {
					t.Fatalf("%s: expected message %s, but got %s",
						test.name, packetMessage, testBody["packet"])
				}

				latencyMessage := fmt.Sprintf("min/avg/max/stddev = %f/%f/%f/%f ms",
					timeInMs(test.stats.MinRtt),
					timeInMs(test.stats.AvgRtt),
					timeInMs(test.stats.MaxRtt),
					timeInMs(test.stats.StdDevRtt))

				if testBody["latency"] != latencyMessage {
					t.Fatalf("%s: expected message %s, but got %s",
						test.name, latencyMessage, testBody["latency"])
				}

				if testBody["packet_size"] != pinger.GetSize() {
					t.Fatalf("%s: expected packet size to be %d, but got %d",
						test.name, pinger.GetSize(), testBody["packet_size"])
				}
				return // no need to test the rest
			}

			timers := icmpChecker.getTimers()
			if len(timers) != 3 {
				t.Fatalf("%s: expected 3 timers, but got %d",
					test.name, len(timers))
			}

			if _, ok := timers["duration"]; !ok {
				t.Fatalf("%s: expected timer 'duration' to exist, but it doesn't",
					test.name)
			}
			if _, ok := timers["packet_loss"]; !ok {
				t.Fatalf("%s: expected timer 'packet_loss' to exist, but it doesn't",
					test.name)
			}

			if _, ok := timers["packet_recv"]; !ok {
				t.Fatalf("%s:  expected timer 'packet_recv' to exist, but it doesn't",
					test.name)
			}

			// check the details
			gotDetails := icmpChecker.details
			if len(gotDetails) != 7 {
				t.Fatalf("%s: expected 7 details, but got %d",
					test.name, len(gotDetails))
			}

			// compare packets sent
			gotPacketsSent, ok := gotDetails["packets_sent"]
			if !ok {
				t.Fatalf("%s: expected detail 'packets_sent' to exist, but it doesn't",
					test.name)
			}

			if gotPacketsSent != float64(test.stats.PacketsSent) {
				t.Fatalf("%s: expected 'packets_sent' to be %f, got %f",
					test.name, float64(test.stats.PacketsSent), gotPacketsSent)
			}

			// compare packets received
			gotPacketsReceived, ok := gotDetails["packets_received"]
			if !ok {
				t.Fatalf("%s: expected detail 'packets_received' to exist, but it doesn't",
					test.name)
			}

			if gotPacketsReceived != float64(test.stats.PacketsRecv) {
				t.Fatalf("%s: expected 'packets_received' to be %f, got %f",
					test.name, float64(test.stats.PacketsRecv), gotPacketsReceived)
			}

			gotPacketLoss, ok := gotDetails["packet_loss"]
			if !ok {
				t.Fatalf("%s: expected detail 'packet_loss' to exist, but it doesn't",
					test.name)
			}

			if gotPacketLoss != float64(test.stats.PacketLoss) {
				t.Fatalf("%s: expected 'packet_loss' to be %f, got %f",
					test.name, float64(test.stats.PacketLoss), gotPacketLoss)
			}

			gotLatencyMin, ok := gotDetails["latency_min"]
			if !ok {
				t.Fatalf("%s: expected detail 'latency_min' to exist, but it doesn't",
					test.name)
			}

			if gotLatencyMin != timeInMs(test.stats.MinRtt) {
				t.Fatalf("%s: expected 'latency_min' to be %f, got %f",
					test.name, timeInMs(test.stats.MinRtt), gotLatencyMin)
			}

			gotLatencyMax, ok := gotDetails["latency_max"]
			if !ok {
				t.Fatalf("%s: expected detail 'latency_max' to exist, but it doesn't",
					test.name)
			}

			if gotLatencyMax != timeInMs(test.stats.MaxRtt) {
				t.Fatalf("%s: expected 'latency_max' to be %f, got %f",
					test.name, timeInMs(test.stats.MaxRtt), gotLatencyMax)
			}

			gotLatencyAvg, ok := gotDetails["latency_avg"]
			if !ok {
				t.Fatalf("%s: expected detail 'latency_avg' to exist, but it doesn't",
					test.name)
			}

			if gotLatencyAvg != timeInMs(test.stats.AvgRtt) {
				t.Fatalf("%s: expected 'latency_avg' to be %f, got %f",
					test.name, timeInMs(test.stats.AvgRtt), gotLatencyAvg)
			}

			gotLatencyStdDev, ok := gotDetails["latency_std_dev"]
			if !ok {
				t.Fatalf("%s: expected detail 'latency_std_dev' to exist, but it doesn't",
					test.name)
			}

			if gotLatencyStdDev != timeInMs(test.stats.StdDevRtt) {
				t.Fatalf("%s: expected 'latency_std_dev' to be %f, got %f",
					test.name, timeInMs(test.stats.StdDevRtt), gotLatencyStdDev)
			}

		})
	}
}

func TestICMPProcessICMPResponse(t *testing.T) {

	tests := []struct {
		name       string
		c          SyntheticCheck
		testStatus testStatus
		assertions []map[string]string
		attrs      pcommon.Map
		details    map[string]float64
	}{

		{
			name: "icmp response with testStatusOK and not test request",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "latency",
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
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			testStatus: testStatus{
				status: testStatusOK,
				msg:    "",
			},
			assertions: []map[string]string{},
			details: map[string]float64{
				"packets_sent":     1,
				"packets_received": 2,
				"packet_loss":      3,
				"latency_min":      4,
				"latency_max":      5,
				"latency_avg":      6,
				"latency_std_dev":  7,
			},
		},

		{
			name: "icmp response with testStatusFail and not test request",
			c: SyntheticCheck{
				SyntheticsModel: SyntheticsModel{

					Request: SyntheticsRequestOptions{
						Assertions: AssertionsOptions{
							ICMP: AssertionsCasesOptions{
								Cases: []CaseOptions{
									{
										Type: "latency",
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
					Expect: SyntheticsExpectMeta{
						LatencyLimit:    0,
						PacketLossLimit: 0,
						HttpCode:        0,
						ResponseText:    "",
					},
				},
			},
			testStatus: testStatus{
				status: testStatusFail,
				msg:    "some error occurred",
			},
			assertions: []map[string]string{
				{
					"actual": "N/A",
					"reason": "should be less than 100",
					"status": testStatusFail,
					"type":   "latency",
				},
			},

			details: map[string]float64{
				"packets_sent":     1,
				"packets_received": 2,
				"packet_loss":      3,
				"latency_min":      4,
				"latency_max":      5,
				"latency_avg":      6,
				"latency_std_dev":  7,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			icmpChecker := newICMPChecker(test.c, nil).(*icmpChecker)
			icmpChecker.details = test.details

			icmpChecker.processICMPResponse(test.testStatus)
			if len(icmpChecker.assertions) != len(test.assertions) {
				t.Errorf("expected %d assertion, but got %d",
					len(icmpChecker.assertions), len(test.assertions))
			}

			if test.testStatus.status != testStatusOK {
				for _, assertion := range icmpChecker.assertions {
					compareAssertions(assertion, test.assertions, t)
				}
				return
			}

			for k, v := range test.details {
				if icmpChecker.details[k] != v {
					t.Errorf("expected %s to be %f, but got %f",
						k, v, icmpChecker.details[k])
				}
			}
		})
	}
}

func compareAssertions(assertion map[string]string, assertions []map[string]string, t *testing.T) {
	found := false

	for _, a := range assertions {
		if assertion["type"] != a["type"] {
			continue
		}

		found = true
		if assertion["actual"] != a["actual"] {
			t.Fatalf("expected actual to be %s, but got %s",
				a["actual"], assertion["actual"])
		}

		if assertion["reason"] != a["reason"] {
			t.Fatalf("expected reason to be %s, but got %s",
				a["reason"], assertion["reason"])
		}

		if assertion["status"] != a["status"] {
			t.Fatalf("expected status to be %s, but got %s",
				a["status"], assertion["status"])
		}
	}

	if !found {
		t.Fatalf("expected assertion %s to be found, but it wasn't",
			assertion["type"])
	}
}

func TestTimeInMs(t *testing.T) {
	// test with a duration of 1 second
	duration := time.Second
	expected := 1000.0
	actual := timeInMs(duration)
	if actual != expected {
		t.Errorf("expected %f, but got %f", expected, actual)
	}

	// test with a duration of 500 milliseconds
	duration = 500 * time.Millisecond
	expected = 500.0
	actual = timeInMs(duration)
	if actual != expected {
		t.Errorf("expected %f, but got %f", expected, actual)
	}
}
