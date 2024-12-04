//go:build windows

package worker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"log/slog"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

type traceRouteChecker struct {
	ip      net.IP
	timeout int
	timers  map[string]float64
	attrs   pcommon.Map
	tracer  tracer // mock tracer
	hops    []string
}

type tracer interface {
	Trace(ctx context.Context, addr net.IP,
		callback func(*TracerouteReply)) error
	Close()
}

// MockWindowsTracer is a mock version of the tracer used for Windows
type mockWindowsTracer struct{}

// TracerouteReply is used to mock a traceroute reply.
type TracerouteReply struct {
	Hops int
	IP   net.IP
	RTT  int
}

// Trace is a mocked version of the traceroute functionality
func (m *mockWindowsTracer) Trace(ctx context.Context, addr net.IP, callback func(*TracerouteReply)) error {
	// Simulate a fixed hop for the mock
	mockReply := &TracerouteReply{
		Hops: 1,    // Only one hop in the mock
		IP:   addr, // Same IP address as the target
		RTT:  100,  // Simulate a round trip time of 100ms
	}
	callback(mockReply) // Simulate receiving a reply
	return nil
}

// Close is a no-op close method for the mock tracer
func (m *mockWindowsTracer) Close() {
	// No action needed for the mock tracer
}

// getDefaultTracer returns a mock tracer for Windows
func getDefaultTracer(timeout int) *mockWindowsTracer {
	return &mockWindowsTracer{}
}

// NewTraceRouteChecker creates a new traceRouteChecker mock for Windows
func newTraceRouteChecker(ip net.IP, timeout int, timers map[string]float64, attrs pcommon.Map) protocolChecker {
	return &traceRouteChecker{
		ip:      ip,
		timeout: timeout,
		timers:  timers,
		attrs:   attrs,
		hops:    []string{},
	}
}

// Close is a no-op close method for the traceRouteChecker mock
func (checker *traceRouteChecker) close() {
	// No action needed for the mock checker
}

// GetTimers returns the timers for the traceRouteChecker mock
func (checker *traceRouteChecker) getTimers() map[string]float64 {
	return checker.timers
}

// GetAttrs returns the attributes for the traceRouteChecker mock
func (checker *traceRouteChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

// GetTestResponseBody returns an empty map for the mock test response body
func (checker *traceRouteChecker) getTestResponseBody() map[string]interface{} {
	return map[string]interface{}{}
}

// Check is a mock implementation of the check function for Windows
func (checker *traceRouteChecker) check() testStatus {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(checker.timeout)*time.Second)
	defer cancel()

	testStatus := testStatus{
		status: testStatusOK,
		msg:    "",
	}

	start := time.Now()
	done := make(chan struct{})

	go func() {
		err := checker.tracer.Trace(ctx, checker.ip, func(reply *TracerouteReply) {
			text := fmt.Sprintf("hop %d. %v %v", reply.Hops, reply.IP, reply.RTT)
			slog.Info("mock traceroute: ", slog.String("trace", text))
			checker.hops = append(checker.hops, text)
		})

		if err != nil {
			slog.Error("mock traceroute error", slog.String("error", err.Error()))
			checker.attrs.PutStr("hops.error", err.Error())
			testStatus.status = testStatusError
			testStatus.msg = fmt.Sprintf("traceroute error %v", err.Error())
		}

		close(done)
	}()

	// Wait for either completion or timeout/cancellation
	select {
	case <-done:
		checker.timers["duration"] = timeInMs(time.Since(start))
		checker.attrs.PutInt("hops.count", int64(len(checker.hops)))
		checker.attrs.PutStr("hops", strings.Join(checker.hops, "\n"))
	case <-ctx.Done():
		checker.timers["duration"] = timeInMs(time.Since(start))
		checker.attrs.PutInt("hops.count", int64(len(checker.hops)))
		checker.attrs.PutStr("hops", strings.Join(checker.hops, "\n"))
	}

	return testStatus
}
