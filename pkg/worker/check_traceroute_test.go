package worker

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/adakailabs/go-traceroute/traceroute"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type mockTracer struct {
	hops     []string
	traceErr error
}

func newMockTracer(traceErr error) *mockTracer {
	return &mockTracer{
		traceErr: traceErr,
	}
}

func (m *mockTracer) Trace(ctx context.Context,
	addr net.IP, callback func(*traceroute.Reply)) error {
	return m.traceErr
}

func (m *mockTracer) Close() {

}

func TestTraceRouteCheck(t *testing.T) {

	tests := []struct {
		name           string
		timeout        int
		hops           []string
		traceErr       error
		expectedStatus testStatus
	}{
		{
			name:     "traceErr",
			timeout:  5,
			hops:     []string{},
			traceErr: errors.New("traceErr"),
			expectedStatus: testStatus{
				status: testStatusError,
				msg:    "traceroute error traceErr",
			},
		},
		{
			name:     "noHops",
			timeout:  5,
			hops:     []string{},
			traceErr: errors.New("no route to host"),
			expectedStatus: testStatus{
				status: testStatusError,
				msg:    "traceroute error no route to host",
			},
		},
		{
			name:     "hops",
			timeout:  5,
			hops:     []string{"1	foo.com", "2	bar.com", "3	baz.com"},
			traceErr: nil,
			expectedStatus: testStatus{
				status: testStatusOK,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := net.ParseIP("")
			timers := make(map[string]float64)
			attrs := pcommon.NewMap()
			tracer := newTraceRouteChecker(ip, test.timeout,
				timers, attrs).(*traceRouteChecker)
			tracer.hops = test.hops
			tracer.tracer = newMockTracer(test.traceErr)

			result := tracer.check()

			if result.status != test.expectedStatus.status ||
				result.msg != test.expectedStatus.msg {
				t.Fatalf("expected status '%s', got status '%s' expected msg '%s', got msg '%s'",
					test.expectedStatus.status, result.status,
					test.expectedStatus.msg, result.msg)
			}

			v, ok := tracer.attrs.Get("hops.count")
			if !ok {
				t.Fatalf("hops.count not found")
			}

			if v.AsString() != strconv.Itoa(len(test.hops)) {
				t.Fatalf("expected hops.count %d, got %s",
					len(test.hops), v.AsString())
			}

			v, ok = tracer.attrs.Get("hops")
			if !ok {
				t.Fatalf("hops not found")
			}

			if strings.Join(test.hops, "\n") != v.AsString() {
				t.Fatalf("expected hops %s, got %s",
					strings.Join(test.hops, "\n"), v.AsString())
			}

			if _, ok := tracer.timers["duration"]; !ok {
				t.Fatalf("duration not found")
			}

		})
	}
}
