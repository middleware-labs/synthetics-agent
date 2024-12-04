//go:build !windows

package worker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"log/slog"

	"github.com/adakailabs/go-traceroute/traceroute"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type traceRouteChecker struct {
	ip      net.IP
	timeout int
	timers  map[string]float64
	attrs   pcommon.Map
	tracer  tracer
	hops    []string
}

type tracer interface {
	Trace(ctx context.Context, addr net.IP,
		callback func(*traceroute.Reply)) error
	Close()
}

func getDefaultTracer(timeout int) *traceroute.Tracer {
	return &traceroute.Tracer{
		Config: traceroute.Config{
			Delay:    50 * time.Millisecond,
			Timeout:  time.Duration(timeout) * time.Second,
			MaxHops:  100,
			Count:    3,
			Networks: []string{"ip4:icmp", "ip4:ip"},
		},
	}
}

func newTraceRouteChecker(ip net.IP, timeout int,
	timers map[string]float64, attrs pcommon.Map) protocolChecker {
	return &traceRouteChecker{
		ip:      ip,
		timeout: timeout,
		timers: map[string]float64{
			"duration": 0,
		},
		attrs:  pcommon.NewMap(),
		tracer: getDefaultTracer(timeout),
		hops:   []string{},
	}
}

func (checker *traceRouteChecker) close() {
	checker.tracer.Close()
}

func (checker *traceRouteChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *traceRouteChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *traceRouteChecker) getTestResponseBody() map[string]interface{} {
	return map[string]interface{}{}
}

func (checker *traceRouteChecker) check() testStatus {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(checker.timeout)*time.Second)
	defer cancel()
	defer checker.close()

	testStatus := testStatus{
		status: testStatusOK,
		msg:    "",
	}

	start := time.Now()
	done := make(chan struct{})

	go func() {
		err := checker.tracer.Trace(ctx, checker.ip, func(reply *traceroute.Reply) {
			text := fmt.Sprintf("hop %d. %v %v", reply.Hops, reply.IP, reply.RTT)
			slog.Info("traceroute: ", slog.String("trace", text))
			checker.hops = append(checker.hops, text)
		})

		if err != nil {
			slog.Error("traceroute error", slog.String("error", err.Error()))
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
