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

func (checker *traceRouteChecker) getTestBody() map[string]interface{} {
	return map[string]interface{}{}
}

func (checker *traceRouteChecker) getDetails() map[string]float64 {
	return map[string]float64{}
}

func (checker *traceRouteChecker) check() testStatus {
	defer checker.close()
	testStatus := testStatus{
		status: testStatusOK,
		msg:    "",
	}
	start := time.Now()
	err := checker.tracer.Trace(context.Background(), checker.ip, func(reply *traceroute.Reply) {
		text := fmt.Sprintf("hop %d. %v %v", reply.Hops, reply.IP, reply.RTT)
		slog.Debug("traceroute: ", slog.String("trace", text))
		checker.hops = append(checker.hops, text)
	})

	checker.attrs.PutInt("hops.count", int64(len(checker.hops)))
	checker.attrs.PutStr("hops", strings.Join(checker.hops, "\n"))
	checker.timers["duration"] = timeInMs(time.Since(start))

	if err != nil {
		slog.Error("traceroute error", slog.String("error", err.Error()))
		checker.attrs.PutStr("hops.error", err.Error())
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("traceroute error %v", err.Error())
		return testStatus
	}

	return testStatus
}
