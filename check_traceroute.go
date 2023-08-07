package synthetics_agent

import (
	"context"
	"fmt"
	"github.com/adakailabs/go-traceroute/traceroute"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"net"
	"strings"
	"time"
)

func traceRoute(ip net.IP, c SyntheticsModelCustom, timers map[string]float64, attrs pcommon.Map) string {
	_start := time.Now()
	t := &traceroute.Tracer{
		Config: traceroute.Config{
			Delay:    50 * time.Millisecond,
			Timeout:  time.Duration(c.Expect.ResponseTimeLessThen) * time.Second,
			MaxHops:  100,
			Count:    3,
			Networks: []string{"ip4:icmp", "ip4:ip"},
		},
	}
	defer t.Close()
	hops := []string{}

	err := t.Trace(context.Background(), ip, func(reply *traceroute.Reply) {
		text := fmt.Sprintf("hop %d. %v %v", reply.Hops, reply.IP, reply.RTT)
		log.Printf(text)
		hops = append(hops, text)
	})
	attrs.PutInt("hops.count", int64(len(hops)))
	attrs.PutStr("hops", strings.Join(hops, "\n"))
	timers["duration"] = timeInMs(time.Since(_start))

	if err != nil {
		log.Printf("error ttl %v", err)
		attrs.PutStr("hops.error", err.Error())
		return fmt.Sprintf("traceroute error %v", err.Error())
	}
	/*for _, val := range c.Request.Assertions.Tra.Cases {
		if(val.)
	}*/
	return ""
}
