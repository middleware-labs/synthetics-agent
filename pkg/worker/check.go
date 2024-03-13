package worker

import (
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"log/slog"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

type SyntheticCheck struct {
	Uid string
	//Not string
	SyntheticsModel
}

type protocolChecker interface {
	check() testStatus
	getTimers() map[string]float64
	getAttrs() pcommon.Map
	getTestResponseBody() map[string]interface{}
}

type testStatus struct {
	status string
	msg    string
}

var (
	testStatusOK    string = "OK"
	testStatusFail  string = "FAIL"
	testStatusError string = "ERROR"
	testStatusPass  string = "PASS"
)

func getProtocolChecker(c SyntheticCheck) (protocolChecker, error) {
	switch c.Proto {
	case "http":
		httpChecker, err := newHTTPChecker(c)
		return httpChecker, err
	case "tcp":
		return newTCPChecker(c), nil
	case "dns":
		return newDNSChecker(c), nil
	case "ping":
		fallthrough
	case "icmp":
		pinger, err := getDefaultPinger(c)
		if err != nil {
			return nil, err
		}
		return newICMPChecker(c, pinger), nil
	case "ssl":
		return newSSLChecker(c), nil
	case "udp":
		return newUDPChecker(c), nil
	case "web_socket":
		return newWSChecker(c), nil
	case "grpc":
		return newGRPCChecker(c), nil
	}

	return nil, nil
}

func assertString(data string, assert CaseOptions) bool {
	if (assert.Config.Operator == "is" || assert.Config.Operator == "equal" ||
		assert.Config.Operator == "equals") && data != assert.Config.Value {
		return false
	}
	if assert.Config.Operator == "is_not" && data == assert.Config.Value {
		return false
	}
	if assert.Config.Operator == "contains" && !strings.Contains(data, assert.Config.Value) {
		return false
	}
	if (assert.Config.Operator == "contains_not" || assert.Config.Operator == "not_contains" || assert.Config.Operator == "does_not_contain") && strings.Index(data, assert.Config.Value) >= 0 {
		return false
	}

	if assert.Config.Operator == "matches_regex" || assert.Config.Operator == "not_matches_regex" {
		found, err := regexp.MatchString(assert.Config.Value, data)
		found = err == nil && found
		if assert.Config.Operator == "matches_regex" && !found {
			return false
		}
		if assert.Config.Operator == "not_matches_regex" && found {
			return false
		}
	}

	return true
}

func assertInt(data int64, assert CaseOptions) bool {
	in, err := strconv.ParseInt(assert.Config.Value, 10, 64)
	if err != nil {
		return false
	}
	if (assert.Config.Operator == "is" || assert.Config.Operator == "equal") && in != data {
		return false
	}
	if assert.Config.Operator == "less_than" && data >= in {
		return false
	}
	if assert.Config.Operator == "greater_than" && data <= in {
		return false
	}
	if assert.Config.Operator == "is_not" && data == in {
		return false
	}
	return true
}

func assertFloat(data float64, assert CaseOptions) bool {
	in, err := strconv.ParseFloat(assert.Config.Value, 64)
	if err != nil {
		return false
	}
	if (assert.Config.Operator == "is" || assert.Config.Operator == "equal") && in != data {
		return false
	}
	if assert.Config.Operator == "less_than" && data >= in {
		return false
	}
	if assert.Config.Operator == "greater_than" && data <= in {
		return false
	}
	if assert.Config.Operator == "is_not" && data == in {
		return false
	}
	return true
}

func percentCalc(val float64, percent float64) float64 {
	float := (val * (percent / 100)) + val
	f2d, err := strconv.ParseFloat(fmt.Sprintf("%.2f", float), 64)
	if err != nil {
		return float
	}
	return f2d
}

func (cs *CheckState) testFire() (map[string]interface{}, error) {
	protocolChecker, err := getProtocolChecker(cs.check)
	var resp map[string]interface{}
	if err == nil {
		protocolChecker.check()
		resp = protocolChecker.getTestResponseBody()
	}
	return resp, err
}
func (cs *CheckState) liveTestFire() (map[string]interface{}, error) {

	protocolChecker, err := getProtocolChecker(cs.check)

	testStatus := protocolChecker.check()
	timers := protocolChecker.getTimers()
	attr := protocolChecker.getAttrs()

	return map[string]interface{}{
		"testStatus": testStatus,
		"timers":     timers,
		"attr":       attr.AsRaw(),
	}, err
}

func (cs *CheckState) fire() {

	//	log.Printf("go: %d", runtime.NumGoroutine())
	//time.Sleep(5 * time.Second)
	c := cs.check
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic", slog.String("error", r.(string)))
		}
	}()

	if c.Request.SpecifyFrequency.SpecifyTimeRange.IsChecked {
		allow := false
		loc, err := time.LoadLocation(c.Request.SpecifyFrequency.SpecifyTimeRange.Timezone)
		if err != nil {
			allow = false
			return
		}
		today := strings.ToLower(time.Now().In(loc).Weekday().String())

		for _, day := range c.Request.SpecifyFrequency.SpecifyTimeRange.DaysOfWeek {
			if day == today {
				allow = true
			}
		}
		if allow {
			currentDate := time.Now().In(loc)
			timeFormat := "2006-01-02 15:04"

			startTimeAppendDate := fmt.Sprintf("%d-%02d-%02d %s", currentDate.Year(), currentDate.Month(), currentDate.Day(), c.Request.SpecifyFrequency.SpecifyTimeRange.StartTime)
			start, err := time.ParseInLocation(timeFormat, startTimeAppendDate, loc)
			if err != nil || currentDate.UTC().Unix() < start.UTC().Unix() {
				return
			}
			
			endTimeAppendDate := fmt.Sprintf("%d-%02d-%02d %s", currentDate.Year(), currentDate.Month(), currentDate.Day(), c.Request.SpecifyFrequency.SpecifyTimeRange.EndTime)
			end, err := time.ParseInLocation(timeFormat, endTimeAppendDate, loc)
			if err != nil || currentDate.UTC().Unix() > end.UTC().Unix() {
				return
			}
		}
	}

	protocolChecker, err := getProtocolChecker(c)
	if err != nil {
		return
	}

	testStatus := protocolChecker.check()

	isTestReq := c.CheckTestRequest.URL != ""
	if isTestReq {
		cs.finishTestRequest(protocolChecker.getTestResponseBody())
	} else {
		cs.finishCheckRequest(testStatus,
			protocolChecker.getTimers(),
			protocolChecker.getAttrs())
	}
}

type CheckState struct {
	location        string
	captureEndpoint string
	check           SyntheticCheck
	timerStop       func()
	exportClient    httpClient
}

func newCheckState(check SyntheticCheck,
	location string, captureEndpoint string) *CheckState {
	return &CheckState{
		location:        location,
		captureEndpoint: captureEndpoint,
		check:           check,
		timerStop:       nil,
		exportClient: func() httpClient {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.DisableCompression = false
			transport.MaxIdleConns = 100
			transport.ForceAttemptHTTP2 = true
			transport.MaxIdleConnsPerHost = 50

			clientTransport := (http.RoundTripper)(transport)

			return &http.Client{
				Transport: clientTransport,
				Timeout:   120 * time.Second,
			}
		}(),
		//txnId: txnId,
	}

}

var lock sync.Mutex

func (w *Worker) removeCheckState(check *SyntheticCheck) {
	lock.Lock()
	defer lock.Unlock()
	check.Uid = check.AccountUID + "_" + strconv.Itoa(check.Id)

	if w._checks[check.Uid] != nil {
		w._checks[check.Uid].remove()
		delete(w._checks, check.Uid)
	}
}
func (w *Worker) getTestState(check SyntheticCheck) *CheckState {
	return newCheckState(check, w.cfg.Location, w.cfg.CaptureEndpoint)
}

func (w *Worker) getCheckState(check SyntheticCheck) *CheckState {
	lock.Lock()
	defer lock.Unlock()
	check.Uid = check.AccountUID + "_" + strconv.Itoa(check.Id)
	checkState, ok := w._checks[check.Uid]
	if !ok {
		checkState = newCheckState(check, w.cfg.Location,
			w.cfg.CaptureEndpoint)
		w._checks[check.Uid] = checkState
	}
	return checkState
}

func (c *CheckState) remove() {
	if c.timerStop != nil {
		c.timerStop()
	}
}

var firing map[string]*sync.Mutex = map[string]*sync.Mutex{}
var firingLock = sync.Mutex{}

func (cs *CheckState) update() {
	c := cs.check
	if cs.timerStop != nil {
		cs.timerStop()
	}

	diff := time.Now().UTC().UnixMilli() - (c.CreatedAt.UTC().UnixMilli() + 20)
	interval := int64(c.IntervalSeconds) * 1000
	fireIn := time.Duration(interval-(diff%interval)) * time.Millisecond

	intervalDuration := time.Duration(c.IntervalSeconds) * time.Second

	slog.Info("next fire in", slog.String("interval", intervalDuration.String()),
		slog.String("fireIn", fireIn.String()))

	if c.CheckTestRequest.URL != "" {
		cs.fire()
		//RemoveCheck(c.check)
		return
	}

	cs.timerStop = TimerNew(func() {
		firingLock.Lock()

		if _, ok := firing[c.Uid]; !ok {
			firing[c.Uid] = &sync.Mutex{}
		}
		lock := firing[c.Uid]
		firingLock.Unlock()

		if !lock.TryLock() {
			slog.Info("not allowed to run twice at same time")
			return
		}

		diff := time.Now().UTC().UnixMilli() - (c.CreatedAt.UTC().UnixMilli() + 20*1000)
		interval := int64(c.IntervalSeconds) * 1000
		offBy := time.Duration((diff % interval)) * time.Millisecond

		slog.Info("update fired", slog.Int("id", c.Id), slog.Int("time", time.Now().Second()),
			slog.Int("routines", runtime.NumGoroutine()), slog.String("off", offBy.String()))

		/*if offBy > 2*time.Second {
			log.Printf("------------------")
		}*/

		cs.fire()

		firingLock.Lock()
		lock.Unlock()
		delete(firing, c.Uid)
		firingLock.Unlock()

		//c.update(txnId, nil)
	}, fireIn, intervalDuration)
}
