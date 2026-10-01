package worker

import (
	"errors"
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
	"go.uber.org/atomic"
)

const (
	errCheckNotAllowedToRun = "not allowed to run at this time"
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
		return newTCPChecker(c)
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
		return newUDPChecker(c)
	case "web_socket":
		return newWSChecker(c), nil
	case "grpc":
		return newGRPCChecker(c)
	}

	return nil, errors.New("no case matched")
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
	if (assert.Config.Operator == "contains_not" || assert.Config.Operator == "not_contains" || assert.Config.Operator == "does_not_contain") && strings.Contains(data, assert.Config.Value) {
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
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	protocolChecker.check()
	resp = protocolChecker.getTestResponseBody()
	return resp, nil
}

func (cs *CheckState) liveTestFire() (map[string]interface{}, error) {

	protocolChecker, err := getProtocolChecker(cs.check)
	if err != nil {
		return nil, err
	}

	testStatus := protocolChecker.check()
	timers := protocolChecker.getTimers()
	attr := protocolChecker.getAttrs()

	return map[string]interface{}{
		"testStatus": testStatus,
		"timers":     timers,
		"attr":       attr.AsRaw(),
	}, nil
}

// checkTimeRange allows overnight windows (start > end, e.g. 23:00-03:30); days_of_week applies to the day the window starts.
func checkTimeRange(tr SpecifyTimeRange, now time.Time) error {
	loc, err := time.LoadLocation(tr.Timezone)
	if err != nil {
		return err
	}
	now = now.In(loc)

	start, err := time.Parse("15:04", tr.StartTime)
	if err != nil {
		return err
	}
	end, err := time.Parse("15:04", tr.EndTime)
	if err != nil {
		return err
	}

	secOfDay := func(t time.Time) int { return t.Hour()*3600 + t.Minute()*60 + t.Second() }
	cur, startSec, endSec := secOfDay(now), secOfDay(start), secOfDay(end)

	windowDay := now
	switch {
	case startSec <= endSec && cur >= startSec && cur <= endSec:
	case startSec > endSec && cur >= startSec:
	case startSec > endSec && cur <= endSec:
		windowDay = now.AddDate(0, 0, -1)
	default:
		return fmt.Errorf("%s, current time %s outside %s-%s", errCheckNotAllowedToRun,
			now.Format("15:04:05"), tr.StartTime, tr.EndTime)
	}

	day := strings.ToLower(windowDay.Weekday().String())
	for _, d := range tr.DaysOfWeek {
		if d == day {
			return nil
		}
	}
	return fmt.Errorf("%s, window day %s, allowed days %v", errCheckNotAllowedToRun, day, tr.DaysOfWeek)
}

func (cs *CheckState) fire(logs *[]string) error {
	//	log.Printf("go: %d", runtime.NumGoroutine())
	*logs = append(*logs, fmt.Sprintf("%s fire() started 1", time.Now().String()))
	c := cs.check
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic", slog.String("error", r.(string)), slog.Int("id", cs.check.Id))
		}
	}()

	*logs = append(*logs, fmt.Sprintf("%s fire() started 2", time.Now().String()))
	if c.Request.SpecifyFrequency.SpecifyTimeRange.IsChecked {
		if err := checkTimeRange(c.Request.SpecifyFrequency.SpecifyTimeRange, time.Now()); err != nil {
			return fmt.Errorf("check %d: %w", cs.check.Id, err)
		}
		*logs = append(*logs, fmt.Sprintf("%s fire() started 6", time.Now().String()))
	}

	*logs = append(*logs, fmt.Sprintf("%s fire() started 7", time.Now().String()))
	if c.Proto == "browser" {
		browserChecker := NewBrowserChecker(c)
		browsers := c.Request.Browsers
		var wg sync.WaitGroup
		captureEndpoint := strings.ReplaceAll(cs.captureEndpoint, "{ACC}", c.AccountUID)

		for browser, devices := range browsers {
			for _, device := range devices {
				wg.Add(1)
				go func(browser string) {
					defer wg.Done()
					commandArgs := CommandArgs{
						CaptureEndpoint: captureEndpoint,
						Browser:         browser,
						CollectRum:      true,
						Device:          device,
						Region:          c.Locations,
						TestId:          fmt.Sprintf("%s-%s-%d-%s-%s", string(c.Uid), cs.location, time.Now().Unix(), browser, device),
					}
					browserChecker.CmdArgs = commandArgs
					slog.Info("Test started. TestID: %s", slog.String("testId", commandArgs.TestId), browser, device)
					_ = browserChecker.Check()
					slog.Info("Test invoked. TestID: %s", slog.String("testId", commandArgs.TestId))

				}(browser)
			}
		}
		*logs = append(*logs, fmt.Sprintf("%s fire() started 8", time.Now().String()))
		wg.Wait()
	} else {
		protocolChecker, err := getProtocolChecker(c)
		if err != nil {
			return err
		}
		testStatus := protocolChecker.check()
		*logs = append(*logs, fmt.Sprintf("%s fire() started 9", time.Now().String()))

		if c.IsPreviewRequest {
			*logs = append(*logs, fmt.Sprintf("%s fire() started 10", time.Now().String()))
			cs.finishTestRequest(protocolChecker.getTestResponseBody())

		} else {
			*logs = append(*logs, fmt.Sprintf("%s fire() started 11", time.Now().String()))
			cs.finishCheckRequest(testStatus,
				protocolChecker.getTimers(),
				protocolChecker.getAttrs())
		}
		*logs = append(*logs, fmt.Sprintf("%s fire() started 12", time.Now().String()))
	}
	*logs = append(*logs, fmt.Sprintf("%s fire() started 13", time.Now().String()))
	return nil
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
	slog.Info("code change next fire in", slog.String("interval", intervalDuration.String()),
		slog.String("fireIn", fireIn.String()))

	logs := make([]string, 0)
	if c.IsPreviewRequest {
		err := cs.fire(&logs)
		if err != nil {
			slog.Error("error firing", slog.String("error", err.Error()))
		}
		//RemoveCheck(c.check)
		return
	}

	execute := func() {
		firingLock.Lock()

		if _, ok := firing[c.Uid]; !ok {
			firing[c.Uid] = &sync.Mutex{}
		}
		lock := firing[c.Uid]
		firingLock.Unlock()

		if !lock.TryLock() {
			slog.Info("not allowed to run twice at same time", slog.Int("id", c.Id),
				slog.String("Uid", c.Uid))
			return
		}

		defer func() {
			lock.Unlock()
			firingLock.Lock()
			delete(firing, c.Uid)
			firingLock.Unlock()
		}()

		diff := time.Now().UTC().UnixMilli() - (c.CreatedAt.UTC().UnixMilli() + 20*1000)
		interval := int64(c.IntervalSeconds) * 1000
		offBy := time.Duration((diff % interval)) * time.Millisecond

		slog.Info("update fired", slog.Int("id", c.Id), slog.Int("time", time.Now().Second()),
			slog.Int("routines", runtime.NumGoroutine()), slog.String("off", offBy.String()))

		/*if offBy > 2*time.Second {
			log.Printf("------------------")
		}*/

		wg := sync.WaitGroup{}
		wgc := atomic.NewBool(false)
		wg.Add(1)
		go func() {
			defer func() {
				if wgc.CompareAndSwap(false, true) {
					defer wg.Done()
				}
			}()
			err := cs.fire(&logs)
			if err != nil {
				slog.Error("error firing", slog.String("error", err.Error()))
			}
		}()
		go func() {
			time.Sleep(1 * time.Minute)
			if wgc.CompareAndSwap(false, true) {
				slog.Error("function is stuck inside cs.fire", slog.String("uid", c.Uid), slog.String("logs", strings.Join(logs, "\n")))
				wg.Done()
			}
		}()
		wg.Wait()
		//c.update(txnId, nil)
	}

	diffUp := time.Now().UTC().Sub(c.UpdatedAt.UTC())
	if diffUp <= 30*time.Second {
		slog.Info("Updated triggering now.", slog.Int("testId", c.Id), slog.String("nextFireIn", fireIn.String()))
		execute()
	}

	cs.timerStop = TimerNew(execute, fireIn, intervalDuration)
}
