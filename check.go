package synthetics_agent

import (
	log "github.com/sirupsen/logrus"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var _checks map[string]*CheckState = map[string]*CheckState{}

type SyntheticsModelCustom struct {
	Uid string
	Not string
	SyntheticsModel
}

func assertString(data string, assert CaseOptions) bool {
	if (assert.Config.Operator == "is" || assert.Config.Operator == "equal") && data != assert.Config.Value {
		return false
	}
	if assert.Config.Operator == "is_not" && data == assert.Config.Value {
		return false
	}
	if assert.Config.Operator == "contains" && strings.Index(data, assert.Config.Value) < 0 {
		return false
	}
	if (assert.Config.Operator == "contains_not" || assert.Config.Operator == "not_contains") && strings.Index(data, assert.Config.Value) >= 0 {
		return false
	}

	if assert.Config.Operator == "matches_regex" && assert.Config.Operator == "not_matches_regex" {
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
	return true
}
func (c SyntheticsModelCustom) fire() {
	//	log.Printf("go: %d", runtime.NumGoroutine())
	//time.Sleep(5 * time.Second)

	defer func() {
		if r := recover(); r != nil {
			log.Error(r)
		}
	}()

	if c.Request.SpecifyFrequency.Type == "advanced" && c.Request.SpecifyFrequency.SpecifyTimeRange.IsChecked {
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
			start, err := time.ParseInLocation("15:04", c.Request.SpecifyFrequency.SpecifyTimeRange.StartTime, loc)

			if err != nil || time.Now().In(loc).UTC().Unix() < start.UTC().Unix() {
				return
			}
			end, err := time.ParseInLocation("15:04", c.Request.SpecifyFrequency.SpecifyTimeRange.EndTime, loc)

			if err != nil || time.Now().In(loc).UTC().Unix() > end.UTC().Unix() {
				return
			}
		}
	}

	if c.Proto == "http" {
		CheckHttpRequest(c)
	}
	if c.Proto == "tcp" {
		CheckTcpRequest(c)
	}
	if c.Proto == "dns" {
		CheckDnsRequest(c)
	}
	if c.Proto == "ping" || c.Proto == "icmp" {
		CheckPingRequest(c)
	}
	if c.Proto == "ssl" {
		CheckSslRequest(c)
	}
	if c.Proto == "udp" {
		CheckUdpRequest(c)
	}
	if c.Proto == "web_socket" {
		CheckWsRequest(c)
	}
	if c.Proto == "grpc" {
		CheckGrpcRequest(c)
	}
}

type CheckState struct {
	timerStop func()
	txnId     string
	check     *SyntheticsModelCustom
}

var lock sync.Mutex

func RemoveCheck(check *SyntheticsModelCustom) {
	lock.Lock()
	defer lock.Unlock()
	check.Uid = check.AccountUID + "_" + strconv.Itoa(check.Id)

	if _checks[check.Uid] != nil {
		//log.Printf("[%d][%d] removed", txnId, check.Id)
		_checks[check.Uid].remove()
		delete(_checks, check.Uid)
	}
}

func RunCheck(check *SyntheticsModelCustom) {
	lock.Lock()
	defer lock.Unlock()
	check.Uid = check.AccountUID + "_" + strconv.Itoa(check.Id)
	if _checks[check.Uid] == nil {
		_checks[check.Uid] = &CheckState{}
	}
	_checks[check.Uid].update(check)
}

func (c *CheckState) remove() {
	if c.timerStop != nil {
		c.timerStop()
	}
}

var firing map[string]*sync.Mutex = map[string]*sync.Mutex{}
var firingLock = sync.Mutex{}

func (c *CheckState) update(chk *SyntheticsModelCustom) {
	if chk != nil {
		c.check = chk
	}
	if c.timerStop != nil {
		c.timerStop()
	}

	diff := time.Now().UTC().UnixNano() - (c.check.CreatedAt.UTC().Unix()+20)*int64(time.Second)
	interval := int64(c.check.IntervalSeconds) * int64(time.Second)
	fireIn := time.Duration(interval - (diff % interval))

	log.Printf("[%d] next fire in %s interval:%d", c.check.Id, fireIn.String(), c.check.IntervalSeconds)

	//diffx := (time.Now().UTC().Unix() - c.check.CreatedAt)
	//log.Printf("[%d] next fire ins %s", c.check.Id, time.Duration((c.check.IntervalSeconds-(diffx%c.check.IntervalSeconds))*int64(time.Second)).String())

	if chk.CheckTestRequest.URL != "" {
		c.check.fire()
		//RemoveCheck(c.check)
		return
	}

	c.timerStop = TimerNew(func() {
		firingLock.Lock()

		if _, ok := firing[c.check.Uid]; !ok {
			firing[c.check.Uid] = &sync.Mutex{}
		}
		lock := firing[c.check.Uid]
		firingLock.Unlock()

		if !lock.TryLock() {
			//log.Printf("not allowed to run twice at same time")
			return
		}
		log.Printf("[%d] fired %d, routings:%d", c.check.Id, time.Now().Second(), runtime.NumGoroutine())

		c.check.fire()

		firingLock.Lock()
		lock.Unlock()
		delete(firing, c.check.Uid)
		firingLock.Unlock()

		//c.update(txnId, nil)
	}, fireIn, time.Duration(interval))

}
