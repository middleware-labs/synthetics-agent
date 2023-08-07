package syntheticsagent

import (
	"fmt"
	"time"
)

func TimerNew(fun func(), fireInNs time.Duration, interval time.Duration) func() {
	done := make(chan int)
	timer := time.NewTimer(fireInNs)
	var ticker *time.Ticker

	go func() {
		for {
			select {
			case <-timer.C:
				go fun()
				if interval > 0 && done != nil {
					ticker = time.NewTicker(interval)
					go func() {
						for {
							select {
							case <-ticker.C:
								go fun()
							case <-done:
								//close(done)
								return
							}
						}
					}()
				}
				return
			case <-done:
				//close(done)
				return
			}
		}
	}()

	return func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Recovered", r)
			}
		}()
		if done != nil {
			x := done
			done = nil
			close(x)
			timer.Stop()
			if ticker != nil {
				ticker.Stop()
			}
		}
	}
}

type Timer struct {
	interval time.Duration
	fn       func()
	ticker   *time.Timer
	process  chan struct{}
	running  bool
	id       int
}

// Start the timer.
func (timer *Timer) Start() {
	if timer.running {
		return
	}

	if timer.process != nil {
		close(timer.process)
	}

	timer.running = true
	timer.process = make(chan struct{})
	timer.ticker = time.NewTimer(timer.interval)

	go func(timer *Timer) {
		for {
			if timer.running {
				select {
				case <-timer.ticker.C:
					if !timer.running {
						return
					}

					timer.Stop()

					go timer.fn()
					return

				case <-timer.process:
					timer.Stop()
					return
				}
			} else {
				return
			}
		}
	}(timer)
}

// Stop the timer.
func (timer *Timer) Stop() {
	if timer.running {
		timer.running = false
		close(timer.process)
	}
}

// Reset the timer
func (timer *Timer) Reset() {
	timer.Stop()
	timer.Start()
}

// SetTimeout runs the specified function after waiting the specified duration (defined in milliseconds)
func SetTimeout(fn func(), duration time.Duration, id int) *Timer {
	timer := &Timer{
		running:  false,
		id:       id,
		interval: duration,
		fn:       fn,
	}

	timer.Start()

	return timer
}
