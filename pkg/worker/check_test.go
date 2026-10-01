package worker

import (
	"strings"
	"testing"
	"time"
)

func TestFire(t *testing.T) {
	tests := []struct {
		name      string
		check     CheckState
		errString string
	}{
		{
			name: "SpecifyFrequency timezone unknown",
			check: CheckState{
				check: SyntheticCheck{
					SyntheticsModel: SyntheticsModel{
						Id: 1,
						Request: SyntheticsRequestOptions{
							SpecifyFrequency: SpecifyFrequencyOptions{

								SpecifyTimeRange: SpecifyTimeRange{
									IsChecked: true,
									Timezone:  "galaxy/mars",
								},
							},
						},
					},
				},
			},
			errString: "check 1: unknown time zone galaxy/mars",
		},
		{
			name: "SpecifyFrequency checked",
			check: CheckState{
				check: SyntheticCheck{
					SyntheticsModel: SyntheticsModel{
						Id: 1,
						Request: SyntheticsRequestOptions{
							SpecifyFrequency: SpecifyFrequencyOptions{

								SpecifyTimeRange: SpecifyTimeRange{
									IsChecked:  true,
									StartTime:  "00:00",
									EndTime:    "23:59",
									DaysOfWeek: []string{},
								},
							},
						},
					},
				},
			},
			errString: "check 1: not allowed to run at this time",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cs := &test.check
			err := cs.fire(&[]string{})
			if err != nil {
				if !strings.HasPrefix(err.Error(), test.errString) {
					t.Errorf("expected error %s, got %s", test.errString, err.Error())
				}
			}
			if err == nil && test.errString != "" {
				t.Errorf("expected error %s, got nil", test.errString)
			}
		})
	}
}

func TestCheckTimeRange(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-09-28 is a Monday.
	at := func(day, hour, min int) time.Time { return time.Date(2026, 9, day, hour, min, 0, 0, loc) }
	allDays := []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}

	tests := []struct {
		name       string
		start, end string
		days       []string
		now        time.Time
		allowed    bool
	}{
		{"same-day inside", "09:00", "17:00", allDays, at(28, 12, 0), true},
		{"same-day before start", "09:00", "17:00", allDays, at(28, 8, 59), false},
		{"same-day after end", "09:00", "17:00", allDays, at(28, 17, 1), false},
		{"same-day end inclusive", "09:00", "17:00", allDays, at(28, 17, 0), true},
		{"overnight before midnight", "23:00", "03:30", allDays, at(28, 23, 30), true},
		{"overnight after midnight", "23:00", "03:30", allDays, at(29, 2, 0), true},
		{"overnight end inclusive", "23:00", "03:30", allDays, at(29, 3, 30), true},
		{"overnight gap", "23:00", "03:30", allDays, at(28, 12, 0), false},
		{"overnight 11:00-03:00 afternoon", "11:00", "03:00", allDays, at(28, 15, 0), true},
		{"overnight morning gap", "11:00", "03:00", allDays, at(28, 5, 0), false},
		{"overnight tail uses start day", "23:00", "03:30", []string{"monday"}, at(29, 1, 0), true},
		{"overnight tail start day not allowed", "23:00", "03:30", []string{"tuesday"}, at(29, 1, 0), false},
		{"overnight head start day not allowed", "23:00", "03:30", []string{"tuesday"}, at(28, 23, 30), false},
		{"day not allowed", "09:00", "17:00", []string{"tuesday"}, at(28, 12, 0), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tr := SpecifyTimeRange{IsChecked: true, StartTime: test.start, EndTime: test.end, Timezone: "Asia/Kolkata", DaysOfWeek: test.days}
			err := checkTimeRange(tr, test.now)
			if test.allowed && err != nil {
				t.Errorf("expected allowed, got %v", err)
			}
			if !test.allowed && err == nil {
				t.Errorf("expected not allowed, got nil")
			}
		})
	}
}
