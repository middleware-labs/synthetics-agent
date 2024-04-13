package worker

import (
	"testing"
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
			errString: "unknown time zone galaxy/mars",
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
			err := cs.fire()
			if err != nil {
				if test.errString != err.Error() {
					t.Errorf("expected error %s, got %s", test.errString, err.Error())
				}
			}
			if err == nil && test.errString != "" {
				t.Errorf("expected error %s, got nil", test.errString)
			}
		})
	}
}
