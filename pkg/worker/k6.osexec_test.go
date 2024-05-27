package worker

import (
	"testing"
)

var inputJSON string = "{" +
	"\\\"steps\\\": \\\"step1\\\\\\\"E\\\"," +
	"\\\"multiStepPreview\\\": true }"

var expectedJSON = `{"steps": "step1\"E","multiStepPreview": true }`

func TestFindValueToPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		pattern  string
		expected string
		errMsg   string
	}{
		{
			name:     "valid pattern",
			input:    `###START->Hello<-END###`,
			pattern:  `###START->([^=]+)<-END###`,
			expected: "Hello",
		},
		{
			name:     "valid pattern with escape characters",
			input:    "###START->" + inputJSON + "<-END###",
			pattern:  `###START->([^=]+)<-END###`,
			expected: expectedJSON,
		},
		{
			name:     "invalid pattern",
			input:    `###START->Hello<-END###`,
			pattern:  `###OTHER_START->([^=]+)<-OTHER_START###`,
			expected: "",
		},
		{
			name:     "invalid pattern with escape characters",
			input:    "###START->" + inputJSON + "<-END###",
			pattern:  `###OTHER_START->([^=]+)<-OTHER_START###`,
			expected: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			result, err := findValueToPattern(tt.input, tt.pattern)

			if err != nil {
				if err.Error() != tt.errMsg {
					t.Errorf("%s: Expected error message %s, but got %s", tt.name, tt.errMsg, err.Error())
				}

				return
			}

			if result != tt.expected {
				t.Errorf("%s: Expected %s, but got %s", tt.name, tt.expected, result)
			}
		})
	}
}
