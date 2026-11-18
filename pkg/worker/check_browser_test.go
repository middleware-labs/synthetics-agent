package worker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserCheckerCheckReportsHubResult(t *testing.T) {
	tests := []struct {
		name       string
		hubStatus  int
		hubBody    string
		wantStatus string
		wantMsg    string
	}{
		{"started", http.StatusOK, `{"status":"ok"}`, testStatusOK, ""},
		{"already running", http.StatusOK, `{"status":"Task already running: a_1_chrome_laptop"}`, testStatusOK, ""},
		{"hub failure", http.StatusBadGateway, `{"status":"Failed to start a_1_chrome_laptop: ECS started no task: Capacity is unavailable"}`,
			testStatusError, "browser-hub returned 502: Failed to start a_1_chrome_laptop: ECS started no task: Capacity is unavailable"},
		{"non-JSON failure", http.StatusInternalServerError, "boom\n", testStatusError, "browser-hub returned 500: boom"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/start" {
					t.Errorf("path = %q, want /start", r.URL.Path)
				}
				w.WriteHeader(tc.hubStatus)
				_, _ = w.Write([]byte(tc.hubBody))
			}))
			defer hub.Close()
			t.Setenv("BROWSER_HUB_URL", hub.URL)

			checker := NewBrowserChecker(SyntheticCheck{})
			checker.CmdArgs = CommandArgs{Browser: "chrome", Device: "laptop", TestId: "t1"}
			got := checker.Check()
			if got.status != tc.wantStatus || got.msg != tc.wantMsg {
				t.Fatalf("Check() = {%q, %q}, want {%q, %q}", got.status, got.msg, tc.wantStatus, tc.wantMsg)
			}
		})
	}
}

func TestBrowserCheckerCheckWithoutHubURL(t *testing.T) {
	t.Setenv("BROWSER_HUB_URL", "")
	got := NewBrowserChecker(SyntheticCheck{}).Check()
	if got.status != testStatusError || !strings.Contains(got.msg, "BROWSER_HUB_URL") {
		t.Fatalf("Check() = {%q, %q}, want an error naming BROWSER_HUB_URL", got.status, got.msg)
	}
}
