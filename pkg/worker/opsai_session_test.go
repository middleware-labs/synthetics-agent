package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStartOpsAISessionForwardsArgsToHub(t *testing.T) {
	var got map[string]map[string]interface{}
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/start" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()

	result := map[string]interface{}{"session": map[string]interface{}{
		"sessionId": "s1", "controlUrl": "https://x", "token": "t",
	}}
	if err := startOpsAISession(context.Background(), hub.URL+"/", result); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got["args"]["sessionId"] != "s1" || got["args"]["mode"] != "session" {
		t.Fatalf("hub got %v", got)
	}
}

func TestStartOpsAISessionErrors(t *testing.T) {
	if err := startOpsAISession(context.Background(), "http://hub", map[string]interface{}{}); err == nil ||
		!strings.Contains(err.Error(), "no session") {
		t.Fatalf("missing session: %v", err)
	}
	withSession := map[string]interface{}{"session": map[string]interface{}{}}
	if err := startOpsAISession(context.Background(), "", withSession); err == nil ||
		!strings.Contains(err.Error(), "BROWSER_HUB_URL") {
		t.Fatalf("missing hub: %v", err)
	}
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no capacity", http.StatusInternalServerError)
	}))
	defer hub.Close()
	if err := startOpsAISession(context.Background(), hub.URL, withSession); err == nil ||
		!strings.Contains(err.Error(), "500: no capacity") {
		t.Fatalf("hub error: %v", err)
	}
}
