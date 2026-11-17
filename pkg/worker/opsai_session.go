package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// opsaiSessionStartAction asks this location to start an OpsAI Testing
// browser session. bifrost publishes it on location-<region> with the
// session args under result.session; the agent hands them to browser-hub.
const opsaiSessionStartAction = "opsai-session-start"

var opsaiHubClient = &http.Client{Timeout: 60 * time.Second}

// startOpsAISession forwards a session start to browser-hub's /start.
func startOpsAISession(ctx context.Context, hubURL string, result map[string]interface{}) error {
	session, ok := result["session"].(map[string]interface{})
	if !ok {
		return errors.New("opsai-session-start carries no session")
	}
	if hubURL == "" {
		return errors.New("BROWSER_HUB_URL environment variable not set")
	}
	session["mode"] = "session"
	body, err := json.Marshal(map[string]interface{}{"args": session})
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(hubURL, "/")+"/start", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := opsaiHubClient.Do(req)
	if err != nil {
		return fmt.Errorf("browser-hub request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("browser-hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
