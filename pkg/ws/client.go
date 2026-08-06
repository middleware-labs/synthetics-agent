package ws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"

	"github.com/cenkalti/backoff"
	"github.com/gorilla/websocket"
)

// Tuned for Cloudflare's 100s idle timeout. We send a heartbeat every
// 25s as a small JSON frame. CF sees a data frame and resets its idle
// timer. We also send protocol-level pings as a belt-and-braces measure.
// If we don't see ANY frame from the peer for livenessTimeout, the
// connection is dead.
var (
	heartbeatInterval = 25 * time.Second
	pingInterval      = 30 * time.Second
	pingTimeout       = 10 * time.Second
	livenessTimeout   = 90 * time.Second // < 100s CF cutoff
)

// heartbeat is a small data-frame heartbeat. Both ends recognize it.
// Sent as a normal JSON message so it counts as traffic at every proxy
// layer (some proxies don't count WebSocket control pings as activity).
type heartbeat struct {
	Type string `json:"_hb"` // "ping" or "pong"
	TS   int64  `json:"ts"`
}

type Params map[string]string

func encodeParams(p Params) string {
	if len(p) == 0 {
		return ""
	}
	v := url.Values{}
	for k, x := range p {
		v.Add(k, x)
	}
	return v.Encode()
}

type PublishMsg struct {
	Payload             []byte            `json:"payload"`
	Properties          map[string]string `json:"properties"`
	Context             string            `json:"context"`
	Key                 string            `json:"key"`
	ReplicationClusters []string          `json:"replicationClusters"`
}

type PublishError struct {
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	Context string `json:"context"`
}

func (e *PublishError) Error() string { return e.Msg }

type publishResult struct {
	Result   string `json:"result"`
	MsgId    string `json:"messageId"`
	ErrorMsg string `json:"errorMsg"`
	Context  string `json:"context"`
}

type PublishResult struct {
	MsgId   string `json:"messageId"`
	Context string `json:"context"`
}

type Msg struct {
	MsgId       string            `json:"messageId"`
	Payload     []byte            `json:"payload"`
	PublishTime time.Time         `json:"publishTime"`
	Properties  map[string]string `json:"properties"`
	Key         string            `json:"key"`
}

type ackMsg struct {
	MsgId string `json:"messageId"`
}
type nackMsg struct {
	Type  string `json:"type"`
	MsgId string `json:"messageId"`
}

type Producer interface {
	Send(context.Context, *PublishMsg) (*PublishResult, error)
	Close() error
}

type Consumer interface {
	Receive(context.Context) (*Msg, error)
	Ack(context.Context, *Msg) error
	Nack(context.Context, *Msg) error
	Close() error
}

type Reader interface {
	Receive(context.Context) (*Msg, error)
	Ack(context.Context, *Msg) error
	Close() error
}

// session wraps a websocket connection with:
//   - one read pump that drains every frame and routes heartbeats vs data
//   - a heartbeat sender (data-frame keepalive, survives picky proxies)
//   - a protocol ping sender (secondary keepalive)
//   - liveness based on "any frame from peer in last N seconds"
//   - a write mutex (heartbeats and user writes don't race)
type session struct {
	w       *websocket.Conn
	writeMu sync.Mutex

	dataCh chan json.RawMessage

	done     chan struct{}
	doneOnce sync.Once

	errMu sync.Mutex
	err   error

	lastActivityNs int64 // atomic
}

func newSession(w *websocket.Conn) *session {
	s := &session{
		w:      w,
		dataCh: make(chan json.RawMessage, 64),
		done:   make(chan struct{}),
	}
	s.touch()
	w.SetPongHandler(func(_ string) error {
		s.touch()
		return nil
	})
	go s.readPump()
	go s.heartbeatPump()
	go s.pingPump()
	go s.livenessWatcher()
	return s
}

func (s *session) touch() {
	atomic.StoreInt64(&s.lastActivityNs, time.Now().UnixNano())
}

func (s *session) lastActivity() time.Time {
	return time.Unix(0, atomic.LoadInt64(&s.lastActivityNs))
}

func (s *session) kill(err error) {
	s.doneOnce.Do(func() {
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		s.w.Close()
		close(s.done)
	})
}

func (s *session) lastErr() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

// readPump is the ONLY goroutine that reads from s.w. It dispatches
// heartbeats internally and forwards user-data frames to dataCh.
func (s *session) readPump() {
	defer s.kill(nil)
	for {
		var raw json.RawMessage
		if err := s.w.ReadJSON(&raw); err != nil {
			s.kill(err)
			return
		}
		s.touch()

		// Sniff for heartbeat.
		var hb heartbeat
		if json.Unmarshal(raw, &hb) == nil && hb.Type != "" {
			if hb.Type == "ping" {
				_ = s.writeJSON(heartbeat{Type: "pong", TS: hb.TS})
			}
			continue
		}

		select {
		case s.dataCh <- raw:
		case <-s.done:
			return
		}
	}
}

func (s *session) heartbeatPump() {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			err := s.writeJSON(heartbeat{Type: "ping", TS: time.Now().UnixNano()})
			if err != nil {
				slog.Error("heartbeat write failed", slog.String("error", err.Error()))
				s.kill(err)
				return
			}
		}
	}
}

func (s *session) pingPump() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.writeMu.Lock()
			err := s.w.WriteControl(
				websocket.PingMessage, nil,
				time.Now().Add(pingTimeout),
			)
			s.writeMu.Unlock()
			if err != nil {
				slog.Error("protocol ping failed", slog.String("error", err.Error()))
				s.kill(err)
				return
			}
		}
	}
}

func (s *session) livenessWatcher() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			since := time.Since(s.lastActivity())
			if since > livenessTimeout {
				slog.Error("liveness timeout, killing session",
					slog.Duration("since_last_frame", since))
				s.kill(fmt.Errorf("liveness timeout: no frames for %s", since))
				return
			}
		}
	}
}

func (s *session) writeJSON(v interface{}) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.w.WriteJSON(v)
}

func (s *session) readData(ctx context.Context, out interface{}) error {
	select {
	case raw, ok := <-s.dataCh:
		if !ok {
			return s.lastErr()
		}
		return json.Unmarshal(raw, out)
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		if e := s.lastErr(); e != nil {
			return e
		}
		return fmt.Errorf("session closed")
	}
}

func (s *session) close() error {
	s.doneOnce.Do(func() {
		s.writeMu.Lock()
		_ = s.w.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		)
		s.writeMu.Unlock()
		s.w.Close()
		close(s.done)
	})
	return nil
}

// ---- Producer / Consumer / Reader ----

type producer struct {
	topic  string
	params Params
	c      *Client
	s      *session
}

func (p *producer) dial(prev error, max int) error {
	if p.s != nil {
		p.s.close()
	}
	u := fmt.Sprintf("%s/producer/%s?%s", p.c.URL, p.topic, encodeParams(p.params))
	w, err := p.c.dial(prev, u, max)
	if err != nil {
		return err
	}
	p.s = newSession(w)
	return nil
}

func (p *producer) Send(ctx context.Context, m *PublishMsg) (*PublishResult, error) {
	for {
		if err := p.s.writeJSON(m); err != nil {
			if rerr := p.dial(err, -1); rerr != nil {
				return nil, rerr
			}
			continue
		}
		var r publishResult
		if err := p.s.readData(ctx, &r); err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			if rerr := p.dial(err, -1); rerr != nil {
				return nil, rerr
			}
			continue
		}
		if r.Result == "ok" {
			return &PublishResult{MsgId: r.MsgId, Context: r.Context}, nil
		}
		return nil, &PublishError{Code: r.Result, Msg: r.ErrorMsg, Context: r.Context}
	}
}

func (p *producer) Close() error { return p.s.close() }

type consumer struct {
	topic  string
	name   string
	params Params
	c      *Client
	s      *session
}

func (c *consumer) dial(prev error, max int) error {
	if c.s != nil {
		c.s.close()
	}
	u := fmt.Sprintf("%s/consumer/%s/%s?%s", c.c.URL, c.topic, c.name, encodeParams(c.params))
	w, err := c.c.dial(prev, u, max)
	if err != nil {
		return err
	}
	c.s = newSession(w)
	return nil
}

func (c *consumer) Receive(ctx context.Context) (*Msg, error) {
	for {
		var m Msg
		if err := c.s.readData(ctx, &m); err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			if rerr := c.dial(err, -1); rerr != nil {
				return nil, rerr
			}
			continue
		}
		return &m, nil
	}
}

func (c *consumer) Ack(ctx context.Context, m *Msg) error {
	for {
		if err := c.s.writeJSON(&ackMsg{MsgId: m.MsgId}); err != nil {
			if rerr := c.dial(err, -1); rerr != nil {
				return rerr
			}
			continue
		}
		return nil
	}
}

func (c *consumer) Nack(ctx context.Context, m *Msg) error {
	for {
		if err := c.s.writeJSON(&nackMsg{Type: "negativeAcknowledge", MsgId: m.MsgId}); err != nil {
			if rerr := c.dial(err, -1); rerr != nil {
				return rerr
			}
			continue
		}
		return nil
	}
}

func (c *consumer) Close() error { return c.s.close() }

type reader struct {
	topic  string
	params Params
	c      *Client
	s      *session
	lastId string
}

func (r *reader) dial(prev error, max int) error {
	if r.s != nil {
		r.s.close()
	}
	p := r.params
	if r.lastId != "" {
		p["messageId"] = r.lastId
	}
	u := fmt.Sprintf("%s/reader/%s?%s", r.c.URL, r.topic, encodeParams(p))
	w, err := r.c.dial(prev, u, max)
	if err != nil {
		return err
	}
	r.s = newSession(w)
	return nil
}

func (r *reader) Receive(ctx context.Context) (*Msg, error) {
	for {
		var m Msg
		if err := r.s.readData(ctx, &m); err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			if rerr := r.dial(err, -1); rerr != nil {
				return nil, rerr
			}
			continue
		}
		return &m, nil
	}
}

func (r *reader) Ack(ctx context.Context, m *Msg) error {
	for {
		if err := r.s.writeJSON(&ackMsg{MsgId: m.MsgId}); err != nil {
			if rerr := r.dial(err, -1); rerr != nil {
				return rerr
			}
			continue
		}
		r.lastId = m.MsgId
		return nil
	}
}

func (r *reader) Close() error { return r.s.close() }

// ---- Client ----

type Client struct {
	URL    string
	dialer *websocket.Dialer
}

func (c *Client) isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if websocket.IsCloseError(err,
		websocket.CloseGoingAway,         // 1001
		websocket.CloseAbnormalClosure,   // 1006
		websocket.CloseNoStatusReceived,  // 1005
		websocket.ClosePolicyViolation,   // 1009
		websocket.CloseInternalServerErr, // 1011
		websocket.CloseTLSHandshake,      // 1015
	) {
		return true
	}
	if _, ok := err.(*net.OpError); ok {
		return true
	}
	return true // broken pipe, reset, liveness timeout, etc.
}

func (c *Client) dial(prev error, u string, max int) (*websocket.Conn, error) {
	if prev != nil {
		if !c.isRetryableError(prev) {
			slog.Error("non-retryable error", slog.String("error", prev.Error()))
			return nil, prev
		}
		slog.Info("reconnecting", slog.String("reason", prev.Error()))
	}

	var w *websocket.Conn

	b := backoff.NewExponentialBackOff()
	b.MaxInterval = time.Minute
	b.MaxElapsedTime = 0

	var o backoff.BackOff = b
	if max == 0 {
		o = &backoff.StopBackOff{}
	} else if max > 0 {
		o = backoff.WithMaxRetries(o, uint64(max))
	}

	err := backoff.Retry(func() error {
		var derr error
		w, _, derr = c.dialer.Dial(u, nil)
		if derr != nil {
			slog.Error("dial failed", slog.String("error", derr.Error()))
		}
		return derr
	}, o)
	if err != nil {
		return nil, err
	}

	slog.Info("websocket connected")
	return w, nil
}

func (c *Client) Producer(topic string, params Params) (Producer, error) {
	p := &producer{topic: topic, params: params, c: c}
	if err := p.dial(nil, 0); err != nil {
		return nil, err
	}
	return p, nil
}

func (c *Client) Consumer(topic string, name string, params Params) (Consumer, error) {
	x := &consumer{topic: topic, name: name, params: params, c: c}
	if err := x.dial(nil, 0); err != nil {
		return nil, err
	}
	return x, nil
}

// Reader initializes a new reader.
func (c *Client) Reader(topic string, params Params) (Reader, error) {
	r := &reader{topic: topic, params: params, c: c}
	if err := r.dial(nil, 0); err != nil {
		return nil, err
	}
	return r, nil
}

// New initializes a new client.
func New(url string) *Client {
	return &Client{
		URL: url,
		dialer: &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}
