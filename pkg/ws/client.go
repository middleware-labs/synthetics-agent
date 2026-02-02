package ws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"log/slog"

	"github.com/cenkalti/backoff"
	"github.com/gorilla/websocket"
)

var (
	pingInterval = 10 * time.Second
	pingTimeout  = 5 * time.Second
	pongTimeout  = 5 * time.Second
)

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

// PublishMsg is the message type for publishing a new message.
type PublishMsg struct {
	Payload             []byte            `json:"payload"`
	Properties          map[string]string `json:"properties"`
	Context             string            `json:"context"`
	Key                 string            `json:"key"`
	ReplicationClusters []string          `json:"replicationClusters"`
}

// PublishError is the error type used if the server responds with an error.
type PublishError struct {
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	Context string `json:"context"`
}

// Error implements the error interface.
func (e *PublishError) Error() string {
	return e.Msg
}

type publishResult struct {
	Result   string `json:"result"`
	MsgId    string `json:"messageId"`
	ErrorMsg string `json:"errorMsg"`
	Context  string `json:"context"`
}

// PublishResult is the result of a successful publish.
type PublishResult struct {
	MsgId   string `json:"messageId"`
	Context string `json:"context"`
}

type Msg struct {
	// MsgId is a base64-encoded value of the serializable MessageId proto.
	MsgId string `json:"messageId"`

	// Payload is the message payload.
	Payload []byte `json:"payload"`

	// PublishTime is the time the message was published.
	PublishTime time.Time `json:"publishTime"`

	// Properties are an arbitrary set of key-value properties.
	Properties map[string]string `json:"properties"`

	// Key is the partition key for this message.
	Key string `json:"key"`
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

func closeConn(w *websocket.Conn) error {
	err := w.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
	)
	if err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

type producer struct {
	topic  string
	params Params
	c      *Client
	w      *websocket.Conn
}

func (p *producer) dial(err error, max int) error {
	url := fmt.Sprintf("%s/producer/%s?%s", p.c.URL, p.topic, encodeParams(p.params))
	w, err := p.c.dial(err, url, max)
	if err != nil {
		return err
	}

	p.w = w
	return nil
}

func (p *producer) Send(ctx context.Context, m *PublishMsg) (*PublishResult, error) {
	t, _ := ctx.Deadline()
	p.w.SetWriteDeadline(t)
	p.w.SetReadDeadline(t)

	for {
		err := p.w.WriteJSON(m)
		// All good.
		if err == nil {
			break
		}

		if err := p.dial(err, -1); err != nil {
			return nil, err
		}
	}

	// Read result.
	var r publishResult
	if err := p.w.ReadJSON(&r); err != nil {
		return nil, err
	}

	if r.Result == "ok" {
		return &PublishResult{
			MsgId:   r.MsgId,
			Context: r.Context,
		}, nil
	}

	return nil, &PublishError{
		Code:    r.Result,
		Msg:     r.ErrorMsg,
		Context: r.Context,
	}
}

func (p *producer) Close() error {
	return closeConn(p.w)
}

type consumer struct {
	topic  string
	name   string
	params Params
	c      *Client
	w      *websocket.Conn
}

func (c *consumer) dial(err error, max int) error {
	url := fmt.Sprintf("%s/consumer/%s/%s?%s", c.c.URL, c.topic, c.name, encodeParams(c.params))
	w, err := c.c.dial(err, url, max)
	if err != nil {
		return err
	}

	c.w = w
	return nil
}

func (c *consumer) Receive(ctx context.Context) (*Msg, error) {
	t, _ := ctx.Deadline()
	c.w.SetReadDeadline(t)

	var m Msg

	for {
		err := c.w.ReadJSON(&m)
		if err == nil {
			break
		}

		if err := c.dial(err, -1); err != nil {
			return nil, err
		}
	}

	return &m, nil
}

func (c *consumer) Ack(ctx context.Context, m *Msg) error {
	t, _ := ctx.Deadline()
	c.w.SetWriteDeadline(t)

	for {
		err := c.w.WriteJSON(&ackMsg{
			MsgId: m.MsgId,
		})
		//log.Printf("ack id:%s", m.MsgId)
		if err == nil {
			break
		}

		if err := c.dial(err, -1); err != nil {
			return err
		}
	}

	return nil
}

func (c *consumer) Nack(ctx context.Context, m *Msg) error {
	t, _ := ctx.Deadline()
	c.w.SetWriteDeadline(t)

	for {
		err := c.w.WriteJSON(&nackMsg{
			Type:  "negativeAcknowledge",
			MsgId: m.MsgId,
		})
		//log.Printf("nack id:%s", m.MsgId)
		if err == nil {
			break
		}

		if err := c.dial(err, -1); err != nil {
			return err
		}
	}

	return nil
}

func (c *consumer) Close() error {
	return closeConn(c.w)
}

type reader struct {
	topic  string
	params Params
	c      *Client
	w      *websocket.Conn
	// In case a disconnect happens, this will be provided as the last message id
	// to resume where the reader left off.
	lastId string
}

func (r *reader) dial(err error, max int) error {
	p := r.params
	// Use the last ack'ed id as the starting point.
	if r.lastId != "" {
		p["messageId"] = r.lastId
	}

	url := fmt.Sprintf("%s/reader/%s?%s", r.c.URL, r.topic, encodeParams(p))
	w, err := r.c.dial(err, url, max)
	if err != nil {
		return err
	}

	r.w = w
	return nil
}

func (r *reader) Receive(ctx context.Context) (*Msg, error) {
	t, _ := ctx.Deadline()
	r.w.SetReadDeadline(t)

	var m Msg

	for {
		err := r.w.ReadJSON(&m)
		if err == nil {
			break
		}

		if err := r.dial(err, -1); err != nil {
			return nil, err
		}
	}

	return &m, nil
}

func (r *reader) Ack(ctx context.Context, m *Msg) error {
	t, _ := ctx.Deadline()
	r.w.SetWriteDeadline(t)

	for {
		err := r.w.WriteJSON(&ackMsg{
			MsgId: m.MsgId,
		})
		if err == nil {
			break
		}

		if err := r.dial(err, -1); err != nil {
			return err
		}
	}

	// Track the last message id across reconnects.
	r.lastId = m.MsgId

	return nil
}

func (r *reader) Close() error {
	return closeConn(r.w)
}

// Client is a client for Apache Pulsar Websocket API.
// Use New to initialize the client with the default configuration.
type Client struct {
	URL    string
	dialer *websocket.Dialer
}

func (c *Client) isRetryableError(err error) bool {
	slog.Debug("isRetryableError", slog.String("error",
		fmt.Sprintf("%#T %#v", err, err)))
	
	// Websocket-specific close errors that should trigger retry
	if websocket.IsCloseError(err,
		websocket.CloseGoingAway,           // 1001
		websocket.CloseAbnormalClosure,     // 1006
		websocket.CloseNoStatusReceived,    // 1005
		websocket.ClosePolicyViolation,     // 1008
		websocket.CloseInternalServerErr,   // 1011
		websocket.CloseTLSHandshake,        // 1015
	) {
		return true
	}

	// Network error.
	if _, ok := err.(*net.OpError); ok {
		return true
	}

	return false
}

// dial attempts to create a new websocket connection. If an error is passed
// it is checked for whether it was a connection error so it can reconnect.
func (c *Client) dial(err error, url string, max int) (*websocket.Conn, error) {
	// Check if a reconnect is worth doing.. otherwise return the error.
	if err != nil {
		if !c.isRetryableError(err) {
			slog.Error("non-retryable error encountered", slog.String("error", err.Error()))
			return nil, err
		}
		slog.Info("reconnecting due to retryable error", slog.String("error", err.Error()))
	}

	var w *websocket.Conn

	b := backoff.NewExponentialBackOff()
	// No longer than a minute interval.
	b.MaxInterval = time.Minute
	// Retry forever.
	b.MaxElapsedTime = 0

	var o backoff.BackOff = b
	if max == 0 {
		o = &backoff.StopBackOff{}
	} else if max > 0 {
		o = backoff.WithMaxRetries(o, uint64(max))
	}

	err = backoff.Retry(func() error {
		w, _, err = c.dialer.Dial(url, nil)
		if err != nil {
			slog.Error("dial attempt failed", slog.String("error", err.Error()))
		}
		return err
	}, o)
	if err != nil {
		return nil, err
	}

	// Setup a ping/pong routine to know when the connection has died.
	/*
		go func() {
			lastResponse := time.Now()
			w.SetPongHandler(func(_ string) error {
				now := time.Now()
				c.Logger.Debug().Dur("delay", now.Sub(lastResponse)).Msg("pong")
				lastResponse = now
				return nil
			})

			ticker := time.NewTicker(pingInterval)
			for {
				select {
				case <-ticker.C:
					c.Logger.Debug().Msg("ping")
					err := w.WriteControl(websocket.PingMessage, nil, time.Now().Add(pingTimeout))
					if err != nil {
						c.Logger.Error().Err(err).Msg("ping")
					}

					// Sleep for partial time to be optimistic.
					time.Sleep(pongTimeout / 2)

					if time.Now().Sub(lastResponse) > pongTimeout {
						c.Logger.Error().Msg("pong timeout")
						w.Close()
						return
					}
				}
			}
		}()
	*/

	slog.Info("websocket connected successfully")
	return w, nil
}

// Producer initializes a new producer.
func (c *Client) Producer(topic string, params Params) (Producer, error) {
	p := &producer{
		topic:  topic,
		params: params,
		c:      c,
	}

	if err := p.dial(nil, 0); err != nil {
		return nil, err
	}

	return p, nil
}

// Consumer initializes a new consumer.
func (c *Client) Consumer(topic string, name string, params Params) (Consumer, error) {
	x := &consumer{
		topic:  topic,
		name:   name,
		params: params,
		c:      c,
	}

	if err := x.dial(nil, 0); err != nil {
		return nil, err
	}

	return x, nil
}

// Reader initializes a new reader.
func (c *Client) Reader(topic string, params Params) (Reader, error) {
	r := &reader{
		topic:  topic,
		params: params,
		c:      c,
	}

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
