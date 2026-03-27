package mq

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

type Params map[string]string

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

// PublishResult is the result of a successful publish.
type PublishResult struct {
	MsgId   string `json:"messageId"`
	Context string `json:"context"`
}

type Msg struct {
	// MsgId is a unique identifier for the message.
	MsgId string `json:"messageId"`

	// Payload is the message payload.
	Payload []byte `json:"payload"`

	// PublishTime is the time the message was published.
	PublishTime time.Time `json:"publishTime"`

	// Properties are an arbitrary set of key-value properties.
	Properties map[string]string `json:"properties"`

	// Key is the partition key for this message.
	Key string `json:"key"`

	// deliveryTag is used internally for acking
	deliveryTag uint64
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

// Client is a client for RabbitMQ.
type Client struct {
	URL        string
	conn       *amqp.Connection
	connCloser chan *amqp.Error
}

// New initializes a new RabbitMQ client.
func New(url string) *Client {
	return &Client{
		URL: url,
	}
}

func (c *Client) connect() error {
	if c.conn != nil && !c.conn.IsClosed() {
		return nil
	}

	conn, err := amqp.Dial(c.URL)
	if err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	c.conn = conn
	c.connCloser = make(chan *amqp.Error)
	c.conn.NotifyClose(c.connCloser)

	slog.Info("RabbitMQ connected successfully")
	return nil
}

func (c *Client) reconnect() error {
	slog.Info("attempting to reconnect to RabbitMQ")

	maxRetries := 10
	backoff := time.Second

	for i := 0; i < maxRetries; i++ {
		if err := c.connect(); err == nil {
			return nil
		}

		slog.Error("reconnect attempt failed",
			slog.Int("attempt", i+1),
			slog.Int("maxRetries", maxRetries))

		time.Sleep(backoff)
		backoff *= 2
		if backoff > time.Minute {
			backoff = time.Minute
		}
	}

	return fmt.Errorf("failed to reconnect after %d attempts", maxRetries)
}

// Producer initializes a new producer.
func (c *Client) Producer(topic string, params Params) (Producer, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	ch, err := c.conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("failed to open channel: %w", err)
	}

	// Declare the exchange (topic becomes exchange name)
	err = ch.ExchangeDeclare(
		topic,   // exchange name
		"topic", // type
		true,    // durable
		false,   // auto-deleted
		false,   // internal
		false,   // no-wait
		nil,     // arguments
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to declare exchange: %w", err)
	}

	p := &producer{
		topic:  topic,
		params: params,
		c:      c,
		ch:     ch,
	}

	return p, nil
}

// Consumer initializes a new consumer with subscription semantics.
func (c *Client) Consumer(topic string, name string, params Params) (Consumer, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	ch, err := c.conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("failed to open channel: %w", err)
	}

	// Declare the exchange
	err = ch.ExchangeDeclare(
		topic,
		"topic",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to declare exchange: %w", err)
	}

	// Create queue name based on subscription type
	queueName := topic + "." + name
	subscriptionType := params["subscriptionType"]

	// For Shared subscriptions, use a common queue name
	// For Exclusive, use consumer-specific queue name
	if subscriptionType == "Shared" {
		queueName = topic + ".shared"
	}

	// Declare the queue
	queue, err := ch.QueueDeclare(
		queueName, // queue name
		true,      // durable
		false,     // auto-delete
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to declare queue: %w", err)
	}

	// Bind the queue to the exchange
	err = ch.QueueBind(
		queue.Name, // queue name
		"#",        // routing key (all messages)
		topic,      // exchange
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to bind queue: %w", err)
	}

	// Set QoS based on params
	prefetchCount := 1
	if params["receiverQueueSize"] != "" {
		// In RabbitMQ, we use prefetch count instead of receiver queue size
		prefetchCount = 100 // reasonable default for high throughput
	}

	err = ch.Qos(prefetchCount, 0, false)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to set QoS: %w", err)
	}

	// Start consuming
	msgs, err := ch.Consume(
		queue.Name, // queue
		name,       // consumer tag
		false,      // auto-ack
		false,      // exclusive
		false,      // no-local
		false,      // no-wait
		nil,        // args
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to register consumer: %w", err)
	}

	cons := &consumer{
		topic:    topic,
		name:     name,
		params:   params,
		c:        c,
		ch:       ch,
		messages: msgs,
	}

	return cons, nil
}

// Reader initializes a new reader (similar to consumer but simpler).
func (c *Client) Reader(topic string, params Params) (Reader, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	ch, err := c.conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("failed to open channel: %w", err)
	}

	// Declare the exchange
	err = ch.ExchangeDeclare(
		topic,
		"topic",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to declare exchange: %w", err)
	}

	// Create exclusive queue for reader
	queueName := topic + ".reader"
	queue, err := ch.QueueDeclare(
		queueName,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to declare queue: %w", err)
	}

	// Bind to exchange
	err = ch.QueueBind(
		queue.Name,
		"#",
		topic,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to bind queue: %w", err)
	}

	err = ch.Qos(1, 0, false)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to set QoS: %w", err)
	}

	// Start consuming
	msgs, err := ch.Consume(
		queue.Name,
		"reader",
		false,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to register reader: %w", err)
	}

	r := &reader{
		topic:    topic,
		params:   params,
		c:        c,
		ch:       ch,
		messages: msgs,
	}

	return r, nil
}

type producer struct {
	topic  string
	params Params
	c      *Client
	ch     *amqp.Channel
}

func (p *producer) Send(ctx context.Context, m *PublishMsg) (*PublishResult, error) {
	if p.ch.IsClosed() {
		if err := p.reconnect(); err != nil {
			return nil, err
		}
	}

	// Generate message ID
	msgId := fmt.Sprintf("%d", time.Now().UnixNano())

	// Create AMQP headers from properties
	headers := amqp.Table{}
	for k, v := range m.Properties {
		headers[k] = v
	}
	if m.Context != "" {
		headers["context"] = m.Context
	}

	// Determine routing key (use Key if provided, otherwise use default)
	routingKey := m.Key
	if routingKey == "" {
		routingKey = "default"
	}

	msg := amqp.Publishing{
		DeliveryMode: amqp.Persistent,
		Timestamp:    time.Now(),
		ContentType:  "application/json",
		MessageId:    msgId,
		Body:         m.Payload,
		Headers:      headers,
	}

	err := p.ch.PublishWithContext(
		ctx,
		p.topic,    // exchange
		routingKey, // routing key
		false,      // mandatory
		false,      // immediate
		msg,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to publish message: %w", err)
	}

	return &PublishResult{
		MsgId:   msgId,
		Context: m.Context,
	}, nil
}

func (p *producer) reconnect() error {
	slog.Info("reconnecting producer channel")

	if err := p.c.reconnect(); err != nil {
		return err
	}

	ch, err := p.c.conn.Channel()
	if err != nil {
		return fmt.Errorf("failed to reopen channel: %w", err)
	}

	err = ch.ExchangeDeclare(
		p.topic,
		"topic",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to redeclare exchange: %w", err)
	}

	p.ch = ch
	return nil
}

func (p *producer) Close() error {
	if p.ch != nil {
		return p.ch.Close()
	}
	return nil
}

type consumer struct {
	topic    string
	name     string
	params   Params
	c        *Client
	ch       *amqp.Channel
	messages <-chan amqp.Delivery
}

func (c *consumer) Receive(ctx context.Context) (*Msg, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case delivery, ok := <-c.messages:
		if !ok {
			// Channel closed, attempt reconnect
			if err := c.reconnect(); err != nil {
				return nil, fmt.Errorf("consumer channel closed and reconnect failed: %w", err)
			}
			// Try to receive from new channel
			return c.Receive(ctx)
		}

		// Convert AMQP delivery to our Msg format
		properties := make(map[string]string)
		for k, v := range delivery.Headers {
			if str, ok := v.(string); ok {
				properties[k] = str
			}
		}

		msg := &Msg{
			MsgId:       delivery.MessageId,
			Payload:     delivery.Body,
			PublishTime: delivery.Timestamp,
			Properties:  properties,
			Key:         delivery.RoutingKey,
			deliveryTag: delivery.DeliveryTag,
		}

		return msg, nil
	}
}

func (c *consumer) Ack(ctx context.Context, m *Msg) error {
	return c.ch.Ack(m.deliveryTag, false)
}

func (c *consumer) Nack(ctx context.Context, m *Msg) error {
	return c.ch.Nack(m.deliveryTag, false, true)
}

func (c *consumer) reconnect() error {
	slog.Info("reconnecting consumer channel")

	if err := c.c.reconnect(); err != nil {
		return err
	}

	ch, err := c.c.conn.Channel()
	if err != nil {
		return fmt.Errorf("failed to reopen channel: %w", err)
	}

	// Redeclare exchange
	err = ch.ExchangeDeclare(
		c.topic,
		"topic",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to redeclare exchange: %w", err)
	}

	// Redeclare and rebind queue
	queueName := c.topic + "." + c.name
	if c.params["subscriptionType"] == "Shared" {
		queueName = c.topic + ".shared"
	}

	queue, err := ch.QueueDeclare(
		queueName,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to redeclare queue: %w", err)
	}

	err = ch.QueueBind(
		queue.Name,
		"#",
		c.topic,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to rebind queue: %w", err)
	}

	// Set QoS
	prefetchCount := 1
	if c.params["receiverQueueSize"] != "" {
		prefetchCount = 100
	}
	err = ch.Qos(prefetchCount, 0, false)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to set QoS: %w", err)
	}

	// Restart consuming
	msgs, err := ch.Consume(
		queue.Name,
		c.name,
		false,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to re-register consumer: %w", err)
	}

	c.ch = ch
	c.messages = msgs
	return nil
}

func (c *consumer) Close() error {
	if c.ch != nil {
		return c.ch.Close()
	}
	return nil
}

type reader struct {
	topic    string
	params   Params
	c        *Client
	ch       *amqp.Channel
	messages <-chan amqp.Delivery
	lastId   string
}

func (r *reader) Receive(ctx context.Context) (*Msg, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case delivery, ok := <-r.messages:
		if !ok {
			if err := r.reconnect(); err != nil {
				return nil, fmt.Errorf("reader channel closed and reconnect failed: %w", err)
			}
			return r.Receive(ctx)
		}

		properties := make(map[string]string)
		for k, v := range delivery.Headers {
			if str, ok := v.(string); ok {
				properties[k] = str
			}
		}

		msg := &Msg{
			MsgId:       delivery.MessageId,
			Payload:     delivery.Body,
			PublishTime: delivery.Timestamp,
			Properties:  properties,
			Key:         delivery.RoutingKey,
			deliveryTag: delivery.DeliveryTag,
		}

		return msg, nil
	}
}

func (r *reader) Ack(ctx context.Context, m *Msg) error {
	err := r.ch.Ack(m.deliveryTag, false)
	if err == nil {
		r.lastId = m.MsgId
	}
	return err
}

func (r *reader) reconnect() error {
	slog.Info("reconnecting reader channel")

	if err := r.c.reconnect(); err != nil {
		return err
	}

	ch, err := r.c.conn.Channel()
	if err != nil {
		return fmt.Errorf("failed to reopen channel: %w", err)
	}

	err = ch.ExchangeDeclare(
		r.topic,
		"topic",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to redeclare exchange: %w", err)
	}

	queueName := r.topic + ".reader"
	queue, err := ch.QueueDeclare(
		queueName,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to redeclare queue: %w", err)
	}

	err = ch.QueueBind(
		queue.Name,
		"#",
		r.topic,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to rebind queue: %w", err)
	}

	err = ch.Qos(1, 0, false)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to set QoS: %w", err)
	}

	msgs, err := ch.Consume(
		queue.Name,
		"reader",
		false,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		return fmt.Errorf("failed to re-register reader: %w", err)
	}

	r.ch = ch
	r.messages = msgs
	return nil
}

func (r *reader) Close() error {
	if r.ch != nil {
		return r.ch.Close()
	}
	return nil
}
