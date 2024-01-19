package worker

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/middleware-labs/synthetics-agent/pkg/ws"
)

var messages map[string]*ws.Msg = make(map[string]*ws.Msg)

var (
	errInvalidMode = errors.New("invalid mode passed")
)

type Mode uint16

var (
	ModeLocation Mode = 0
	ModeAgent    Mode = 1
)

func (m Mode) String() string {
	switch m {
	case ModeLocation:
		return "location"
	case ModeAgent:
		return "agent"
	}

	return "unknown"
}

type Config struct {
	Mode                Mode
	Location            string
	Hostname            string
	PulsarHost          string
	UnsubscribeEndpoint string
	NCAPassword         string
	Token               string
	CaptureEndpoint     string
}

// Worker is the main worker struct
type Worker struct {
	cfg          *Config
	pulsarClient *ws.Client
	topic        string
	_checks      map[string]*CheckState
}

// New creates a new worker
func New(cfg *Config) (*Worker, error) {
	var topic string
	switch cfg.Mode {
	case ModeLocation:
		topic = fmt.Sprintf("%s-%s", ModeLocation, strings.ToLower(cfg.Location))
	case ModeAgent:
		if cfg.Location == "" {
			topic = fmt.Sprintf("%s-%s", ModeAgent, strings.ToLower(cfg.Token))
		} else {
			topic = fmt.Sprintf("%s-%s-%x", ModeAgent, strings.ToLower(cfg.Token),
				sha1.Sum([]byte(strings.ToLower(cfg.Location))))
		}
	default:
		return &Worker{}, errInvalidMode
	}

	return &Worker{
		cfg:          cfg,
		pulsarClient: ws.New(cfg.PulsarHost),
		topic:        topic,
		_checks:      make(map[string]*CheckState),
	}, nil
}

func (w *Worker) Run() {
	go w.UnsubscribeUpdates(w.topic, w.cfg.Token)
	w.SubscribeUpdates(w.topic, w.cfg.Token)
}

func (w *Worker) UnsubscribeUpdates(topic string, token string) {
	// instanceId := strings.ToLower(os.Getenv("HOSTNAME"))
	consumerName := "unsubscribe-" + w.cfg.Hostname + "-" +
		strconv.FormatInt(time.Now().UTC().Unix(), 10)

	consumer, err := w.pulsarClient.Consumer("persistent/public/default/"+topic+"-unsubscribe", consumerName, ws.Params{
		"subscriptionType": "Exclusive",
		"consumerName":     consumerName,
		"token":            token,
	})

	if err != nil {
		slog.Error("failed to subscribe", slog.String("error", err.Error()))
		timer := time.NewTimer(time.Second * 5)
		<-timer.C
		w.UnsubscribeUpdates(topic, token)
		return
	}

	ctx := context.Background()

	for {
		msg, err := consumer.Receive(ctx)
		if err != nil {
			slog.Error("failed to consume", slog.String("error", err.Error()))
			consumer.Close()

			timer := time.NewTimer(time.Second * 5)
			<-timer.C
			w.UnsubscribeUpdates(topic, token)
			return
		}

		v := unsubscribePayload{}
		log.Printf("unsub payload str %s", string(msg.Payload))
		err = json.Unmarshal(msg.Payload, &v)
		log.Printf("unsub payload %v", v)
		if err != nil {
			slog.Error("failed to decode json", slog.String("error", err.Error()))
			continue
		}

		err = consumer.Ack(context.Background(), msg)
		if err != nil {
			slog.Error("failed to ack message", slog.String("error", err.Error()))
		}

		if v.Not != w.cfg.Hostname {
			_, ok := messages[msg.Key]
			if ok {
				slog.Info("unsubscribed", slog.String("key", msg.Key))
				delete(messages, msg.Key)
			}
			w.removeCheckState(&SyntheticCheck{
				SyntheticsModel: SyntheticsModel{
					AccountUID: v.AccountUID,
					Action:     v.Action,
					Id:         v.Id,
				},
			})
		}

	}
}

func (w *Worker) DirectRun(v SyntheticCheck) (map[string]interface{}, error) {
	checkState := w.getTestState(v)
	return checkState.testFire()
}
func (w *Worker) RealDirectRun(v SyntheticCheck) (map[string]interface{}, error) {
	checkState := w.getCheckState(v)
	return checkState.liveTestFire()
}
func (w *Worker) SubscribeUpdates(topic string, token string) {
	// instanceId := strings.ToLower(os.Getenv("HOSTNAME"))

	consumerName := "subscribe-" + w.cfg.Hostname + "-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)
	url := w.cfg.Hostname + "/consumer/persistent/public/default/" +
		topic + "/" + consumerName + "?token=" + token
	slog.Info("subscribing to topic", slog.String("url", url),
		slog.String("consumer", consumerName), slog.String("token", token))

	consumer, err := w.pulsarClient.Consumer("persistent/public/default/"+topic,
		"subscribe", ws.Params{
			"subscriptionType":           "Key_Shared",
			"ackTimeoutMillis":           "20000",
			"consumerName":               consumerName,
			"negativeAckRedeliveryDelay": "30000",
			"pullMode":                   "false",
			"receiverQueueSize":          "2000",
			"token":                      token,
		})

	if err != nil {
		slog.Error("failed to subscribe",
			slog.String("error", err.Error()))
		timer := time.NewTimer(time.Second * 5)
		<-timer.C
		w.SubscribeUpdates(topic, token)
		return
	}

	ctx := context.Background()

	for {
		msg, err := consumer.Receive(ctx)
		if err != nil {
			consumer.Close()

			timer := time.NewTimer(time.Second * 5)
			<-timer.C
			w.SubscribeUpdates(topic, token)
			return
		} else if msg.Payload == nil || len(msg.Payload) == 0 {
			slog.Info("null message recved", slog.String("msgId", msg.MsgId))
			consumer.Ack(context.Background(), msg)
			continue
		}

		v := SyntheticCheck{}

		err = json.Unmarshal(msg.Payload, &v)
		if err != nil {
			slog.Error("failed to decode json", slog.String("error", err.Error()))
			continue
		}

		if v.Action == "create" {
			v.Action = "update"
		}

		if v.Action != "update" && v.Action != "delete" {
			slog.Info("invalid action message", slog.String("payload", string(msg.Payload)))
			err := consumer.Ack(context.Background(), msg)
			if err != nil {
				slog.Error("failed to ack message", slog.String("error", err.Error()))
			}
			continue
		}

		_, ok := messages[msg.Key]
		refresh := false

		if ok && messages[msg.Key].MsgId == msg.MsgId {
			refresh = true
			log.Printf("[%d] job refresh key:%s ", v.Id, msg.Key)
		} else if ok && messages[msg.Key].MsgId != msg.MsgId {
			slog.Info("job update", slog.String("key", msg.Key))
			err := consumer.Ack(context.Background(), messages[msg.Key])
			if err != nil {
				slog.Error("failed to ack message", slog.String("error", err.Error()))
			}
		} else if !ok {
			if v.Action == "update" {
				slog.Info("job assigned update", slog.Int("id", v.Id),
					slog.String("key", msg.Key))
			} else {
				slog.Info("job assign delete", slog.Int("id", v.Id),
					slog.String("key", msg.Key))
			}
		}

		if v.Action == "update" {
			messages[msg.Key] = msg

			if v.CheckTestRequest.URL != "" {
				// ack  check-type requests.
				err := consumer.Ack(context.Background(), msg)
				if err != nil {
					slog.Error("ack msg failed", slog.String("error", err.Error()))
				}
			} else {
				err := consumer.Nack(context.Background(), msg)
				if err != nil {
					slog.Error("nack msg failed", slog.String("error", err.Error()))
				}
			}

			if !refresh {
				if v.CheckTestRequest.URL == "" {
					// let others subscriber unsuscribe...
					w.produceMessage(v.AccountUID, topic+"-unsubscribe", msg.Key, unsubscribePayload{
						Not:        w.cfg.Hostname,
						Action:     "unsub",
						Id:         v.Id,
						AccountUID: v.AccountUID,
					})
				}
				checkState := w.getCheckState(v)
				checkState.update()
			}
			continue
		}

		// handle delete
		delete(messages, msg.Key)
		err = consumer.Ack(context.Background(), msg)
		if err != nil {
			slog.Error("failed to ack the msg", slog.String("error", err.Error()))
		}
		slog.Info("job removed", slog.String("key", msg.Key))
		w.removeCheckState(&v)

	}
}

type unsubscribePayload struct {
	Not        string
	Action     string
	Id         int
	AccountUID string
}

func (w *Worker) produceMessage(accountUid string,
	topic string, key string, payload unsubscribePayload) {

	type topicKeyPayload struct {
		Topic   string
		Key     string
		Payload unsubscribePayload
	}

	pay := topicKeyPayload{
		Topic:   topic,
		Key:     key,
		Payload: payload,
	}
	str, _ := json.Marshal(pay)

	url := strings.ReplaceAll(w.cfg.UnsubscribeEndpoint, "{ACC}", accountUid)
	req, err := http.NewRequest("POST", url, bytes.NewReader(str))
	if err != nil {
		slog.Error("failed to create request", slog.String("error", err.Error()))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if w.cfg.NCAPassword != "" {
		req.Header.Set("Authorization", w.cfg.NCAPassword)
	}

	re, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error("failed to produce message", slog.String("error", err.Error()))
		return
	}

	if re.StatusCode != 200 {
		str, _ := io.ReadAll(re.Body)
		slog.Error("failed to produce message", slog.String("response status", re.Status),
			slog.String("url", url), slog.String("response", string(str)))
	}
}
