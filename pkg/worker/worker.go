package worker

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/middleware-labs/synthetics-agent/pkg/ws"
)

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
	consumer     ws.Consumer
	messages     map[string]*ws.Msg
	messagesLock sync.Mutex
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
		messages:     make(map[string]*ws.Msg),
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
		err = json.Unmarshal(msg.Payload, &v)
		if err != nil {
			slog.Error("failed to decode json", slog.String("error", err.Error()))
		}

		err = consumer.Ack(context.Background(), msg)
		if err != nil {
			slog.Error("failed to ack message", slog.String("error", err.Error()))
		}

		if v.Not != w.cfg.Hostname {
			omsg, ok := w.GetMessage(msg.Key)
			if ok {
				slog.Info("unsubscribed", slog.String("key", msg.Key))
				w.DeleteMessage(msg.Key)
				w.consumer.Ack(context.Background(), omsg)
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
func (w *Worker) GetMessage(key string) (*ws.Msg, bool) {
	w.messagesLock.Lock()
	defer w.messagesLock.Unlock()
	msg, ok := w.messages[key]
	return msg, ok
}
func (w *Worker) DeleteMessage(key string) {
	w.messagesLock.Lock()
	defer w.messagesLock.Unlock()
	delete(w.messages, key)
}
func (w *Worker) SetMessage(key string, msg *ws.Msg) {
	w.messagesLock.Lock()
	defer w.messagesLock.Unlock()
	w.messages[key] = msg
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

	var err error
	w.consumer, err = w.pulsarClient.Consumer("persistent/public/default/"+topic,
		"subscribe", ws.Params{
			"subscriptionType":           "Shared",
			"ackTimeoutMillis":           strconv.Itoa(60 * 60 * 1000),
			"consumerName":               consumerName,
			"negativeAckRedeliveryDelay": "0",
			"pullMode":                   "false",
			"receiverQueueSize":          "500000",
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
		msg, err := w.consumer.Receive(ctx)
		if err != nil {
			w.consumer.Close()

			timer := time.NewTimer(time.Second * 5)
			<-timer.C
			w.SubscribeUpdates(topic, token)
			return
		} else if msg.Payload == nil || len(msg.Payload) == 0 {
			slog.Info("null message received", slog.String("msgId", msg.MsgId))
			w.consumer.Ack(context.Background(), msg)
			continue
		}

		v := SyntheticCheck{}

		err = json.Unmarshal(msg.Payload, &v)
		if err != nil {
			slog.Error("failed to decode json", slog.String("error", err.Error()))
			w.consumer.Ack(context.Background(), msg)
			continue
		}
		if v.IsPreviewRequest {
			result, err := w.DirectRun(v)
			if err != nil {
				slog.Error("failed to run preview test", slog.String("accountUID", v.AccountUID), slog.Int("Id", v.Id), slog.String("error", err.Error()))
				slog.Info("empty result will be sent")
			}
			v.Action = "delete"
			w.produceMessage(v.AccountUID, topic+"-unsubscribe", msg.Key, unsubscribePayload{
				Not:        w.cfg.Hostname,
				Action:     "unsub",
				Id:         v.Id,
				AccountUID: v.AccountUID,
			})
			err = w.consumer.Ack(context.Background(), msg)
			if err != nil {
				slog.Error("failed to ack the msg", slog.String("error", err.Error()))
				continue
			}
			slog.Info("result got", slog.Any("result", result))
			err = w.sendPreview(v.Id, "preview", result)
			if err != nil {
				slog.Error("failed to send preview", slog.String("error", err.Error()))
			} else {
				slog.Info("test preview result sent to pulsar", slog.Int("check.Id", v.Id), slog.String("AccountUID", v.AccountUID))
			}
			continue
		}

		if v.Action == "create" {
			v.Action = "update"
		}

		if v.Action != "update" && v.Action != "delete" {
			slog.Info("invalid action message", slog.String("payload", string(msg.Payload)))
			err := w.consumer.Ack(context.Background(), msg)
			if err != nil {
				slog.Error("failed to ack message", slog.String("error", err.Error()))
			}
			continue
		}
		oldMsg, ok := w.GetMessage(msg.Key)

		if ok && oldMsg.MsgId == msg.MsgId {
			slog.Info(fmt.Sprintf("[%d] job refresh key:%s ", v.Id, msg.Key))
		} else if ok && oldMsg.MsgId != msg.MsgId {
			slog.Info("job update", slog.String("key", msg.Key))
			err := w.consumer.Ack(context.Background(), oldMsg)
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
			w.SetMessage(msg.Key, msg)
			if v.IsPreviewRequest {
				err := w.consumer.Ack(context.Background(), msg)
				if err != nil {
					slog.Error("ack msg failed", slog.String("error", err.Error()))
				}
			}

			//if !refresh {
			if !v.IsPreviewRequest {
				w.produceMessage(v.AccountUID, topic+"-unsubscribe", msg.Key, unsubscribePayload{
					Not:        w.cfg.Hostname,
					Action:     "unsub",
					Id:         v.Id,
					AccountUID: v.AccountUID,
				})
			}
			checkState := w.getCheckState(v)
			checkState.update()
			//}
			continue
		}

		// handle delete
		w.DeleteMessage(msg.Key)

		w.produceMessage(v.AccountUID, topic+"-unsubscribe", msg.Key, unsubscribePayload{
			Not:        w.cfg.Hostname,
			Action:     "unsub",
			Id:         v.Id,
			AccountUID: v.AccountUID,
		})

		err = w.consumer.Ack(context.Background(), msg)
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

func (w *Worker) sendPreview(id int, topic string, payload map[string]interface{}) error {
	pay := struct {
		PreviewId int                    `json:"preview_id"`
		Topic     string                 `json:"topic"`
		Result    map[string]interface{} `json:"result"`
	}{
		PreviewId: id,
		Topic:     topic,
		Result:    payload,
	}

	payloadStr, err := json.Marshal(pay)
	if err != nil {
		slog.Error("failed to marshal payload", slog.String("error", err.Error()))
		return err
	}
	return SendMsgToPulsar(topic, pay.PreviewId, string(payloadStr), true)
}

func SendMsgToPulsar(topic string, key int, payload string, autoCreateTopic bool) error {
	pulsarHost := os.Getenv("PULSAR_HOST_SYNTHETICS")
	if pulsarHost == "" {
		return fmt.Errorf("PULSAR_HOST_SYNTHETICS environment variable not set")
	}

	pl, _ := json.Marshal(payload)
	str := `{
        "producerName": "preview-producer",
        "messages": [
            {
                "key":` + fmt.Sprintf("%v", key) + `,
                "payload":` + string(pl) + `,
                "eventTime":` + strconv.FormatInt(time.Now().Unix(), 10) + `,
                "sequenceId":` + strconv.FormatInt(time.Now().UnixMilli(), 10) + `
            }
        ]
    }`

	endpoint := pulsarHost + "/topics/persistent/public/default/" + topic
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(str))
	if err != nil {
		return fmt.Errorf("produce message http failed. topic:%s key:%v payload:%s endpoint:%s  %v", topic, key, payload, endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")

	var client = &http.Client{
		Transport: &http.Transport{},
	}

	re, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("produce resp failed, topic:%s key:%d payload:%s endpoint:%s %v", topic, key, payload, endpoint, err)
	}
	defer func() {
		if re != nil {
			re.Body.Close()
		}
	}()

	if re.StatusCode != 200 {
		str, _ := io.ReadAll(re.Body)
		if autoCreateTopic && re.StatusCode == 500 && strings.Contains(string(str), topic+" not found") {
			// Create the topic if not found
			topicEndpoint := pulsarHost + "/admin/v2/persistent/public/default/" + topic
			req, err := http.NewRequest("PUT", topicEndpoint, nil)
			if err != nil {
				return fmt.Errorf("topic create failed. topic:%s key:%v endpoint:%s  %v", topic, key, topicEndpoint, err)
			}
			req.Header.Set("Content-Type", "application/json")
			re, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("topic create resp failed, topic:%s key:%v endpoint:%s %v", topic, key, topicEndpoint, err)
			}
			if re == nil {
				return fmt.Errorf("nil response when creating topic. topic:%s key:%v endpoint:%s", topic, key, topicEndpoint)
			}
			if re.StatusCode != 200 {
				str, _ := io.ReadAll(re.Body)
				return fmt.Errorf("produce resp invalid status code, topic:%s key:%v payload:%s endpoint:%s status:%s output:%s", topic, key, payload, endpoint, re.Status, string(str))
			} else {
				return SendMsgToPulsar(topic, key, payload, false)
			}
		}
		return fmt.Errorf("produce resp invalid status code, topic:%s key:%v endpoint:%s status:%s output:%s", topic, key, endpoint, re.Status, string(str))
	}
	// log.Printf("pulsar send msg topic:%s key:%s payload:%s endpoint:%s", topic, key, payload, endpoint)
	return nil
}
