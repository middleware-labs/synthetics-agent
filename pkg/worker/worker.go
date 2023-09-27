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
}

type Worker struct {
	cfg          *Config
	pulsarClient *ws.Client
	topic        string
}

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
	}, nil
}

func (w *Worker) Run() {
	go w.UnsubscribeUpdates(w.topic, w.cfg.Token)
	w.SubscribeUpdates(w.topic, w.cfg.Token)
}

func (w *Worker) UnsubscribeUpdates(topic string, token string) {
	// instanceId := strings.ToLower(os.Getenv("HOSTNAME"))
	consumerName := "unsubscribe-" + w.cfg.Hostname + "-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)

	consumer, err := w.pulsarClient.Consumer("persistent/public/default/"+topic+"-unsubscribe", consumerName, ws.Params{
		"subscriptionType": "Exclusive",
		"consumerName":     consumerName,
		"token":            token,
	})

	if err != nil {
		// log.Errorf("error while subscibing %v", err)
		timer := time.NewTimer(time.Second * 5)
		<-timer.C
		w.UnsubscribeUpdates(topic, token)
		return
	}

	ctx := context.Background()

	for {
		msg, err := consumer.Receive(ctx)
		if err != nil {
			// log.Errorf("error while consume subscibing %v", err)
			consumer.Close()

			timer := time.NewTimer(time.Second * 5)
			<-timer.C
			w.UnsubscribeUpdates(topic, token)
			return
		} else {
			v := unsubscribePayload{}
			//log.Printf("unsub payload str %s", string(msg.Payload))
			err := json.Unmarshal(msg.Payload, &v)
			//log.Printf("unsub payload %v", v)
			if err != nil {
				log.Printf("json decode errro %v", err)
			} else {
				err := consumer.Ack(context.Background(), msg)
				if err != nil {
					log.Print("ack msg failed %v", err)
				}

				if v.Not != w.cfg.Hostname {
					_, ok := messages[msg.Key]
					if ok {
						log.Printf("[%d] job revoked   key:%s  ", v.Id, msg.Key)
						delete(messages, msg.Key)
					}
					RemoveCheck(&SyntheticsModelCustom{
						SyntheticsModel: SyntheticsModel{
							AccountUID: v.AccountUID,
							Action:     v.Action,
							Id:         v.Id,
						},
					})
				}
			}
		}
	}
}

func (w *Worker) SubscribeUpdates(topic string, token string) {
	// instanceId := strings.ToLower(os.Getenv("HOSTNAME"))

	consumerName := "subscribe-" + w.cfg.Hostname + "-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)

	log.Printf("URL: %s", w.cfg.Hostname+"/consumer/persistent/public/default/"+topic+"/"+consumerName+"?token="+token)

	consumer, err := w.pulsarClient.Consumer("persistent/public/default/"+topic, "subscribe", ws.Params{
		"subscriptionType":           "Key_Shared",
		"ackTimeoutMillis":           "20000",
		"consumerName":               consumerName,
		"negativeAckRedeliveryDelay": "30000",
		"pullMode":                   "false",
		"receiverQueueSize":          "2000",
		"token":                      token,
	})

	if err != nil {
		// log.Errorf("error while subscibing %v", err)
		timer := time.NewTimer(time.Second * 5)
		<-timer.C
		w.SubscribeUpdates(topic, token)
		return
	}

	ctx := context.Background()

	for {
		msg, err := consumer.Receive(ctx)
		if err != nil {
			// log.Errorf("error while consume subscibing %v", err)
			consumer.Close()

			timer := time.NewTimer(time.Second * 5)
			<-timer.C
			w.SubscribeUpdates(topic, token)
			return
		} else if msg.Payload == nil || len(msg.Payload) == 0 {
			log.Print("[%s] null message recved", msg.MsgId)
			consumer.Ack(context.Background(), msg)
		} else {
			v := SyntheticsModelCustom{}

			err := json.Unmarshal(msg.Payload, &v)
			if err != nil {
				log.Printf("json decode errro %v", err)
			} else {

				if v.Action == "create" {
					v.Action = "update"
				}
				if v.Action == "update" || v.Action == "delete" {
					_, ok := messages[msg.Key]
					refresh := false

					if ok && messages[msg.Key].MsgId == msg.MsgId {
						refresh = true
						//log.Printf("[%d] job refresh key:%s ", v.Id, msg.Key)
					} else if ok && messages[msg.Key].MsgId != msg.MsgId {
						log.Printf("[%d] job update key:%s ", v.Id, msg.Key)
						err := consumer.Ack(context.Background(), messages[msg.Key])
						if err != nil {
							// log.Errorf("error while ack %v", err)
						}
					} else if !ok {
						if v.Action == "update" {
							log.Printf("[%d] job assigned key:%s ", v.Id, msg.Key)
						} else {
							log.Printf("[%d] job assign-delete key:%s", v.Id, msg.Key)
						}
					}

					if v.Action == "update" {

						messages[msg.Key] = msg

						if v.CheckTestRequest.URL != "" {
							// ack  check-type requests.
							err := consumer.Ack(context.Background(), msg)
							if err != nil {
								log.Print("ack msg failed %v", err)
							}
						} else {
							err := consumer.Nack(context.Background(), msg)
							if err != nil {
								log.Print("[%d] nack msg failed %v", v.Id, err)
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
							RunCheck(&v)
						}

					} else {
						delete(messages, msg.Key)
						err := consumer.Ack(context.Background(), msg)
						if err != nil {
							log.Print("ack msg failed %v", err)
						}
						log.Printf("[%d] job removed  key:%s", v.Id, msg.Key)
						RemoveCheck(&v)
					}
				} else {
					log.Printf("invalid action message %s", string(msg.Payload))
				}
			}
		}
	}
}

type unsubscribePayload struct {
	Not        string
	Action     string
	Id         int
	AccountUID string
}

func (w *Worker) produceMessage(accountUid string, topic string, key string, payload unsubscribePayload) {

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
		log.Printf("produce message http failed. %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.cfg.NCAPassword != "" {
		req.Header.Set("Authorization", w.cfg.NCAPassword)
	}

	re, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("produce message failed. %s %v", url, err)
	} else if re.StatusCode != 200 {
		str, _ := io.ReadAll(re.Body)
		log.Printf("produce resp %s %s ss", re.Status, url, string(str))
	}
}
