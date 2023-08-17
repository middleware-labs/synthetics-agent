package synthetics_agent

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"github.com/middleware-labs/synthetics-agent/ws"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	//"github.com/apache/pulsar-client-go/pulsar"
	log "github.com/sirupsen/logrus"
	"os"
)

func RunSyntheticWorker(typ string, location string, token string) {
	var topic string = ""
	if typ == "location" {
		topic = "location-" + strings.ToLower(location)
	} else if typ == "agent" {
		if location == "" {
			topic = "agent-" + strings.ToLower(token)
		} else {
			topic = "agent-" + strings.ToLower(token) + "-" + fmt.Sprintf("%x", sha1.Sum([]byte(strings.ToLower(location))))
		}
	} else {
		panic(fmt.Errorf("invalid type passed."))
	}
	go unsubscribeUpdates(topic, token)

	subscribeUpdates(topic, token)
}

var messages map[string]*ws.Msg = make(map[string]*ws.Msg)

func unsubscribeUpdates(topic string, token string) {
	instanceId := strings.ToLower(os.Getenv("HOSTNAME"))
	consumerName := "unsubscribe-" + instanceId + "-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)

	consumer, err := GetPulsar().Consumer("persistent/public/default/"+topic+"-unsubscribe", consumerName, ws.Params{
		"subscriptionType": "Exclusive",
		"consumerName":     consumerName,
		"token":            token,
	})

	if err != nil {
		log.Errorf("error while subscibing %v", err)
		timer := time.NewTimer(time.Second * 5)
		<-timer.C
		unsubscribeUpdates(topic, token)
		return
	}

	ctx := context.Background()

	for {
		msg, err := consumer.Receive(ctx)
		if err != nil {
			log.Errorf("error while consume subscibing %v", err)
			consumer.Close()

			timer := time.NewTimer(time.Second * 5)
			<-timer.C
			unsubscribeUpdates(topic, token)
			return
		} else {
			v := UnsubscribePayload{}
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
				if v.Not != instanceId {
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
func subscribeUpdates(topic string, token string) {
	instanceId := strings.ToLower(os.Getenv("HOSTNAME"))

	consumerName := "subscribe-" + instanceId + "-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)

	log.Printf("URL: %s", os.Getenv("PULSAR_HOST")+"/consumer/persistent/public/default/"+topic+"/"+consumerName+"?token="+token)

	consumer, err := GetPulsar().Consumer("persistent/public/default/"+topic, "subscribe", ws.Params{
		"subscriptionType":           "Key_Shared",
		"ackTimeoutMillis":           "20000",
		"consumerName":               consumerName,
		"negativeAckRedeliveryDelay": "30000",
		"pullMode":                   "false",
		"receiverQueueSize":          "2000",
		"token":                      token,
	})

	if err != nil {
		log.Errorf("error while subscibing %v", err)
		timer := time.NewTimer(time.Second * 5)
		<-timer.C
		subscribeUpdates(topic, token)
		return
	}

	ctx := context.Background()

	for {
		msg, err := consumer.Receive(ctx)
		if err != nil {
			log.Errorf("error while consume subscibing %v", err)
			consumer.Close()

			timer := time.NewTimer(time.Second * 5)
			<-timer.C
			subscribeUpdates(topic, token)
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
							log.Errorf("error while ack %v", err)
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
								produceMessage(v.AccountUID, topic+"-unsubscribe", msg.Key, UnsubscribePayload{
									Not:        instanceId,
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

type UnsubscribePayload struct {
	Not        string
	Action     string
	Id         int
	AccountUID string
}

func produceMessage(accountUid string, topic string, key string, payload UnsubscribePayload) {

	type Payload struct {
		Topic   string
		Key     string
		Payload UnsubscribePayload
	}
	pay := Payload{
		Topic:   topic,
		Key:     key,
		Payload: payload,
	}
	str, _ := json.Marshal(pay)

	url := strings.ReplaceAll(os.Getenv("UNSUBSCRIBE_ENDPOINT"), "{ACC}", accountUid)
	req, err := http.NewRequest("POST", url, bytes.NewReader(str))
	if err != nil {
		log.Printf("produce message http failed. %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if os.Getenv("NCA_PASSWORD") != "" {
		req.Header.Set("Authorization", os.Getenv("NCA_PASSWORD"))
	}

	re, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("produce message failed. %s %v", url, err)
	} else if re.StatusCode != 200 {
		str, _ := io.ReadAll(re.Body)
		log.Printf("produce resp %s %s ss", re.Status, url, string(str))
	}
}
