package synthetics_agent

import (
	"github.com/middleware/check-agent/ws"
	"os"
)

var _pulsar *ws.Client
var _producers map[string]ws.Producer = make(map[string]ws.Producer)

func GetPulsar() *ws.Client {
	if _pulsar != nil {
		return _pulsar
	}
	_pulsar = ws.New(os.Getenv("PULSAR_HOST"))
	return _pulsar
}
