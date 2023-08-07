package synthetics_agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var _md map[string]*pmetric.Metrics = make(map[string]*pmetric.Metrics)
var _exportTimer func()

var syn = sync.Mutex{}

func getResource(c SyntheticsModelCustom) pmetric.ResourceMetrics {
	syn.Lock()
	defer syn.Unlock()

	if _exportTimer == nil {
		_exportTimer = TimerNew(func() {
			exportMetrics()
		}, 5*time.Second, 5*time.Second)
	}

	if _md[c.AccountUID] == nil {
		pm := pmetric.NewMetrics()
		_md[c.AccountUID] = &pm
	}
	pm := _md[c.AccountUID]
	for i := 0; i < pm.ResourceMetrics().Len(); i++ {
		rm := pm.ResourceMetrics().At(i)
		val, ok := rm.Resource().Attributes().Get("check.check_id")
		if ok && val.Int() == int64(c.Id) {
			return rm
		}
	}
	rm := pm.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("check.agent", "check-agent")
	rm.Resource().Attributes().PutStr("check.version", "1")
	rm.Resource().Attributes().PutStr("check.protocol", c.Proto)
	rm.Resource().Attributes().PutStr("mw.account_key", c.AccountKey)
	rm.Resource().Attributes().PutInt("check.check_id", int64(c.Id))
	return rm
}

func exportMetrics() {
	syn.Lock()
	all := _md
	_md = make(map[string]*pmetric.Metrics)
	syn.Unlock()
	if len(all) == 0 {
		//log.Printf("nothing to export")
		return
	}
	//start_export := time.Now()
	wg := sync.WaitGroup{}

	for account, md := range all {

		mdd := *md
		resources := 0
		scopes := 0
		metrics := 0
		for i := 0; i < mdd.ResourceMetrics().Len(); i++ {
			resources++
			for s := 0; s < mdd.ResourceMetrics().At(i).ScopeMetrics().Len(); s++ {
				scopes++
				metrics += mdd.ResourceMetrics().At(i).ScopeMetrics().At(s).Metrics().Len()
			}
		}
		tr := pmetricotlp.NewExportRequestFromMetrics(mdd)

		///log.Printf("exporting ", resources, scopes, metrics, account)

		request, err := tr.MarshalProto()
		if err != nil {
			log.Printf("error with proto %v", err)
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				endpoint := strings.ReplaceAll(os.Getenv("CAPTURE_ENDPOINT"), "{ACC}", account)
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(request))
				if err != nil {
					log.Errorf("error while exporting metrics %v", err)
					return
				}
				req.Header.Set("Content-Type", "application/x-protobuf")
				req.Header.Set("User-Agent", "ncheck-agent")

				resp, err := exportClient().Do(req)
				if err != nil {
					log.Errorf("[Dur: %s] failed to make an HTTP request: %v", time.Since(start).String(), err)
				} else {
					if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
						// Request is successful.
						body, err := io.ReadAll(resp.Body)
						if err != nil {
							log.Errorf("error reading body %v", err)
						}
						log.Errorf("[Dur: %s] error exporting items, request to %s responded with HTTP Status Code %d\n\n%s\n\n", time.Since(start).String(), endpoint, resp.StatusCode, string(body))
					} else {
						log.Infof("[Dur: %s] exported %s resources: %d scopes: %d metrics: %d account: %s  routines: %d", time.Since(start).String(), resp.Status, resources, scopes, metrics, account, runtime.NumGoroutine())
					}
				}
			}()
		}
	}
	//re := time.Since(start_export).String()
	wg.Wait()
	//log.Printf("export job(%d) fininished in %s but requests in %s", len(all), re, time.Since(start_export).String())
}

var _eclient *http.Client

func exportClient() *http.Client {
	if _eclient != nil {
		return _eclient
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = false
	transport.MaxIdleConns = 100
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConnsPerHost = 50

	clientTransport := (http.RoundTripper)(transport)

	_eclient := &http.Client{
		Transport: clientTransport,
		Timeout:   120 * time.Second,
	}
	return _eclient
}

func FinishCheckRequest(c SyntheticsModelCustom, status string, errstr string, timers map[string]float64, attrs pcommon.Map) {

	testId := strconv.Itoa(c.Id) + "-" + os.Getenv("LOCATION") + "-" + strconv.Itoa(int(time.Now().UnixNano()))
	//log.Printf("testId %s finish %s status:%s err:%s endpoint:%s timers:%v attrs:%v", testId, c.Proto, status, errstr, c.Endpoint, timers, attrs.AsRaw())

	rm := getResource(c)
	ils := rm.ScopeMetrics().AppendEmpty()
	ils.Scope().SetName("check")
	ils.Scope().SetVersion("1")

	//	meter := provider.Meter("go.opentelemetry.io/otel/metric/example")

	for key, value := range timers {
		metrics := pmetric.NewMetric()

		metrics.SetName("check." + key)
		metrics.SetUnit("ms")
		metrics.SetEmptyGauge()

		dp := metrics.Gauge().DataPoints().AppendEmpty()
		dp.SetStartTimestamp(pcommon.Timestamp(time.Now().UnixNano()))
		dp.SetTimestamp(pcommon.Timestamp(time.Now().UnixNano()))
		dp.SetDoubleValue(value)

		attrs.PutStr("check.id", strconv.Itoa(c.Id))
		attrs.PutStr("check.test_id", testId)
		attrs.PutStr("check.status", status)
		attrs.PutStr("check.location", os.Getenv("LOCATION"))
		if status != "OK" {
			attrs.PutStr("check.error", errstr)
		}

		attrs.CopyTo(dp.Attributes())

		metrics.MoveTo(ils.Metrics().AppendEmpty())
	}
}

func WebhookSendCheckRequest(c SyntheticsModelCustom, opts map[string]interface{}) {
	go func() {
		if c.CheckTestRequest.URL != "" {
			go func() {
				resStr, _ := MakeRequest(RequestOptions{
					URL:     c.CheckTestRequest.URL,
					Headers: c.CheckTestRequest.Headers,
					Method:  "POST",
					Body:    opts,
				})

				log.Printf("MakeRequest--test request %s", resStr)
			}()
		}
	}()
}

type RequestOptions struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    map[string]interface{}
}

func MakeRequest(r RequestOptions) (string, error) {
	bodyByte, _ := json.Marshal(r.Body)
	req, reqErr := http.NewRequest(r.Method, r.URL, bytes.NewBuffer(bodyByte))
	if reqErr != nil {
		fmt.Println("Error creating request:", reqErr)
		return "", reqErr
	}
	for key, value := range r.Headers {
		req.Header.Set(key, value)
	}
	if _, k := r.Headers["Content-Type"]; !k {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, clientErr := client.Do(req)
	if clientErr != nil {
		fmt.Println("Error sending request:", clientErr)
		return "", clientErr
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	_, bufErr := buf.ReadFrom(resp.Body)
	if bufErr != nil {
		fmt.Println("Error reading response:", bufErr)
		return "", bufErr
	}
	return buf.String(), nil
}
