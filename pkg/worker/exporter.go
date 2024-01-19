package worker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"log/slog"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"golang.org/x/sync/errgroup"
)

var md map[string]*pmetric.Metrics = make(map[string]*pmetric.Metrics)

var exportTimer func()

var syn = sync.Mutex{}

func (cs *CheckState) getResourceMetrics() pmetric.ResourceMetrics {
	syn.Lock()
	defer syn.Unlock()
	check := cs.check
	if exportTimer == nil {
		exportTimer = TimerNew(func() {
			cs.exportMetrics()
		}, 5*time.Second, 5*time.Second)
	}

	if md[check.AccountUID] == nil {
		pm := pmetric.NewMetrics()
		md[check.AccountUID] = &pm
	}
	pm := md[check.AccountUID]
	for i := 0; i < pm.ResourceMetrics().Len(); i++ {
		rm := pm.ResourceMetrics().At(i)
		val, ok := rm.Resource().Attributes().Get("check.check_id")
		if ok && val.Int() == int64(check.Id) {
			return rm
		}
	}
	rm := pm.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("check.agent", "check-agent")
	rm.Resource().Attributes().PutStr("check.version", "1")
	rm.Resource().Attributes().PutStr("check.protocol", check.Proto)
	rm.Resource().Attributes().PutStr("mw.account_key", check.AccountKey)
	rm.Resource().Attributes().PutInt("check.check_id", int64(check.Id))
	return rm
}

func (cs *CheckState) exportMetrics() error {
	syn.Lock()
	all := md
	md = make(map[string]*pmetric.Metrics)
	syn.Unlock()
	if len(all) == 0 {
		//log.Printf("nothing to export")
		return nil
	}
	//start_export := time.Now()
	eg := errgroup.Group{}

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
		account := account

		eg.Go(func() error {
			return cs.exportProtoRequest(account, tr)
		})
		///log.Printf("exporting ", resources, scopes, metrics, account)

	}

	return eg.Wait()
	//re := time.Since(start_export).String()
	// wg.Wait()
	//log.Printf("export job(%d) fininished in %s but requests in %s", len(all), re, time.Since(start_export).String())
}

func (cs *CheckState) exportProtoRequest(account string, tr pmetricotlp.ExportRequest) error {
	defer func() {
		if r := recover(); r != nil {
			slog.Info("Recovered in f", slog.Any("r", r),
				slog.String("account", account),
				slog.String("tr", fmt.Sprintf("%v", tr)))
		}
	}()
	request, err := tr.MarshalProto()
	if err != nil {
		slog.Error("error with proto", slog.String("error", err.Error()))
		return err
	}
	start := time.Now()
	endpoint := strings.ReplaceAll(cs.captureEndpoint, "{ACC}", account)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(request))
	if err != nil {
		slog.Error("error while exporting metrics", slog.String("error", err.Error()))
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("User-Agent", "ncheck-agent")

	resp, err := cs.exportClient.Do(req)
	if err != nil {
		slog.Error("error while exporting metrics", slog.String("duration",
			time.Since(start).String()), slog.String("error", err.Error()))
		return err
	}
	defer resp.Body.Close()
	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		// Request is successful.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("error reading body",
				slog.String("error", err.Error()))

		}

		slog.Error("error exporting items", slog.String("duration", time.Since(start).String()),
			slog.String("endpoint", endpoint),
			slog.Int("status", resp.StatusCode),
			slog.String("body", string(body)),
			slog.String("account key", cs.check.AccountKey),
			slog.Any("check", cs.check))
		return err
	}
	//slog.Infof("[Dur: %s] exported %s resources: %d scopes: %d metrics: %d account: %s  routines: %d", time.Since(start).String(), resp.Status, resources, scopes, metrics, account, runtime.NumGoroutine())
	return nil
}

func (cs *CheckState) finishCheckRequest(testStatus testStatus,
	timers map[string]float64, attrs pcommon.Map) {
	check := cs.check
	testId := strconv.Itoa(check.Id) + "-" +
		cs.location + "-" +
		strconv.Itoa(int(time.Now().UnixNano()))
	//log.Printf("testId %s finish %s status:%s err:%s endpoint:%s timers:%v attrs:%v", testId, c.Proto, status, errstr, c.Endpoint, timers, attrs.AsRaw())

	rm := cs.getResourceMetrics()
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

		attrs.PutStr("check.id", strconv.Itoa(check.Id))
		attrs.PutStr("check.test_id", testId)
		attrs.PutStr("check.status", testStatus.status)
		attrs.PutStr("check.location", cs.location)
		if testStatus.status != testStatusOK {
			attrs.PutStr("check.error", testStatus.msg)
		}

		attrs.CopyTo(dp.Attributes())

		metrics.MoveTo(ils.Metrics().AppendEmpty())
	}
}

func (cs *CheckState) finishTestRequest(opts map[string]interface{}) {
	go func() {
		c := cs.check
		if c.CheckTestRequest.URL != "" {
			_, _ = makeRequest(RequestOptions{
				URL:     c.CheckTestRequest.URL,
				Headers: c.CheckTestRequest.Headers,
				Method:  http.MethodPost,
				Body:    opts,
			})
		}
	}()
}

type RequestOptions struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    map[string]interface{}
}

func makeRequest(r RequestOptions) (string, error) {
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
