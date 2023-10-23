package worker

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
)

func TestExportProtoRequest(t *testing.T) {
	tests := []struct {
		name            string
		captureEndpoint string
		account         string
		exportClient    httpClient
		exportRequest   pmetricotlp.ExportRequest
		wantErrMsg      string
	}{
		{
			name:            "successful request",
			captureEndpoint: "http://example.com/{ACC}",

			account: "test-account",
			exportRequest: func() pmetricotlp.ExportRequest {
				metrics := pmetric.NewMetrics()
				resourceMetrics := metrics.ResourceMetrics()
				rm := resourceMetrics.AppendEmpty()
				resourceAttributes := rm.Resource().Attributes()

				resourceAttributes.PutStr("mw.client_origin", "example.com")
				resourceAttributes.PutStr("mw.account_key", "12345")
				resourceAttributes.PutStr("mw_source", "datadog")
				resourceAttributes.PutStr("host.id", "example.com")
				resourceAttributes.PutStr("host.name", "example.com")

				scopeMetrics := rm.ScopeMetrics().AppendEmpty()
				instrumentationScope := scopeMetrics.Scope()
				instrumentationScope.SetName("mw")
				instrumentationScope.SetVersion("v0.0.1")

				scopeMetric := scopeMetrics.Metrics().AppendEmpty()
				scopeMetric.SetName("requests")
				metricAttributes := pcommon.NewMap()

				metricAttributes.PutStr("key1", "value1")
				metricAttributes.PutStr("key2", "value2")

				var dataPoints pmetric.NumberDataPointSlice

				sum := scopeMetric.SetEmptySum()
				sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				sum.SetIsMonotonic(false)
				dataPoints = sum.DataPoints()

				unixNano := 1619737200 * math.Pow(10, 9)
				dp1 := dataPoints.AppendEmpty()
				dp1.SetTimestamp(pcommon.Timestamp(unixNano))

				dp1.SetDoubleValue(10 * 10)
				attributeMap := dp1.Attributes()
				metricAttributes.CopyTo(attributeMap)

				unixNano = 1619737210 * math.Pow(10, 9)
				dp2 := dataPoints.AppendEmpty()
				dp2.SetTimestamp(pcommon.Timestamp(unixNano))
				dp2.SetDoubleValue(15 * 10)
				attributeMap = dp2.Attributes()
				metricAttributes.CopyTo(attributeMap)

				return pmetricotlp.NewExportRequestFromMetrics(metrics)
			}(),
			wantErrMsg: "",
		},
		{
			name:            "failed to send the request",
			captureEndpoint: "http://example.com/{ACC}",
			account:         "test-account",
			exportClient: &mockHTTPClient{
				err: errors.New("failed to send the request"),
			},
			exportRequest: func() pmetricotlp.ExportRequest {
				metrics := pmetric.NewMetrics()
				resourceMetrics := metrics.ResourceMetrics()
				rm := resourceMetrics.AppendEmpty()
				resourceAttributes := rm.Resource().Attributes()

				resourceAttributes.PutStr("mw.client_origin", "example.com")
				resourceAttributes.PutStr("mw.account_key", "12345")
				resourceAttributes.PutStr("mw_source", "datadog")
				resourceAttributes.PutStr("host.id", "example.com")
				resourceAttributes.PutStr("host.name", "example.com")

				scopeMetrics := rm.ScopeMetrics().AppendEmpty()
				instrumentationScope := scopeMetrics.Scope()
				instrumentationScope.SetName("mw")
				instrumentationScope.SetVersion("v0.0.1")

				scopeMetric := scopeMetrics.Metrics().AppendEmpty()
				scopeMetric.SetName("requests")
				metricAttributes := pcommon.NewMap()

				metricAttributes.PutStr("key1", "value1")
				metricAttributes.PutStr("key2", "value2")

				var dataPoints pmetric.NumberDataPointSlice

				sum := scopeMetric.SetEmptySum()
				sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				sum.SetIsMonotonic(false)
				dataPoints = sum.DataPoints()

				unixNano := 1619737200 * math.Pow(10, 9)
				dp1 := dataPoints.AppendEmpty()
				dp1.SetTimestamp(pcommon.Timestamp(unixNano))

				dp1.SetDoubleValue(10 * 10)
				attributeMap := dp1.Attributes()
				metricAttributes.CopyTo(attributeMap)

				unixNano = 1619737210 * math.Pow(10, 9)
				dp2 := dataPoints.AppendEmpty()
				dp2.SetTimestamp(pcommon.Timestamp(unixNano))
				dp2.SetDoubleValue(15 * 10)
				attributeMap = dp2.Attributes()
				metricAttributes.CopyTo(attributeMap)

				return pmetricotlp.NewExportRequestFromMetrics(metrics)
			}(),
			wantErrMsg: "failed to send the request",
		},
		{
			name:            "response status code not 200",
			captureEndpoint: "http://example.com/{ACC}",
			account:         "test-account",
			exportClient: &mockHTTPClient{
				response: &http.Response{
					StatusCode: 500,
					Body:       io.NopCloser(bytes.NewBufferString("hello")),
				},
				err: nil,
			},
			exportRequest: func() pmetricotlp.ExportRequest {
				metrics := pmetric.NewMetrics()
				resourceMetrics := metrics.ResourceMetrics()
				rm := resourceMetrics.AppendEmpty()
				resourceAttributes := rm.Resource().Attributes()

				resourceAttributes.PutStr("mw.client_origin", "example.com")
				resourceAttributes.PutStr("mw.account_key", "12345")
				resourceAttributes.PutStr("mw_source", "datadog")
				resourceAttributes.PutStr("host.id", "example.com")
				resourceAttributes.PutStr("host.name", "example.com")

				scopeMetrics := rm.ScopeMetrics().AppendEmpty()
				instrumentationScope := scopeMetrics.Scope()
				instrumentationScope.SetName("mw")
				instrumentationScope.SetVersion("v0.0.1")

				scopeMetric := scopeMetrics.Metrics().AppendEmpty()
				scopeMetric.SetName("requests")
				metricAttributes := pcommon.NewMap()

				metricAttributes.PutStr("key1", "value1")
				metricAttributes.PutStr("key2", "value2")

				var dataPoints pmetric.NumberDataPointSlice

				sum := scopeMetric.SetEmptySum()
				sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				sum.SetIsMonotonic(false)
				dataPoints = sum.DataPoints()

				unixNano := 1619737200 * math.Pow(10, 9)
				dp1 := dataPoints.AppendEmpty()
				dp1.SetTimestamp(pcommon.Timestamp(unixNano))

				dp1.SetDoubleValue(10 * 10)
				attributeMap := dp1.Attributes()
				metricAttributes.CopyTo(attributeMap)

				unixNano = 1619737210 * math.Pow(10, 9)
				dp2 := dataPoints.AppendEmpty()
				dp2.SetTimestamp(pcommon.Timestamp(unixNano))
				dp2.SetDoubleValue(15 * 10)
				attributeMap = dp2.Attributes()
				metricAttributes.CopyTo(attributeMap)

				return pmetricotlp.NewExportRequestFromMetrics(metrics)
			}(),
			wantErrMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := newCheckState(SyntheticCheck{}, "us-east-1", tt.captureEndpoint)
			if tt.exportClient != nil {
				cs.exportClient = tt.exportClient
			}

			// create a test server to mock the http request
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "application/x-protobuf", r.Header.Get("Content-Type"))
				assert.Equal(t, "ncheck-agent", r.Header.Get("User-Agent"))
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/"+tt.account, r.URL.String())
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.NotEmpty(t, body)
				w.WriteHeader(http.StatusOK)
			}))
			defer testServer.Close()

			cs.captureEndpoint = testServer.URL + "/{ACC}"
			gotErr := cs.exportProtoRequest(tt.account, tt.exportRequest)

			if gotErr != nil && gotErr.Error() != tt.wantErrMsg {
				t.Fatalf("%s: Expected err to be %v, but got %v", tt.name,
					tt.wantErrMsg, gotErr.Error())
			}

			if gotErr == nil && tt.wantErrMsg != "" {
				t.Fatalf("%s: Expected err to be %v, but got %v", tt.name,
					tt.wantErrMsg, gotErr)
			}
			if gotErr != nil {
				return
			}
		})
	}
}
