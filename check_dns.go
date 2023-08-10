package synthetics_agent

import (
	"context"
	"encoding/json"
	"fmt"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"net"
	"strings"
	"time"
)

func CheckDnsRequest(c SyntheticsModelCustom) {
	timers := map[string]float64{
		"duration": 0,
	}
	attrs := pcommon.NewMap()
	_start := time.Now()
	_Status := "OK"
	_Message := ""
	assertions := make([]map[string]string, 0)

	_IsTestReq := c.CheckTestRequest.URL != ""
	_lookup := make([]map[string]string, 0)

	_dialAddress := c.Request.DNSServer + ":" + c.Request.Port

	_Resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second,
			}
			return d.DialContext(ctx, network, _dialAddress)
		},
	}

	ips, err := _Resolver.LookupIP(context.Background(), "ip", c.Endpoint)
	if err != nil {
		_Status = "FAIL"
		_Message = fmt.Sprintf("error resolving dns %v", err)
		timers["duration"] = timeInMs(time.Since(_start))

		//FinishCheckRequest(c, "FAIL", fmt.Sprintf("error resolving dns %v", err), timers, attrs)
		//return
	} else {

		ipss := []string{}
		for _, v := range ips {
			ipss = append(ipss, v.String())
		}
		attrs.PutStr("resolve.ips", strings.Join(ipss, "\n"))

		timers["duration"] = timeInMs(time.Since(_start))
	}

	if !_IsTestReq {

		for _, assert := range c.Request.Assertions.DNS.Cases {

			if _Status == "FAIL" {
				assertions = append(assertions, map[string]string{
					"type":   assert.Type,
					"reason": "Error resolving dns",
					"actual": "N/A",
					"status": "FAIL",
				})
			} else {
				switch assert.Type {
				case "response_time":
					_ck := make(map[string]string)
					_ck["type"] = assert.Type
					_ck["status"] = "OK"
					_ck["actual"] = fmt.Sprintf("%v", timers["duration"])
					_ck["reason"] = "response time assertion passed"
					if !assertInt(int64(timers["duration"]), assert) {
						_ck["status"] = "FAIL"
						_ck["reason"] = "response time assertion failed"
						//FinishCheckRequest(c, "FAIL", "assert failed, body didn't matched", timers, attrs)
						//return
					}
					_ck["status"] = "OK"
					assertions = append(assertions, _ck)
					break
				case "every_available_record":
				case "at_least_one_record":
					records := make([]string, 0)

					_ck := make(map[string]string)
					_ck["type"] = strings.ReplaceAll(assert.Type, "_", " ") + " " + strings.ReplaceAll(assert.Config.Target, "_", " ")
					_ck["status"] = "OK"

					if assert.Config.Target == "of_type_a" {
						for _, v := range ips {
							if len(v) == net.IPv4len {
								records = append(records, v.String())
							}
						}
					}
					if assert.Config.Target == "of_type_aaaa" {
						for _, v := range ips {
							if len(v) == net.IPv6len {
								records = append(records, v.String())
							}
						}
					}
					if assert.Config.Target == "of_type_cname" {
						cname, cnmErr := _Resolver.LookupCNAME(context.Background(), c.Endpoint)
						if cnmErr != nil {
							_ck["reason"] = "Error while looking up CNAME record"
							_ck["status"] = "FAIL"
							_ck["actual"] = fmt.Sprintf("%v", cnmErr)
						} else {
							records = append(records, cname)
						}
					}
					if assert.Config.Target == "of_type_mx" {
						mxs, lcErr := _Resolver.LookupMX(context.Background(), c.Endpoint)
						if lcErr != nil {
							_ck["reason"] = "Error while resolving MX record"
							_ck["status"] = "FAIL"
							_ck["actual"] = fmt.Sprintf("%v", lcErr)
						} else {
							for _, v := range mxs {
								records = append(records, v.Host)
							}
						}
					}
					if assert.Config.Target == "of_type_ns" {
						nsx, nsErr := _Resolver.LookupNS(context.Background(), c.Endpoint)
						if nsErr != nil {
							_ck["reason"] = "Error while looking up NS record"
							_ck["status"] = "FAIL"
							_ck["actual"] = fmt.Sprintf("%v", nsErr)
						} else {
							for _, v := range nsx {
								records = append(records, v.Host)
							}
						}
					}
					if assert.Config.Target == "of_type_txt" {
						nsx, txErr := _Resolver.LookupTXT(context.Background(), c.Endpoint)
						if txErr != nil {
							_ck["status"] = "FAIL"
							_ck["reason"] = "Error while looking up TXT record"
							_ck["actual"] = fmt.Sprintf("%v", txErr)
						} else {
							records = nsx
						}
					}

					every := assert.Type == "every_available_record"
					match := false

					if len(records) > 0 {
						_pass := true
						for _, rec := range records {
							if !assertString(rec, assert) {
								_pass = false
								if every {
									break
									//FinishCheckRequest(c, "FAIL", "ip a record match failed with "+rec, timers, attrs)
									//return
								}
								match = true
								break
							}
						}

						if _ck["actual"] == "" {
							_ck["actual"] = strings.Join(records, ",")
						}

						if _pass {
							_ck["status"] = "OK"
							_ck["actual"] = strings.Join(records, ",")
						} else {
							_ck["status"] = "FAIL"
							if _ck["reason"] == "" {
								_ck["reason"] = "assertion failed"
							}
							_Status = "FAIL"
							_Message = "Assertion failed with " + strings.Join(records, ",")
						}
					}

					if !every && !match {
						_Status = "FAIL"
						_Message = "No record matched with given condition " + strings.Join(records, ",")
						//FinishCheckRequest(c, "FAIL", "no record matched with given condition "+strings.Join(records, ","), timers, attrs)
						//return
					}

					break
				}
			}
		}

		resultStr, _ := json.Marshal(assertions)
		attrs.PutStr("assertions", string(resultStr))

		FinishCheckRequest(c, _Status, _Message, timers, attrs)
	} else {

		_testBody := make(map[string]interface{}, 0)
		_asr := []map[string]interface{}{
			{
				"type": "response_time",
				"config": map[string]string{
					"operator": "is",
					"value":    fmt.Sprintf("%v", timers["duration"]),
				},
			},
		}

		for _, v := range ips {
			if len(v) == net.IPv6len {
				_asr = append(_asr, map[string]interface{}{
					"type": "at_least_one_record",
					"config": map[string]string{
						"operator": "is",
						"value":    v.String(),
						"target":   "of_type_aaaa",
					},
				})
				_lookup = append(_lookup, map[string]string{
					"AAAA": v.String(),
				})
			}
			if len(v) == net.IPv4len {
				_lookup = append(_lookup, map[string]string{
					"A": v.String(),
				})

				_asr = append(_asr, map[string]interface{}{
					"type": "at_least_one_record",
					"config": map[string]string{
						"operator": "is",
						"value":    v.String(),
						"target":   "of_type_a",
					},
				})
			}
		}

		if txt, txtEr := _Resolver.LookupTXT(context.Background(), c.Endpoint); txtEr == nil && len(txt) > 0 {
			for _, v := range txt {
				_lookup = append(_lookup, map[string]string{
					"TXT": v,
				})
			}
			_asr = append(_asr, map[string]interface{}{
				"type": "at_least_one_record",
				"config": map[string]string{
					"operator": "is",
					"value":    strings.Join(txt, ","),
					"target":   "of_type_txt",
				},
			})
		}
		if ns, nsEr := _Resolver.LookupNS(context.Background(), c.Endpoint); nsEr == nil && len(ns) > 0 {
			for _, v := range ns {
				_lookup = append(_lookup, map[string]string{
					"NS": v.Host,
				})
			}
			_asr = append(_asr, map[string]interface{}{
				"type": "at_least_one_record",
				"config": map[string]string{
					"operator": "is",
					"value":    ns[0].Host,
					"target":   "of_type_ns",
				},
			})
		}
		if mx, mxEr := _Resolver.LookupMX(context.Background(), c.Endpoint); mxEr == nil {
			for _, v := range mx {
				_lookup = append(_lookup, map[string]string{
					"MX": fmt.Sprintf("%v %v", v.Pref, v.Host),
				})
			}
		}
		if cname, cnmErr := _Resolver.LookupCNAME(context.Background(), c.Endpoint); cnmErr == nil && cname != "" {
			_lookup = append(_lookup, map[string]string{
				"CNAME": cname,
			})
			_asr = append(_asr, map[string]interface{}{
				"type": "at_least_one_record",
				"config": map[string]string{
					"operator": "is",
					"value":    cname,
					"target":   "of_type_cname",
				},
			})
		}

		_testBody["headers"] = _lookup
		_testBody["assertions"] = _asr
		_testBody["tookMs"] = fmt.Sprintf("%.2f ms", timers["duration"])
		WebhookSendCheckRequest(c, _testBody)
	}
}
