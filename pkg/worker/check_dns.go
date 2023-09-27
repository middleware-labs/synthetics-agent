package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

const (
	assertTypeDNSResponseTime         = "response_time"
	assertTypeDNSEveryAvailableRecord = "every_available_record"
	assertTypeDNSAtLeastOneRecord     = "at_least_one_record"
)

var (
	errEmptyTXTRecord   = errors.New("zero TXT records found")
	errEmptyNSRecord    = errors.New("zero NS records found")
	errEmptyCNAMERecord = errors.New("zero CNAME records found")
)

type dnsRecordType string

const (
	dnsRecordTypeA     dnsRecordType = "A"
	dnsRecordTypeAAAA  dnsRecordType = "AAAA"
	dnsRecordTypeTXT   dnsRecordType = "TXT"
	dnsRecordTypeNS    dnsRecordType = "NS"
	dnsRecordTypeMX    dnsRecordType = "MX"
	dnsRecordTypeCNAME dnsRecordType = "CNAME"
)

var recordTypeToLookupFn = map[dnsRecordType]func(context.Context,
	string, *net.Resolver) ([]string, map[string]interface{}, error){
	dnsRecordTypeTXT:   lookupTXT,
	dnsRecordTypeNS:    lookupNS,
	dnsRecordTypeMX:    lookupMX,
	dnsRecordTypeCNAME: lookupCNAME,
}

func getDNSResolver(r SyntheticsRequestOptions) *net.Resolver {
	dialAddress := r.DNSServer + ":" + r.Port

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second,
			}
			return d.DialContext(ctx, network, dialAddress)
		},
	}
}

func processTestDNSRequest(ctx context.Context, c SyntheticsModelCustom) {

	resolver := getDNSResolver(c.Request)
	testBody := make(map[string]interface{}, 0)
	start := time.Now()
	// ignore error intentionally
	ips, _ := resolver.LookupIP(ctx, "ip", c.Endpoint)
	duration := timeInMs(time.Since(start))

	lookup := make([]map[string]string, 0)
	asr := []map[string]interface{}{
		{
			"type": assertTypeDNSResponseTime,
			"config": map[string]string{
				"operator": "is",
				"value":    fmt.Sprintf("%v", duration),
			},
		},
	}

	for _, v := range ips {
		if len(v) == net.IPv6len {
			asr = append(asr, map[string]interface{}{
				"type": assertTypeDNSAtLeastOneRecord,
				"config": map[string]string{
					"operator": "is",
					"value":    v.String(),
					"target":   "of_type_aaaa",
				},
			})
			lookup = append(lookup, map[string]string{
				"AAAA": v.String(),
			})
		}
		if len(v) == net.IPv4len {
			lookup = append(lookup, map[string]string{
				"A": v.String(),
			})

			asr = append(asr, map[string]interface{}{
				"type": assertTypeDNSAtLeastOneRecord,
				"config": map[string]string{
					"operator": "is",
					"value":    v.String(),
					"target":   "of_type_a",
				},
			})
		}
	}

	// TODO: following lookups can be concurrent
	for recordType, lookupFn := range recordTypeToLookupFn {
		records, assert, _ := lookupFn(ctx, c.Endpoint, resolver)
		for _, record := range records {
			lookup = append(lookup, map[string]string{string(recordType): record})
		}
		asr = append(asr, assert)
	}

	testBody["headers"] = lookup
	testBody["assertions"] = asr
	testBody["tookMs"] = fmt.Sprintf("%.2f ms", duration)
	WebhookSendCheckRequest(c, testBody)
}

func processDNSRequest(ctx context.Context, c SyntheticsModelCustom) {
	timers := map[string]float64{
		"duration": 0,
	}
	attrs := pcommon.NewMap()
	start := time.Now()
	status := reqStatusOK
	message := ""
	assertions := make([]map[string]string, 0)

	resolver := getDNSResolver(c.Request)
	ips, err := resolver.LookupIP(ctx, "ip", c.Endpoint)
	if err != nil {
		status = reqStatusFail
		message = fmt.Sprintf("error resolving dns: %v", err)
		timers["duration"] = timeInMs(time.Since(start))
	} else {
		ipss := []string{}
		for _, v := range ips {
			ipss = append(ipss, v.String())
		}
		attrs.PutStr("resolve.ips", strings.Join(ipss, "\n"))

		timers["duration"] = timeInMs(time.Since(start))
	}

	for _, assert := range c.Request.Assertions.DNS.Cases {
		if status == reqStatusFail {
			assertions = append(assertions, map[string]string{
				"type":   assert.Type,
				"reason": message,
				"actual": "N/A",
				"status": string(reqStatusFail),
			})
			continue
		}

		switch assert.Type {
		case assertTypeDNSResponseTime:
			ck := make(map[string]string)
			ck["type"] = assert.Type
			ck["status"] = string(reqStatusOK)
			ck["actual"] = fmt.Sprintf("%v", timers["duration"])
			ck["reason"] = "response time assertion passed"
			if !assertInt(int64(timers["duration"]), assert) {
				ck["status"] = string(reqStatusFail)
				ck["reason"] = "response time assertion failed"
			}
			ck["status"] = string(reqStatusOK)
			assertions = append(assertions, ck)

		case assertTypeDNSEveryAvailableRecord:
			fallthrough
		case assertTypeDNSAtLeastOneRecord:
			records := make([]string, 0)

			ck := make(map[string]string)
			ck["type"] = strings.ReplaceAll(assert.Type, "_", " ") + " " +
				strings.ReplaceAll(assert.Config.Target, "_", " ")
			ck["status"] = string(reqStatusOK)

			switch assert.Config.Target {
			case "of_type_a":
				for _, v := range ips {
					if len(v) == net.IPv4len {
						records = append(records, v.String())
					}
				}
			case "of_type_aaaa":
				for _, v := range ips {
					if len(v) == net.IPv6len {
						records = append(records, v.String())
					}
				}
			case "of_type_cname":
				cnames, _, err := lookupCNAME(ctx, c.Endpoint, resolver)
				if err != nil {
					ck["reason"] = "Error while looking up CNAME record"
					ck["status"] = string(reqStatusFail)
					ck["actual"] = fmt.Sprintf("%v", err)
				} else {
					records = append(records, cnames...)
				}
			case "of_type_mx":
				mxHosts, _, err := lookupMX(ctx, c.Endpoint, resolver)
				if err != nil {
					ck["reason"] = "Error while resolving MX record"
					ck["status"] = string(reqStatusFail)
					ck["actual"] = fmt.Sprintf("%v", err)
				} else {
					records = append(records, mxHosts...)
				}
			case "of_type_ns":
				nsHosts, _, err := lookupNS(ctx, c.Endpoint, resolver)
				if err != nil {
					ck["reason"] = "Error while looking up NS record"
					ck["status"] = string(reqStatusFail)
					ck["actual"] = fmt.Sprintf("%v", err)
				} else {
					records = append(records, nsHosts...)
				}
			case "of_type_txt":
				txtHosts, _, err := lookupTXT(ctx, c.Endpoint, resolver)
				if err != nil {
					ck["status"] = string(reqStatusFail)
					ck["reason"] = "Error while looking up TXT record"
					ck["actual"] = fmt.Sprintf("%v", err)
				} else {
					records = append(records, txtHosts...)
				}
			}

			every := assert.Type == assertTypeDNSEveryAvailableRecord
			match := false

			if len(records) > 0 {
				pass := true
				for _, rec := range records {
					if !assertString(rec, assert) {
						pass = false
						if every {
							break
							//FinishCheckRequest(c, "FAIL", "ip a record match failed with "+rec, timers, attrs)
							//return
						}
						match = true
						break
					}
				}

				if ck["actual"] == "" {
					ck["actual"] = strings.Join(records, ",")
				}

				if pass {
					ck["status"] = string(reqStatusOK)
					ck["actual"] = strings.Join(records, ",")
				} else {
					ck["status"] = string(reqStatusFail)
					if ck["reason"] == "" {
						ck["reason"] = "assertion failed"
					}
					status = reqStatusFail
					message = "Assertion failed with " + strings.Join(records, ",")
				}
			}

			if !every && !match {
				status = reqStatusFail
				message = "No record matched with given condition " + strings.Join(records, ",")
				//FinishCheckRequest(c, "FAIL", "no record matched with given condition "+strings.Join(records, ","), timers, attrs)
				//return
			}
		}
	}

	resultStr, _ := json.Marshal(assertions)
	attrs.PutStr("assertions", string(resultStr))

	FinishCheckRequest(c, string(status), message, timers, attrs)
}

func lookupTXT(ctx context.Context, endpoint string,
	resolver *net.Resolver) ([]string, map[string]interface{}, error) {
	asr := make(map[string]interface{})

	txt, err := resolver.LookupTXT(ctx, endpoint)
	if err != nil {
		return []string{}, asr, err
	}

	if len(txt) == 0 {
		return []string{}, asr, errEmptyTXTRecord
	}

	asr = map[string]interface{}{
		"type": assertTypeDNSAtLeastOneRecord,
		"config": map[string]string{
			"operator": "is",
			"value":    strings.Join(txt, ","),
			"target":   "of_type_txt",
		},
	}

	return txt, asr, nil
}

func lookupNS(ctx context.Context, endpoint string,
	resolver *net.Resolver) ([]string, map[string]interface{}, error) {
	var nsHosts []string
	asr := make(map[string]interface{})

	ns, err := resolver.LookupNS(ctx, endpoint)
	if err != nil {
		return nsHosts, asr, err
	}

	if len(ns) == 0 {
		return nsHosts, asr, errEmptyNSRecord
	}

	for _, v := range ns {
		nsHosts = append(nsHosts, v.Host)
	}

	asr = map[string]interface{}{
		"type": assertTypeDNSAtLeastOneRecord,
		"config": map[string]string{
			"operator": "is",
			"value":    ns[0].Host,
			"target":   "of_type_ns",
		},
	}

	return nsHosts, asr, nil
}

func lookupMX(ctx context.Context, endpoint string,
	resolver *net.Resolver) ([]string, map[string]interface{}, error) {
	var hosts []string
	asr := make(map[string]interface{})

	mx, err := resolver.LookupMX(ctx, endpoint)
	if err != nil {
		return hosts, asr, err
	}

	for _, v := range mx {
		hosts = append(hosts, v.Host)
	}

	return hosts, asr, nil
}

func lookupCNAME(ctx context.Context, endpoint string,
	resolver *net.Resolver) ([]string, map[string]interface{}, error) {
	var hosts []string
	asr := make(map[string]interface{})

	cname, err := resolver.LookupCNAME(ctx, endpoint)
	if err != nil {
		return hosts, asr, err
	}

	if cname == "" {
		return hosts, asr, errEmptyCNAMERecord
	}

	hosts = append(hosts, cname)
	asr = map[string]interface{}{
		"type": assertTypeDNSAtLeastOneRecord,
		"config": map[string]string{
			"operator": "is",
			"value":    cname,
			"target":   "of_type_cname",
		},
	}

	return hosts, asr, nil
}

func CheckDnsRequest(c SyntheticsModelCustom) {

	ctx := context.Background()
	isTestReq := c.CheckTestRequest.URL != ""
	if !isTestReq {
		processDNSRequest(ctx, c)
	} else {
		processTestDNSRequest(ctx, c)
	}
}
