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

const (
	dnsRecordTypeA     = "A"
	dnsRecordTypeAAAA  = "AAAA"
	dnsRecordTypeTXT   = "TXT"
	dnsRecordTypeNS    = "NS"
	dnsRecordTypeMX    = "MX"
	dnsRecordTypeCNAME = "CNAME"
)

var recordTypeToLookupFn = map[string]func(context.Context,
	string, *net.Resolver) ([]string, map[string]interface{}, error){
	dnsRecordTypeTXT:   lookupTXT,
	dnsRecordTypeNS:    lookupNS,
	dnsRecordTypeMX:    lookupMX,
	dnsRecordTypeCNAME: lookupCNAME,
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

	// This was not there in the old code. Adding it here and
	// commenting it out. Why are assertions not needed for MX records?
	/*asr = map[string]interface{}{
		"type": assertTypeDNSAtLeastOneRecord,
		"config": map[string]string{
			"operator": "is",
			"value":    mx[0].Host,
			"target":   "of_type_mx",
		},
	}*/

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

type dnsChecker struct {
	c          SyntheticsModelCustom
	lookup     []map[string]string
	resolver   *net.Resolver
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
}

func newDNSChecker(c SyntheticsModelCustom) protocolChecker {
	return &dnsChecker{
		c:      c,
		lookup: make([]map[string]string, 0),
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second,
				}
				return d.DialContext(ctx, network, c.Request.DNSServer+":"+c.Request.Port)
			},
		},
		timers: map[string]float64{
			"duration": 0,
			"dns":      0,
		},
		testBody: map[string]interface{}{
			"assertions": make([]map[string]interface{}, 0),
			"tookMs":     "0 ms",
		},
		assertions: make([]map[string]string, 0),
		attrs:      pcommon.NewMap(),
	}
}

func (checker *dnsChecker) fillAssertions(ips []net.IP) testStatus {
	c := checker.c
	testStatus := testStatus{
		status: testStatusOK,
	}

	ctx := context.Background()
	for _, assert := range c.Request.Assertions.DNS.Cases {

		if testStatus.status == testStatusFail {
			checker.assertions = append(checker.assertions, map[string]string{
				"type":   assert.Type,
				"reason": testStatus.msg,
				"actual": "N/A",
				"status": testStatusFail,
			})
			continue
		}

		switch assert.Type {
		case assertTypeDNSResponseTime:
			ck := make(map[string]string)
			ck["type"] = assert.Type
			ck["status"] = testStatusOK
			ck["actual"] = fmt.Sprintf("%v", checker.timers["duration"])
			ck["reason"] = "response time assertion passed"
			if !assertInt(int64(checker.timers["duration"]), assert) {
				ck["status"] = testStatusFail
				ck["reason"] = "response time assertion failed"
			}
			ck["status"] = testStatusOK
			checker.assertions = append(checker.assertions, ck)

		case assertTypeDNSEveryAvailableRecord:
			fallthrough
		case assertTypeDNSAtLeastOneRecord:
			records := make([]string, 0)

			ck := make(map[string]string)
			ck["type"] = strings.ReplaceAll(assert.Type, "_", " ") +
				" " + strings.ReplaceAll(assert.Config.Target, "_", " ")
			ck["status"] = testStatusOK

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
				cnames, _, err := lookupCNAME(ctx, c.Endpoint, checker.resolver)
				if err != nil {
					ck["reason"] = "Error while looking up CNAME record"
					ck["status"] = testStatusFail
					ck["actual"] = fmt.Sprintf("%v", err)
				} else {
					records = append(records, cnames...)
				}
			case "of_type_mx":
				mxHosts, _, err := lookupMX(ctx, c.Endpoint, checker.resolver)
				if err != nil {
					ck["reason"] = "Error while resolving MX record"
					ck["status"] = testStatusFail
					ck["actual"] = fmt.Sprintf("%v", err)
				} else {
					records = append(records, mxHosts...)
				}
			case "of_type_ns":
				nsHosts, _, err := lookupNS(ctx, c.Endpoint, checker.resolver)
				if err != nil {
					ck["reason"] = "Error while looking up NS record"
					ck["status"] = testStatusFail
					ck["actual"] = fmt.Sprintf("%v", err)
				} else {
					records = append(records, nsHosts...)
				}
			case "of_type_txt":
				txtHosts, _, err := lookupTXT(ctx, c.Endpoint, checker.resolver)
				if err != nil {
					ck["status"] = testStatusFail
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
							//finishCheckRequest(c, "FAIL", "ip a record match failed with "+rec, timers, attrs)
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
					ck["status"] = testStatusOK
					ck["actual"] = strings.Join(records, ",")
				} else {
					ck["status"] = testStatusFail
					if ck["reason"] == "" {
						ck["reason"] = "assertion failed"
					}

					testStatus.status = testStatusFail
					testStatus.msg = "assertion failed with " + strings.Join(records, ",")
				}
			}

			if !every && !match {
				testStatus.status = testStatusFail
				testStatus.msg = "no record matched with given condition " + strings.Join(records, ",")
			}
		}
	}
	return testStatus
}
func (checker *dnsChecker) processDNSResponse(testStatus testStatus, ips []net.IP) {

	c := checker.c
	ctx := context.Background()

	isTestReq := checker.c.CheckTestRequest.URL != ""
	if !isTestReq {
		testStatus = checker.fillAssertions(ips)
		resultStr, _ := json.Marshal(checker.assertions)
		checker.attrs.PutStr("assertions", string(resultStr))

		// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
		return
	}

	testBody := make(map[string]interface{}, 0)
	asr := []map[string]interface{}{
		{
			"type": "response_time",
			"config": map[string]string{
				"operator": "is",
				"value":    fmt.Sprintf("%v", checker.timers["duration"]),
			},
		},
	}

	for _, v := range ips {
		if len(v) == net.IPv6len {
			asr = append(asr, map[string]interface{}{
				"type": "at_least_one_record",
				"config": map[string]string{
					"operator": "is",
					"value":    v.String(),
					"target":   "of_type_aaaa",
				},
			})

			checker.lookup = append(checker.lookup, map[string]string{
				dnsRecordTypeAAAA: v.String(),
			})
		}
		if len(v) == net.IPv4len {
			checker.lookup = append(checker.lookup, map[string]string{
				dnsRecordTypeA: v.String(),
			})

			asr = append(asr, map[string]interface{}{
				"type": "at_least_one_record",
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
		records, assert, _ := lookupFn(ctx, c.Endpoint, checker.resolver)
		for _, record := range records {
			checker.lookup = append(checker.lookup,
				map[string]string{string(recordType): record})
		}
		asr = append(asr, assert)
	}

	testBody["headers"] = checker.lookup
	testBody["assertions"] = asr
	testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
	// finishTestRequest(c, testBody)
}

func (checker *dnsChecker) check() testStatus {
	c := checker.c
	start := time.Now()
	testStatus := testStatus{
		status: testStatusOK,
		msg:    "",
	}

	ctx := context.Background()

	ips, err := checker.resolver.LookupIP(ctx, "ip", c.Endpoint)
	if err != nil {
		testStatus.status = testStatusFail
		testStatus.msg = fmt.Sprintf("error resolving dns: %v", err)
		checker.timers["duration"] = timeInMs(time.Since(start))
		checker.processDNSResponse(testStatus, ips)
		return testStatus
	}

	ipss := []string{}
	for _, v := range ips {
		ipss = append(ipss, v.String())
	}
	checker.attrs.PutStr("resolve.ips", strings.Join(ipss, "\n"))

	checker.timers["duration"] = timeInMs(time.Since(start))
	return testStatus
}

func (checker *dnsChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *dnsChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *dnsChecker) getTestBody() map[string]interface{} {
	return checker.testBody
}

func (checker *dnsChecker) getDetails() map[string]float64 {
	return nil
}
