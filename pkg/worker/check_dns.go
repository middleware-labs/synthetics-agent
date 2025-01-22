package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

const (
	assertTypeDNSResponseTime             = "response_time"
	assertTypeDNSEveryAvailableRecord     = "every_available_record"
	assertTypeDNSAtLeastOneRecord         = "at_least_one_record"
	assertTypeDNSDomainRegistrationExpiry = "domain_registration_expiry"
)

var (
	errEmptyTXTRecord   = errors.New("zero TXT records found")
	errEmptyNSRecord    = errors.New("zero NS records found")
	errEmptyCNAMERecord = errors.New("zero CNAME records found")
	errExpiryNotSet     = errors.New("expiration date is not set")
)

const (
	dnsRecordTypeA     = "A"
	dnsRecordTypeAAAA  = "AAAA"
	dnsRecordTypeTXT   = "TXT"
	dnsRecordTypeNS    = "NS"
	dnsRecordTypeMX    = "MX"
	dnsRecordTypeCNAME = "CNAME"
	defaultDnsServer   = "8.8.8.8"
	defaultDnsPort     = "53"
)

var recordTypeToLookupFn = map[string]func(context.Context,
	string, resolver) ([]string, map[string]interface{}, error){
	dnsRecordTypeTXT:   lookupTXT,
	dnsRecordTypeNS:    lookupNS,
	dnsRecordTypeMX:    lookupMX,
	dnsRecordTypeCNAME: lookupCNAME,
}

type resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

func lookupTXT(ctx context.Context, endpoint string,
	resolver resolver) ([]string, map[string]interface{}, error) {
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
	resolver resolver) ([]string, map[string]interface{}, error) {
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
	resolver resolver) ([]string, map[string]interface{}, error) {
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
	asr = map[string]interface{}{
		"type": assertTypeDNSAtLeastOneRecord,
		"config": map[string]string{
			"operator": "is",
			"value":    mx[0].Host,
			"target":   "of_type_mx",
		},
	}

	return hosts, asr, nil
}

func lookupCNAME(ctx context.Context, endpoint string,
	resolver resolver) ([]string, map[string]interface{}, error) {
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
	c                 SyntheticCheck
	lookup            []map[string]string
	resolver          resolver
	timers            map[string]float64
	testBody          map[string]interface{}
	assertions        []map[string]string
	attrs             pcommon.Map
	domainExpiryStore *DomainExpiryCache
}

func newDNSChecker(c SyntheticCheck) protocolChecker {
	return &dnsChecker{
		c:      c,
		lookup: make([]map[string]string, 0),
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second,
				}
				if strings.TrimSpace(c.Request.DNSServer) == "" {
					c.Request.DNSServer = defaultDnsServer
				}
				if strings.TrimSpace(c.Request.Port) == "" {
					c.Request.Port = defaultDnsPort
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
		assertions:        make([]map[string]string, 0),
		attrs:             pcommon.NewMap(),
		domainExpiryStore: GetDomainExpiryStoreInstance(),
	}
}

func (checker *dnsChecker) fillAssertions(ips []net.IP) testStatus {
	c := checker.c
	testStatus := testStatus{
		status: testStatusOK,
	}
	testStatusMsg := make([]string, 0)

	ctx := context.Background()
	for _, assert := range c.Request.Assertions.DNS.Cases {
		ck := AssertResult{}
		switch assert.Type {
		case assertTypeDNSResponseTime:
			ck.Type = assert.Type
			ck.Status = testStatusOK
			ck.Actual = fmt.Sprintf("%v", checker.timers["duration"])
			ck.Reason = AssertObj{
				Verb: "response time assertion passed",
			}
			if !assertFloat(checker.timers["duration"], assert) {
				ck.Status = testStatusFail
				ck.Reason = AssertObj{
					Verb:     "should be",
					Operator: assert.Config.Operator,
					Value:    assert.Config.Value,
				}
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got value %v)", assert.Type, assert.Config.Operator, assert.Config.Value, checker.timers["duration"]))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			}

		case assertTypeDNSEveryAvailableRecord:
			fallthrough
		case assertTypeDNSAtLeastOneRecord:
			records := make([]string, 0)

			ck.Type = strings.ReplaceAll(assert.Type, "_", " ") +
				" " + strings.ReplaceAll(assert.Config.Target, "_", " ")
			ck.Status = testStatusOK

			switch assert.Config.Target {
			case "of_type_a":
				for _, v := range ips {
					if v.To4() != nil {
						records = append(records, v.String())
					}
				}
			case "of_type_aaaa":
				for _, v := range ips {
					if v.To16() != nil && len(v) == net.IPv6len {
						records = append(records, v.String())
					}
				}
			case "of_type_cname":
				cnames, _, err := lookupCNAME(ctx, c.Endpoint, checker.resolver)
				if err != nil {
					ck.Status = testStatusFail
					ck.Actual = fmt.Sprintf("%v", err)
					ck.Reason = AssertObj{
						Verb: "Error while looking up CNAME record",
					}
					testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s %s assertion failed, error while looking up CNAME record: %s", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value, err))
					testStatus.status = testStatusError
					testStatus.msg = strings.Join(testStatusMsg, "; ")
				} else {
					records = append(records, cnames...)
				}
			case "of_type_mx":
				mxHosts, _, err := lookupMX(ctx, c.Endpoint, checker.resolver)
				if err != nil {
					ck.Status = testStatusFail
					ck.Actual = fmt.Sprintf("%v", err)
					ck.Reason = AssertObj{
						Verb: "Error while resolving MX record",
					}
					testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s %s assertion failed, error while resolving MX record: %s", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value, err))
					testStatus.status = testStatusError
					testStatus.msg = strings.Join(testStatusMsg, "; ")
				} else {
					records = append(records, mxHosts...)
				}
			case "of_type_ns":
				nsHosts, _, err := lookupNS(ctx, c.Endpoint, checker.resolver)
				if err != nil {
					ck.Status = testStatusFail
					ck.Actual = fmt.Sprintf("%v", err)
					ck.Reason = AssertObj{
						Verb: "Error while looking up NS record",
					}
					testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s %s assertion failed, error while looking up NS record: %s", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value, err))
					testStatus.status = testStatusError
					testStatus.msg = strings.Join(testStatusMsg, "; ")
				} else {
					records = append(records, nsHosts...)
				}
			case "of_type_txt":
				txtHosts, _, err := lookupTXT(ctx, c.Endpoint, checker.resolver)
				if err != nil {
					ck.Status = testStatusFail
					ck.Actual = fmt.Sprintf("%v", err)
					ck.Reason = AssertObj{
						Verb: "Error while looking up TXT record",
					}
					testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s %s assertion failed, error while looking up TXT record: %s", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value, err))
					testStatus.status = testStatusError
					testStatus.msg = strings.Join(testStatusMsg, "; ")
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
						// match = true
						// break
					}
					match = true
				}

				if ck.Actual == "" {
					ck.Actual = strings.Join(records, ",")
				}

				if pass {
					ck.Status = testStatusOK
					ck.Actual = strings.Join(records, ",")
				} else {
					ck.Status = testStatusFail
					if ck.Reason.Verb == "" {
						ck.Reason = AssertObj{
							Verb:  "assertion failed with",
							Value: strings.Join(records, ","),
						}
					}

					testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s %s assertion failed with %s", assert.Type, assert.Config.Operator, assert.Config.Target, assert.Config.Value, strings.Join(records, ",")))
					testStatus.status = testStatusFail
					testStatus.msg = strings.Join(testStatusMsg, "; ")
				}
			}

			if !every && !match {
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed with no record matched with given condition (%s)", assert.Type, assert.Config.Operator, assert.Config.Value, strings.Join(records, ",")))
				testStatus.status = testStatusFail
				testStatus.msg = strings.Join(testStatusMsg, "; ")
				ck.Status = testStatusFail
				ck.Reason = AssertObj{
					Verb:  "assertion failed with ",
					Value: strings.Join(records, ","),
				}
			}
		case assertTypeDNSDomainRegistrationExpiry:
			ck.Status = testStatusOK
			ck.Type = assert.Type
			expiry, err := checker.getDNSExpiry()
			if err != nil {
				slog.Error("error while geting domain expiry time", slog.String("domain", checker.c.Endpoint), slog.Any("err", err.Error()))
				ck.Status = testStatusError
				ck.Reason = AssertObj{
					Verb: "Error while getting domain expiration",
				}
				ck.Actual = "N/A"
				testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s failed, error while geting the domain expiry: %s, ", assert.Type, assert.Config.Operator, assert.Config.Value, err))
				testStatus.status = testStatusError
				testStatus.msg = strings.Join(testStatusMsg, "; ")
			} else {
				ck.Actual = strconv.Itoa(expiry)
				ck.Reason = AssertObj{
					Verb: "domain registration expiry assertion passed",
				}
				if !assertFloat(float64(expiry), assert) {
					ck.Status = testStatusFail
					ck.Reason = AssertObj{
						Verb:     "should be",
						Operator: assert.Config.Operator,
						Value:    assert.Config.Value,
					}
					testStatusMsg = append(testStatusMsg, fmt.Sprintf("%s %s %s assertion failed (got domain expiration %v)", assert.Type, assert.Config.Operator, assert.Config.Value, expiry))
					testStatus.status = testStatusFail
					testStatus.msg = strings.Join(testStatusMsg, "; ")
				}
			}
		}
		checker.assertions = append(checker.assertions, ck.ToMap())
	}
	return testStatus
}

func (checker *dnsChecker) processDNSResponse(testStatus *testStatus, ips []net.IP) {
	c := checker.c
	ctx := context.Background()

	isTestReq := checker.c.CheckTestRequest.URL != ""
	if !isTestReq {
		tStatus := checker.fillAssertions(ips)
		testStatus.status = tStatus.status
		testStatus.msg = tStatus.msg
		resultStr, _ := json.Marshal(checker.assertions)
		checker.attrs.PutStr("assertions", string(resultStr))

		// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
		return
	}

	asr := []map[string]interface{}{
		{
			"type": assertTypeDNSResponseTime,
			"config": map[string]string{
				"operator": "less_than",
				"value":    fmt.Sprintf("%v", percentCalc(checker.timers["duration"], 4)),
			},
		},
	}

	domainExpiry, err := checker.getDNSExpiry()
	if err != nil {
		slog.Error("error while geting domain expiry time", slog.String("domain", checker.c.Endpoint), slog.Any("err", err.Error()))
		if errors.Is(err, errExpiryNotSet) {
			checker.testBody["domainExpiryError"] = errExpiryNotSet.Error()
		} else {
			checker.testBody["domainExpiryError"] = err.Error()
		}
		checker.testBody["domainExpiry"] = ""
	} else {
		assertVal := domainExpiry
		if domainExpiry > 15 {
			assertVal = 15
		}
		asr = append(asr, map[string]interface{}{
			"type": assertTypeDNSDomainRegistrationExpiry,
			"config": map[string]string{
				"operator": "greater_than",
				"value":    fmt.Sprintf("%v", assertVal),
			},
		})

		// set the expiry in testbody
		checker.testBody["domainExpiryError"] = ""
		checker.testBody["domainExpiry"] = domainExpiry
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

			checker.lookup = append(checker.lookup, map[string]string{
				dnsRecordTypeAAAA: v.String(),
			})
		}
		if len(v) == net.IPv4len {
			checker.lookup = append(checker.lookup, map[string]string{
				dnsRecordTypeA: v.String(),
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
		records, assert, _ := lookupFn(ctx, c.Endpoint, checker.resolver)
		for _, record := range records {
			checker.lookup = append(checker.lookup,
				map[string]string{string(recordType): record})
		}
		asr = append(asr, assert)
	}

	checker.testBody["headers"] = checker.lookup
	checker.testBody["assertions"] = asr
	checker.testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
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
		checker.processDNSResponse(&testStatus, ips)
		return testStatus
	}

	ipss := []string{}
	for _, v := range ips {
		ipss = append(ipss, v.String())
	}
	checker.attrs.PutStr("resolve.ips", strings.Join(ipss, "\n"))

	checker.timers["duration"] = timeInMs(time.Since(start))
	checker.processDNSResponse(&testStatus, ips)
	return testStatus
}

func (checker *dnsChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *dnsChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *dnsChecker) getTestResponseBody() map[string]interface{} {
	return checker.testBody
}

func (checker *dnsChecker) getDNSExpiry() (int, error) {
	cacheKey := checker.c.Id
	if entry, found := checker.domainExpiryStore.GetCache(cacheKey); found {
		if time.Since(entry.Timestamp) < 24*time.Hour {
			return entry.ExpiryDays, nil
		}
	}

	rawWhoisData, err := whois.Whois(checker.c.Endpoint)
	if err != nil {
		return 0, err
	}

	// Parse the WHOIS data
	parsedData, err := whoisparser.Parse(rawWhoisData)
	if err != nil {
		return 0, err
	}

	/*
		Positive: If the domain's expiration date is in the future, indicating how much time is left until it expires.
		Zero: If the expiration date is exactly now or if it’s not set.
		Negative: If the expiration date is in the past, indicating that the domain has already expired.
	*/
	if parsedData.Domain.ExpirationDateInTime.IsZero() {
		return 0, errExpiryNotSet
	}

	expiryDuration := parsedData.Domain.ExpirationDateInTime.Sub(time.Now().Local())
	expiryDays := int(expiryDuration.Hours() / 24) // duration -> days

	// Update the cache
	checker.domainExpiryStore.AddOrUpdateCache(cacheKey, CacheEntry{
		ExpiryDays: expiryDays,
		Timestamp:  time.Now(),
	})

	slog.Info("fetched expiry", slog.String("domain", checker.c.Endpoint), slog.Int("expiryDays", expiryDays))
	return expiryDays, nil
}
