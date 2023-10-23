package worker

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

type sslChecker struct {
	c          SyntheticCheck
	timers     map[string]float64
	testBody   map[string]interface{}
	assertions []map[string]string
	attrs      pcommon.Map
}

func newSSLChecker(c SyntheticCheck) protocolChecker {
	return &sslChecker{
		c: c,
		timers: map[string]float64{
			"duration":   0,
			"dns":        0,
			"tls":        0,
			"connection": 0,
		},
		testBody: map[string]interface{}{
			"assertions": make([]map[string]interface{}, 0),
			"tookMs":     "0 ms",
			"issued_to": map[string]string{
				"Alternative Name": "N/A",
				"Common Name":      "N/A",
			},
			"issued_by": map[string]string{
				"Common Name":  "N/A",
				"Country":      "N/A",
				"Organization": "N/A",
			},
			"certificate": map[string]string{
				"Fingerprint SHA-1":   "N/A",
				"Fingerprint SHA-256": "N/A",
				"Not Valid After":     "N/A",
				"Not Valid Before":    "N/A",
			},
			"connection": map[string]string{
				"Cipher used": "",
				"Protocol":    "",
			},
		},
		assertions: make([]map[string]string, 0),
		attrs:      pcommon.NewMap(),
	}
}

func (checker *sslChecker) processSSLReponse(testStatus testStatus) {
	resultStr, _ := json.Marshal(checker.assertions)
	checker.attrs.PutStr("assertions", string(resultStr))
	c := checker.c

	if testStatus.status != testStatusOK {
		checker.assertions = append(checker.assertions, map[string]string{
			"type":   "certificate",
			"reason": "will not be checked",
			"actual": "N/A",
			"status": "FAIL",
		})
		for _, assert := range c.Request.Assertions.Ssl.Cases {
			checker.assertions = append(checker.assertions, map[string]string{
				"type":   assert.Type,
				"reason": "will not be checked",
				"actual": "N/A",
				"status": "FAIL",
			})
		}
	}

	if c.CheckTestRequest.URL == "" {
		// finishCheckRequest(c, testStatus, checker.timers, checker.attrs)
		return
	}

	checker.testBody["assertions"] = append(checker.testBody["assertions"].([]map[string]interface{}), map[string]interface{}{
		"type": "response_time",
		"config": map[string]string{
			"operator": "is",
			"value":    fmt.Sprintf("%v", checker.timers["duration"]),
		},
	})
	checker.testBody["tookMs"] = fmt.Sprintf("%.2f ms", checker.timers["duration"])
	// finishTestRequest(c, checker.testBody)

}

func getSupportedSSLVersions() (map[int]uint16, map[uint16]string) {
	versionsInt := map[int]uint16{
		30: tls.VersionSSL30,
		10: tls.VersionTLS10,
		11: tls.VersionTLS11,
		12: tls.VersionTLS12,
		13: tls.VersionTLS13,
	}
	versions := map[uint16]string{
		tls.VersionSSL30: "SSL",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	return versionsInt, versions
}

func (checker *sslChecker) fillAssertions(expiryDays int64) testStatus {

	testStatus := testStatus{
		status: testStatusOK,
	}

	c := checker.c
	for _, assert := range c.Request.Assertions.Ssl.Cases {
		assertVal := make(map[string]string)
		assertVal["type"] = assert.Type

		switch assert.Type {
		case "certificate":
			if assert.Config.Operator == "expires_in_greater_then_days" {
				assert.Config.Operator = "greater_then"
			}
			if assert.Config.Operator == "expires_in_less_then_days" {
				assert.Config.Operator = "less_then"
			}
			assertVal["reason"] = "will expire in " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value + " days"
			assertVal["actual"] = strconv.FormatInt(expiryDays, 10) + " days"

			if !assertInt(expiryDays, assert) {
				assertVal["status"] = testStatusFail
				testStatus.status = testStatusFail
				testStatus.msg = "assert failed, expiry didn't matched, certificate expire in " +
					strconv.FormatInt(expiryDays, 10) + " days"
			} else {
				assertVal["status"] = testStatusPass
			}
			checker.assertions = append(checker.assertions, assertVal)

		case "response_time":
			assertVal["reason"] = "response time is " +
				strings.ReplaceAll(assert.Config.Operator, "_", " ") +
				" " + assert.Config.Value + " ms"
			assertVal["actual"] = strconv.FormatInt(int64(checker.timers["duration"]), 10) + " ms"
			if !assertInt(int64(checker.timers["duration"]), assert) {
				testStatus.status = testStatusFail
				testStatus.msg = "assert failed, response_time didn't matched"

				assertVal["status"] = testStatusFail
			} else {
				assertVal["status"] = testStatusPass
			}

			checker.assertions = append(checker.assertions, assertVal)
		}
	}
	return testStatus
}

// check performs an SSL check on the given endpoint and returns an error if the check fails.
// It checks the DNS server, establishes a TLS connection, and verifies the SSL certificate.
// It populates various attributes and test results in the sslChecker struct.
// This function is part of the synthetics-agent package and is located in the check_ssl.go file.
func (checker *sslChecker) check() testStatus {
	start := time.Now()
	host := checker.c.Endpoint + ":" + checker.c.Request.Port

	testStatus := testStatus{
		status: testStatusOK,
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error getting system cert pool %v", err)
		return testStatus
	}

	dnsIps, _ := net.LookupIP(host)
	checker.timers["dns"] = timeInMs(time.Since(start))

	ips := make([]string, len(dnsIps))
	for _, ip := range dnsIps {
		ips = append(ips, ip.String())
	}
	checker.attrs.PutStr("check.dns_server", strings.Join(ips, ","))

	sslVersionInt, sslVersions := getSupportedSSLVersions()
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            roots,
		MinVersion:         sslVersionInt[checker.c.Request.SslMinVersion],
		MaxVersion:         sslVersionInt[13],
	})

	if err != nil {
		testStatus.status = testStatusError
		testStatus.msg = fmt.Sprintf("error connecting to server %v", err)
		checker.processSSLReponse(testStatus)
		return testStatus
	}
	defer conn.Close()

	checker.timers["connection"] = timeInMs(time.Since(start))
	ver := sslVersions[conn.ConnectionState().Version]

	tlsHandshakeStart := time.Now()

	_ = conn.Handshake()
	checker.timers["tls"] = timeInMs(time.Since(tlsHandshakeStart))
	checker.timers["duration"] = timeInMs(time.Since(start))
	cert := conn.ConnectionState().PeerCertificates[0]
	isCa := false
	cSta := "FAIL"
	for _, crt := range conn.ConnectionState().PeerCertificates {
		if crt.IsCA {
			isCa = true
			cSta = "PASS"
		}
	}

	checker.attrs.PutBool("tls.is_ca", isCa)
	checker.attrs.PutStr("check.details.fingerprint", fmt.Sprintf("%x", cert.Signature))
	checker.attrs.PutStr("check.details.not_valid_after", cert.NotAfter.Format(time.RFC3339))
	checker.attrs.PutStr("check.details.not_valid_before", cert.NotBefore.Format(time.RFC3339))
	checker.attrs.PutStr("check.details.cipher", tls.CipherSuiteName(conn.ConnectionState().CipherSuite))
	checker.attrs.PutStr("check.details.protocol", ver)
	checker.attrs.PutStr("check.details.issuer", cert.Issuer.String())
	checker.attrs.PutStr("check.details.subject", cert.Subject.String())
	checker.attrs.PutStr("check.details.is_ca", strconv.FormatBool(cert.IsCA))

	checker.testBody["issued_to"] = map[string]string{
		"Alternative Name": strings.Join(cert.DNSNames, ", "),
		"Common Name":      cert.Issuer.CommonName,
	}
	checker.testBody["issued_by"] = map[string]string{
		"Common Name":  cert.Issuer.CommonName,
		"Country Name": strings.Join(cert.Issuer.Country, ", "),
		"Organization": strings.Join(cert.Issuer.Organization, ", "),
	}

	checker.testBody["certificate"] = map[string]string{
		"Fingerprint":      cert.SignatureAlgorithm.String(),
		"Not Valid After":  cert.NotAfter.String(),
		"Not Valid Before": cert.NotBefore.String(),
	}

	checker.testBody["connection"] = map[string]string{
		"CipherSuite": tls.CipherSuiteName(conn.ConnectionState().CipherSuite),
		"Protocol":    ver,
	}

	checker.assertions = append(checker.assertions, map[string]string{
		"type":   "certificate",
		"reason": "is valid",
		"actual": fmt.Sprintf("%v", isCa),
		"status": cSta,
	})
	expiryDays := int64(cert.NotAfter.Sub(time.Now()).Hours() / 24)

	if !checker.c.Request.SslSignedCertificate && !isCa {
		testStatus.status = testStatusFail
		testStatus.msg = "assert failed, certificate is not signed by CA"

	} else {
		checker.attrs.PutInt("tls.expire_in", expiryDays)
		checker.attrs.PutStr("tls.allowed_host", strings.Join(cert.DNSNames, ", "))

		if checker.c.Request.SslServerName == "" {
			checker.c.Request.SslServerName = checker.c.Endpoint
		}
		hostMatchedErr := cert.VerifyHostname(checker.c.Request.SslServerName)
		if hostMatchedErr != nil {
			testStatus.status = testStatusFail
			testStatus.msg = fmt.Sprintf("hostname doesn't matched with %s %v",
				strings.Join(cert.DNSNames, ","), hostMatchedErr.Error())
		}

		checker.testBody["assertions"] = []map[string]interface{}{
			{
				"type": "certificate",
				"config": map[string]string{
					"operator": "expires_in_greater_then_days",
					"value":    strconv.FormatInt(expiryDays, 10),
				},
			},
		}

	}

	testStatus = checker.fillAssertions(expiryDays)
	checker.processSSLReponse(testStatus)
	return testStatus
}

func (checker *sslChecker) getTimers() map[string]float64 {
	return checker.timers
}

func (checker *sslChecker) getAttrs() pcommon.Map {
	return checker.attrs
}

func (checker *sslChecker) getTestBody() map[string]interface{} {
	return checker.testBody
}

func (checker *sslChecker) getDetails() map[string]float64 {
	return nil
}
