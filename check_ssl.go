package syntheticsagent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func CheckSslRequest(c SyntheticsModelCustom) {
	assertions := make([]map[string]string, 0)
	attrs := pcommon.NewMap()
	_start := time.Now()
	_Status := "OK"
	_Message := ""
	_host := c.Endpoint + ":" + c.Request.Port

	timers := map[string]float64{
		"duration":   0,
		"dns":        0,
		"tls":        0,
		"connection": 0,
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("root certificates error  %v", roots)
	}

	dnsIps, _ := net.LookupIP(_host)
	timers["dns"] = timeInMs(time.Since(_start))

	_ips := []string{}
	for _, ip := range dnsIps {
		_ips = append(_ips, ip.String())
	}
	attrs.PutStr("check.dns_server", strings.Join(_ips, ","))

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

	conn, err := tls.Dial("tcp", _host, &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            roots,
		MinVersion:         versionsInt[c.Request.SslMinVersion],
		MaxVersion:         versionsInt[13],
	})

	if err != nil {
		timers["duration"] = timeInMs(time.Since(_start))
		_Status = "ERROR"
		_Message = "server doesn't support ssl, " + err.Error()

		assertions = append(assertions, map[string]string{
			"type":   "certificate",
			"reason": "will not be checked",
			"actual": "N/A",
			"status": "FAIL",
		})
		for _, assert := range c.Request.Assertions.Ssl.Cases {
			assertions = append(assertions, map[string]string{
				"type":   assert.Type,
				"reason": "will not be checked",
				"actual": "N/A",
				"status": "FAIL",
			})
		}
	} else {
		timers["connection"] = timeInMs(time.Since(_start))
		ver := versions[conn.ConnectionState().Version]
		defer conn.Close()

		tlsHandshakeStart := time.Now()

		_ = conn.Handshake()
		timers["tls"] = timeInMs(time.Since(tlsHandshakeStart))
		timers["duration"] = timeInMs(time.Since(_start))

		attrs.PutStr("check.resolved_ip", conn.RemoteAddr().String())
		attrs.PutStr("tls.version", ver)

		cert := conn.ConnectionState().PeerCertificates[0]
		isCa := false
		_cSta := "FAIL"
		for _, crt := range conn.ConnectionState().PeerCertificates {
			if crt.IsCA {
				isCa = true
				_cSta = "PASS"
			}
		}
		attrs.PutBool("tls.is_ca", isCa)

		attrs.PutStr("check.details.fingerprint", fmt.Sprintf("%x", cert.Signature))
		attrs.PutStr("check.details.not_valid_after", cert.NotAfter.Format(time.RFC3339))
		attrs.PutStr("check.details.not_valid_before", cert.NotBefore.Format(time.RFC3339))
		attrs.PutStr("check.details.cipher", tls.CipherSuiteName(conn.ConnectionState().CipherSuite))
		attrs.PutStr("check.details.protocol", ver)
		attrs.PutStr("check.details.issuer", cert.Issuer.String())
		attrs.PutStr("check.details.subject", cert.Subject.String())
		attrs.PutStr("check.details.is_ca", strconv.FormatBool(cert.IsCA))

		assertions = append(assertions, map[string]string{
			"type":   "certificate",
			"reason": "is valid",
			"actual": fmt.Sprintf("%v", isCa),
			"status": _cSta,
		})

		expiryDays := int64(cert.NotAfter.Sub(time.Now()).Hours() / 24)

		if !c.Request.SslSignedCertificate && !isCa {
			_Status = "FAIL"
			_Message = "hostname contains self signed certificate"
		} else {
			attrs.PutInt("tls.expire_in", expiryDays)
			attrs.PutStr("tls.allowed_host", strings.Join(cert.DNSNames, ", "))

			if c.Request.SslServerName == "" {
				c.Request.SslServerName = c.Endpoint
			}
			hostMatchedErr := cert.VerifyHostname(c.Request.SslServerName)
			if hostMatchedErr != nil {
				_Status = "FAIL"
				_Message = fmt.Sprintf("hostname doesn't matched with %s %v", strings.Join(cert.DNSNames, ","), hostMatchedErr.Error())
			}
		}

		for _, assert := range c.Request.Assertions.Ssl.Cases {
			_artVal := make(map[string]string)
			_artVal["type"] = assert.Type

			switch assert.Type {
			case "certificate":
				if assert.Config.Operator == "expires_in_greater_then_days" {
					assert.Config.Operator = "greater_then"
				}
				if assert.Config.Operator == "expires_in_less_then_days" {
					assert.Config.Operator = "less_then"
				}
				_artVal["reason"] = "will expire in " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value + " days"
				_artVal["actual"] = strconv.FormatInt(expiryDays, 10) + " days"

				if !assertInt(expiryDays, assert) {
					_artVal["status"] = "FAIL"
					_Status = "FAIL"
					_Message = fmt.Sprintf("assert failed, expiry didn't matched, certificate expire in %d days", expiryDays)
				} else {
					_artVal["status"] = "PASS"
				}
				assertions = append(assertions, _artVal)
				break
			case "response_time":
				_artVal["reason"] = "response time is " + strings.ReplaceAll(assert.Config.Operator, "_", " ") + " " + assert.Config.Value + " ms"
				_artVal["actual"] = strconv.FormatInt(int64(timers["duration"]), 10) + " ms"
				if !assertInt(int64(timers["duration"]), assert) {
					_artVal["status"] = "FAIL"
					FinishCheckRequest(c, "FAIL", "assert failed, response_time didn't matched", timers, attrs)
					return
				} else {
					_artVal["status"] = "PASS"
				}

				assertions = append(assertions, _artVal)
				break
			}
		}
	}

	resultStr, _ := json.Marshal(assertions)
	attrs.PutStr("assertions", string(resultStr))

	FinishCheckRequest(c, _Status, _Message, timers, attrs)
}
