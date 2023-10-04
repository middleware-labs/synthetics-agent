package worker

import (
	"context"
	"net"
	"strings"
	"testing"
)

/*func TestDNSChecker_fillAssertions(t *testing.T) {
	// create a new DNS checker instance
	checker := &dnsChecker{
		c: SyntheticsModelCustom{
			SyntheticsModel: SyntheticsModel{
				Endpoint: "example.com",
				Request: SyntheticsRequestOptions{
					Assertions: AssertionsOptions{
						DNS: AssertionsCasesOptions{
							Cases: []CaseOptions{
								{
									Type: assertTypeDNSResponseTime,
									Config: struct {
										Operator string `json:"operator"`
										Target   string `json:"target"`
										Value    string `json:"value"`
									}{
										Operator: "less_than",
										Value:    "100",
									},
								},
								{
									Type: assertTypeDNSEveryAvailableRecord,
									Config: struct {
										Operator string `json:"operator"`
										Target   string `json:"target"`
										Value    string `json:"value"`
									}{
										Operator: "equals",
										Target:   "of_type_a",
										Value:    "",
									},
								},
							},
						},
					},
				},
			},
		},
		resolver: &net.Resolver{},
	}

	// create a mock list of IPs to test against
	ips := []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.3"),
	}

	// test DNS response time assertion
	testStatus := checker.fillAssertions(ips)
	if testStatus.status != testStatusOK {
		t.Fatalf("DNS response time assertion failed: %s", testStatus.msg)
	}

	// test DNS every available record assertion
	checker.c.Request.Assertions.DNS.Cases[1].Config.Target = "of_type_aaaa"
	testStatus = checker.fillAssertions(ips)
	if testStatus.status != testStatusFail {
		t.Fatalf("DNS every available record assertion should have failed")
	}

	// test DNS at least one record assertion
	checker.c.Request.Assertions.DNS.Cases[1].Type = assertTypeDNSAtLeastOneRecord
	testStatus = checker.fillAssertions(ips)
	if testStatus.status != testStatusOK {
		t.Fatalf("DNS at least one record assertion failed: %s", testStatus.msg)
	}

	// test DNS CNAME record assertion
	checker.c.Request.Assertions.DNS.Cases[1].Config.Target = "of_type_cname"
	testStatus = checker.fillAssertions(ips)
	if testStatus.status != testStatusFail {
		t.Fatalf("DNS CNAME record assertion should have failed")
	}

	// test DNS MX record assertion
	checker.c.Request.Assertions.DNS.Cases[1].Config.Target = "of_type_mx"
	testStatus = checker.fillAssertions(ips)
	if testStatus.status != testStatusFail {
		t.Fatalf("DNS MX record assertion should have failed")
	}

	// test DNS NS record assertion
	checker.c.Request.Assertions.DNS.Cases[1].Config.Target = "of_type_ns"
	testStatus = checker.fillAssertions(ips)
	if testStatus.status != testStatusFail {
		t.Fatalf("DNS NS record assertion should have failed")
	}

	// test DNS TXT record assertion
	checker.c.Request.Assertions.DNS.Cases[1].Config.Target = "of_type_txt"
	testStatus = checker.fillAssertions(ips)
	if testStatus.status != testStatusFail {
		t.Fatalf("DNS TXT record assertion should have failed")
	}
}*/

func TestLookupTXT(t *testing.T) {
	ctx := context.Background()
	resolver := &net.Resolver{}

	// Test case 1: Lookup TXT record for a valid endpoint
	endpoint := "example.com"
	txt, asr, err := lookupTXT(ctx, endpoint, resolver)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	if len(txt) == 0 {
		t.Fatalf("Expected at least one TXT record, but got none")
	}
	if asr["type"] != assertTypeDNSAtLeastOneRecord {
		t.Fatalf("Expected assertion type %v, but got %v", assertTypeDNSAtLeastOneRecord, asr["type"])
	}
	if asr["config"].(map[string]string)["operator"] != "is" {
		t.Fatalf("Expected operator %v, but got %v", "is", asr["config"].(map[string]string)["operator"])
	}
	if asr["config"].(map[string]string)["value"] != strings.Join(txt, ",") {
		t.Fatalf("Expected value %v, but got %v", strings.Join(txt, ","), asr["config"].(map[string]string)["value"])
	}
	if asr["config"].(map[string]string)["target"] != "of_type_txt" {
		t.Fatalf("Expected target %v, but got %v", "of_type_txt", asr["config"].(map[string]string)["target"])
	}

	// Test case 2: Lookup TXT record for an invalid endpoint
	endpoint = "invalid.example.com"
	txt, asr, err = lookupTXT(ctx, endpoint, resolver)
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if len(txt) != 0 {
		t.Fatalf("Expected no TXT record, but got %v", txt)
	}

	if len(asr) != 0 {
		t.Fatalf("Expected no TXT record, but got %v", asr)
	}

}
func TestLookupNS(t *testing.T) {
	ctx := context.Background()
	resolver := &net.Resolver{}

	// Test case 1: Lookup NS record for a valid endpoint
	endpoint := "example.com"
	nsHosts, asr, err := lookupNS(ctx, endpoint, resolver)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	if len(nsHosts) == 0 {
		t.Fatalf("Expected at least one NS record, but got none")
	}
	if asr["type"] != assertTypeDNSAtLeastOneRecord {
		t.Fatalf("Expected assertion type %v, but got %v", assertTypeDNSAtLeastOneRecord, asr["type"])
	}
	if asr["config"].(map[string]string)["operator"] != "is" {
		t.Fatalf("Expected operator %v, but got %v", "is", asr["config"].(map[string]string)["operator"])
	}
	if asr["config"].(map[string]string)["value"] != nsHosts[0] {
		t.Fatalf("Expected value %v, but got %v", nsHosts[0], asr["config"].(map[string]string)["value"])
	}
	if asr["config"].(map[string]string)["target"] != "of_type_ns" {
		t.Fatalf("Expected target %v, but got %v", "of_type_ns", asr["config"].(map[string]string)["target"])
	}

	// Test case 2: Lookup NS record for an invalid endpoint
	endpoint = "invalid.example.com"
	nsHosts, asr, err = lookupNS(ctx, endpoint, resolver)
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if len(nsHosts) != 0 {
		t.Fatalf("Expected no NS record, but got %v", nsHosts)
	}

	if len(asr) != 0 {
		t.Fatalf("Expected no NS assertions, but got %v", asr)
	}
}

func TestLookupMX(t *testing.T) {
	ctx := context.Background()
	resolver := &net.Resolver{}

	// Test case 1: Lookup MX record for a valid endpoint
	endpoint := "middleware.io"
	hosts, asr, err := lookupMX(ctx, endpoint, resolver)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	if len(hosts) == 0 {
		t.Fatalf("Expected at least one MX record, but got none")
	}

	if len(asr) != 0 {
		t.Fatalf("Expected no MX assertions, but got %v", asr)
	}
	// Test case 2: Lookup MX record for an invalid endpoint
	endpoint = "invalid.example.com"
	hosts, asr, err = lookupMX(ctx, endpoint, resolver)
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if len(hosts) != 0 {
		t.Fatalf("Expected no NS record, but got %v", hosts)
	}

	if len(asr) != 0 {
		t.Fatalf("Expected no MX assertions, but got %v", asr)
	}
}
func TestLookupCNAME(t *testing.T) {
	ctx := context.Background()
	resolver := &net.Resolver{}

	// Test case 1: Lookup CNAME record for a valid endpoint
	endpoint := "example.com"
	cname, asr, err := lookupCNAME(ctx, endpoint, resolver)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	if len(cname) == 0 {
		t.Fatalf("Expected at least one CNAME record, but got none")
	}

	if asr["type"] != assertTypeDNSAtLeastOneRecord {
		t.Fatalf("Expected assertion type %v, but got %v", assertTypeDNSAtLeastOneRecord, asr["type"])
	}
	if asr["config"].(map[string]string)["operator"] != "is" {
		t.Fatalf("Expected operator %v, but got %v", "is", asr["config"].(map[string]string)["operator"])
	}
	if asr["config"].(map[string]string)["value"] != cname[0] {
		t.Fatalf("Expected value %v, but got %v", "", asr["config"].(map[string]string)["value"])
	}
	if asr["config"].(map[string]string)["target"] != "of_type_cname" {
		t.Fatalf("Expected target %v, but got %v", "of_type_cname", asr["config"].(map[string]string)["target"])
	}

	// Test case 2: Lookup CNAME record for an invalid endpoint
	endpoint = "invalid.example.com"
	cname, asr, err = lookupCNAME(ctx, endpoint, resolver)
	if err == nil {
		t.Fatalf("Expected error, but got none")
	}
	if len(cname) != 0 {
		t.Fatalf("Expected no CNAME record, but got %v", cname)
	}

	if len(asr) != 0 {
		t.Fatalf("Expected no CNAME assertions, but got %v", asr)
	}
}
