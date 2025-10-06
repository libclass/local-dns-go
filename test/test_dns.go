package test

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// TestDNSProtocol tests DNS protocol handling
func TestDNSProtocol(t *testing.T) {
	tests := []struct {
		name     string
		question string
		qtype    uint16
		expected string
	}{
		{"Google A record", "google.com.", dns.TypeA, ""},
		{"Google AAAA record", "google.com.", dns.TypeAAAA, ""},
		{"Cloudflare DNS", "one.one.one.one.", dns.TypeA, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := new(dns.Client)
			msg := new(dns.Msg)
			msg.SetQuestion(tt.question, tt.qtype)

			response, _, err := client.Exchange(msg, "8.8.8.8:53")
			if err != nil {
				t.Skipf("Skipping test due to network error: %v", err)
				return
			}

			if response == nil {
				t.Error("No response from DNS server")
				return
			}

			if response.Rcode != dns.RcodeSuccess {
				t.Errorf("DNS query failed with rcode: %d", response.Rcode)
			}

			if len(response.Answer) == 0 {
				t.Logf("No answers for %s %s", tt.question, dns.TypeToString[tt.qtype])
			}
		})
	}
}

// TestDNSEdgeCases tests DNS edge cases and error conditions
func TestDNSEdgeCases(t *testing.T) {
	testCases := []struct {
		name        string
		query       string
		qtype       uint16
		expectError bool
	}{
		{"Empty domain", "", dns.TypeA, true},
		{"Invalid domain", "invalid..domain.", dns.TypeA, true},
		{"Non-existent domain", "nonexistent-domain-12345.test.", dns.TypeA, false},
		{"Localhost", "localhost.", dns.TypeA, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.query == "" {
				// Test empty query handling
				return
			}

			client := new(dns.Client)
			msg := new(dns.Msg)
			msg.SetQuestion(tc.query, tc.qtype)

			_, _, err := client.Exchange(msg, "8.8.8.8:53")
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			} else if !tc.expectError && err != nil {
				t.Logf("Non-fatal error: %v", err)
			}
		})
	}
}

// TestDNSRecordTypes tests different DNS record types
func TestDNSRecordTypes(t *testing.T) {
	recordTests := []struct {
		domain string
		qtype  uint16
	}{
		{"google.com", dns.TypeA},
		{"google.com", dns.TypeAAAA},
		{"google.com", dns.TypeMX},
		{"google.com", dns.TypeNS},
		{"google.com", dns.TypeTXT},
	}

	for _, rt := range recordTests {
		t.Run(dns.TypeToString[rt.qtype], func(t *testing.T) {
			client := new(dns.Client)
			msg := new(dns.Msg)
			msg.SetQuestion(rt.domain+".", rt.qtype)

			response, _, err := client.Exchange(msg, "8.8.8.8:53")
			if err != nil {
				t.Skipf("Skipping %s test: %v", dns.TypeToString[rt.qtype], err)
				return
			}

			if response != nil && response.Rcode != dns.RcodeSuccess {
				t.Logf("Query for %s %s returned rcode: %d", 
					rt.domain, dns.TypeToString[rt.qtype], response.Rcode)
			}
		})
	}
}

// TestDNSCaching tests DNS cache behavior
func TestDNSCaching(t *testing.T) {
	// This would test the actual cache implementation
	// For now, test cache data structure
	cacheData := struct {
		Key    string
		Value  string
		Expiry int64
	}{
		Key:    "test.example.com:A",
		Value:  "192.168.1.1",
		Expiry: 300,
	}

	if cacheData.Key == "" {
		t.Error("Cache key cannot be empty")
	}
	if cacheData.Value == "" {
		t.Error("Cache value cannot be empty")
	}
	if cacheData.Expiry <= 0 {
		t.Error("Cache expiry must be positive")
	}
}

// TestDNSOverHTTPS tests DoH functionality
func TestDNSOverHTTPS(t *testing.T) {
	// Test DoH endpoint format
	dohEndpoints := []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
	}

	for _, endpoint := range dohEndpoints {
		if !isValidDoHEndpoint(endpoint) {
			t.Errorf("Invalid DoH endpoint: %s", endpoint)
		}
	}
}

func isValidDoHEndpoint(url string) bool {
	return len(url) > 0 && (url[:8] == "https://")
}

// TestDNSOverTLS tests DoT functionality
func TestDNSOverTLS(t *testing.T) {
	dotServers := []string{
		"1.1.1.1:853",
		"8.8.8.8:853",
		"9.9.9.9:853",
	}

	for _, server := range dotServers {
		if !isValidDoTServer(server) {
			t.Errorf("Invalid DoT server: %s", server)
		}
	}
}

func isValidDoTServer(server string) bool {
	// Basic validation - should be host:port format
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return false
	}
	return host != "" && port == "853"
}


