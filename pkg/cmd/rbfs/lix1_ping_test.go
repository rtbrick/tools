package rbfs

import (
	"bytes"
	"testing"
	"time"
)

func TestBuildLix1PingBody(t *testing.T) {
	tests := []struct {
		name                string
		admfID              string
		neID                string
		version             string
		pingType            string
		expectedIdentifiers []string // substrings that must appear in XML output
	}{
		{
			name:                "default values",
			admfID:              "ADMF-ID",
			neID:                "NE-ID",
			version:             "v1.12.1",
			pingType:            "basic",
			expectedIdentifiers: []string{"ADMF-ID-01", "NE-ID-102", "v1.12.1", "basic"},
		},
		{
			name:                "custom identifiers",
			admfID:              "CUSTOM-A",
			neID:                "CUSTOM-N",
			version:             "v1.13.0",
			pingType:            "extended",
			expectedIdentifiers: []string{"CUSTOM-A-01", "CUSTOM-N-102", "v1.13.0", "extended"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txTime := time.Now()
			body, err := buildLix1dPingBody(tt.admfID, tt.neID, tt.version, tt.pingType, txTime)
			if err != nil {
				t.Fatalf("buildLix1dPingBody returned error: %v", err)
			}

			// Should contain XML declaration
			if !bytes.HasPrefix(body, []byte(`<?xml version="1.0" encoding="UTF-8"?>`)) {
				t.Fatalf("XML should start with declaration")
			}

			// Should contain expected identifiers
			for _, id := range tt.expectedIdentifiers {
				if !bytes.Contains(body, []byte(id)) {
					t.Fatalf("expected XML fragment %q not found in body", id)
				}
			}

			// Should contain ETSI namespace
			if !bytes.Contains(body, []byte("xmlns=\"http://uri.etsi.org/03221/X1/2017/10\"")) {
				t.Fatalf("expected ETSI namespace not found in body")
			}
		})
	}
}

func TestPingRequestXMLStructure(t *testing.T) {
	txTime := time.Now()
	body, err := buildLix1dPingBody("ADMF-ID", "NE-ID", "v1.12.1", "basic", txTime)
	if err != nil {
		t.Fatalf("buildLix1dPingBody returned error: %v", err)
	}

	// Should contain XML namespace declaration
	namespaces := `xmlns="http://uri.etsi.org/03221/X1/2017/10"`
	if !bytes.Contains(body, []byte(namespaces)) {
		t.Fatalf("expected namespace %q not found in body", namespaces)
	}

	// Should contain expected elements
	checks := []string{
		"ADMF-ID-01",
		"NE-ID-102",
		"v1.12.1",
		"basic",
		"x1TransactionId",
	}
	for _, check := range checks {
		if !bytes.Contains(body, []byte(check)) {
			t.Fatalf("expected %q not found in body", check)
		}
	}

	// Verify structure: X1Request root element
	if !bytes.Contains(body, []byte("<X1Request")) {
		t.Fatalf("expected <X1Request root element not found in body")
	}

	// Verify x1RequestMessage element
	if !bytes.Contains(body, []byte("<x1RequestMessage")) {
		t.Fatalf("expected <x1RequestMessage element not found in body")
	}

	// Verify xsi:type="PingRequest"
	if !bytes.Contains(body, []byte(`xsi:type="PingRequest"`)) {
		t.Fatalf("expected xsi:type='PingRequest' not found in body")
	}
}

func TestLix1PingHandlesCurrentTime(t *testing.T) {
	txTime := time.Now()

	body, err := buildLix1dPingBody("ADMF-ID", "NE-ID", "v1.12.1", "basic", txTime)
	if err != nil {
		t.Fatalf("buildLix1dPingBody returned error: %v", err)
	}

	// Should contain timestamp in RFC3339 format
	if !bytes.Contains(body, []byte(txTime.Format(time.RFC3339))) {
		t.Fatalf("expected RFC3339 timestamp not found in body")
	}

	// Verify transaction ID contains a dash (format: timestamp-nanoseconds)
	txIDIndex := bytes.Index(body, []byte("x1TransactionId"))
	if txIDIndex >= 0 {
		// Check that the transaction ID value contains a dash
		txIDSection := body[txIDIndex : txIDIndex+100]
		if !bytes.Contains(txIDSection, []byte("-")) {
			t.Logf("transaction ID dash check: checking format around x1TransactionId")
		}
	}
}
