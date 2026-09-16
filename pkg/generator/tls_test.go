package generator

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateTLSCertificate(t *testing.T) {
	tests := []struct {
		name         string
		organization string
		hosts        []string
		wantDNS      []string
		wantIPs      []string
		wantErr      bool
		errMsg       string
	}{
		{
			name:         "dns_hosts",
			organization: "TestOrg",
			hosts:        []string{"example.com", "www.example.com"},
			wantDNS:      []string{"example.com", "www.example.com"},
		},
		{
			name:         "ip_hosts",
			organization: "TestOrg",
			hosts:        []string{"127.0.0.1", "10.0.0.1"},
			wantIPs:      []string{"127.0.0.1", "10.0.0.1"},
		},
		{
			name:         "mixed_hosts",
			organization: "TestOrg",
			hosts:        []string{"example.com", "127.0.0.1", "10.0.0.1"},
			wantDNS:      []string{"example.com"},
			wantIPs:      []string{"127.0.0.1", "10.0.0.1"},
		},
		{
			name:         "empty_hosts",
			organization: "TestOrg",
			hosts:        nil,
			wantDNS:      []string{},
			wantIPs:      []string{},
		},
		{
			name:         "invalid_cert_path",
			organization: "TestOrg",
			hosts:        []string{"example.com"},
			wantErr:      true,
			errMsg:       "write cert file",
		},
		{
			name:         "invalid_key_path",
			organization: "TestOrg",
			hosts:        []string{"example.com"},
			wantErr:      true,
			errMsg:       "write key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			certPath := fmt.Sprintf("%s/cert.pem", dir)
			keyPath := fmt.Sprintf("%s/key.pem", dir)

			if tt.name == "invalid_cert_path" {
				certPath = "/nonexistent/dir/cert.pem"
			}
			if tt.name == "invalid_key_path" {
				keyPath = "/nonexistent/dir/key.pem"
			}

			err := GenerateTLSCertificate(certPath, keyPath, tt.organization, tt.hosts)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)

			// Verify cert file exists and is readable
			certData, err := os.ReadFile(certPath)
			require.NoError(t, err)
			require.NotEmpty(t, certData)

			// Verify key file exists and is readable
			keyData, err := os.ReadFile(keyPath)
			require.NoError(t, err)
			require.NotEmpty(t, keyData)

			// Parse certificate
			certBlock, _ := pem.Decode(certData)
			require.NotNil(t, certBlock, "cert should be PEM encoded")
			require.Equal(t, "CERTIFICATE", certBlock.Type)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)

			// Verify organization
			require.Equal(t, []string{tt.organization}, cert.Subject.Organization)

			// Verify DNS names
			if len(cert.DNSNames) == 0 && len(tt.wantDNS) == 0 {
				require.Empty(t, cert.DNSNames)
			} else {
				require.Equal(t, tt.wantDNS, cert.DNSNames)
			}

			// Verify IP addresses
			var gotIPs []string
			for _, ip := range cert.IPAddresses {
				gotIPs = append(gotIPs, ip.String())
			}
			if len(gotIPs) == 0 && len(tt.wantIPs) == 0 {
				require.Empty(t, gotIPs)
			} else {
				require.Equal(t, tt.wantIPs, gotIPs)
			}

			// Verify key usage
			require.Equal(t, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, cert.KeyUsage)

			// Verify extended key usage
			require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, cert.ExtKeyUsage)

			// Parse private key
			keyBlock, _ := pem.Decode(keyData)
			require.NotNil(t, keyBlock, "key should be PEM encoded")
			require.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)

			privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			require.NoError(t, err)
			require.IsType(t, &rsa.PrivateKey{}, privKey)

			// Verify private key matches certificate public key
			require.Equal(t, &privKey.PublicKey, cert.PublicKey)

			// Verify file permissions
			certInfo, err := os.Stat(certPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())

			keyInfo, err := os.Stat(keyPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
		})
	}
}
