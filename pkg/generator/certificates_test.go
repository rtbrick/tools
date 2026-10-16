package generator

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerateCA(t *testing.T) {
	tests := []struct {
		name         string
		subject      pkix.Name
		valid        time.Duration
		wantCert     string
		wantKey      string
		wantErr      bool
		errMsg       string
		wantIsCA     bool
		wantKeyUsage x509.KeyUsage
	}{
		{
			name:         "valid_ca_defaults",
			subject:      pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:        10 * 365 * 24 * time.Hour,
			wantCert:     "testdata/ca.crt",
			wantKey:      "testdata/ca.key",
			wantIsCA:     true,
			wantKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
		{
			name:         "valid_ca_short_duration",
			subject:      pkix.Name{CommonName: "Short CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:        1 * time.Hour,
			wantCert:     "testdata/ca.crt",
			wantKey:      "testdata/ca.key",
			wantIsCA:     true,
			wantKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
		{
			name:         "valid_ca_multiple_ous",
			subject:      pkix.Name{CommonName: "Multi OU CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng", "Security"}},
			valid:        5 * 365 * 24 * time.Hour,
			wantCert:     "testdata/ca.crt",
			wantKey:      "testdata/ca.key",
			wantIsCA:     true,
			wantKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
		{
			name:     "invalid_cert_path",
			subject:  pkix.Name{CommonName: "Bad Path CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			wantCert: "/nonexistent/dir/ca.crt",
			wantKey:  "testdata/ca.key",
			wantErr:  true,
			errMsg:   "write certificate file",
		},
		{
			name:     "invalid_key_path",
			subject:  pkix.Name{CommonName: "Bad Path CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			wantCert: "testdata/ca.crt",
			wantKey:  "/nonexistent/dir/ca.key",
			wantErr:  true,
			errMsg:   "write private key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				_ = os.Remove(tt.wantCert)
				_ = os.Remove(tt.wantKey)
			})

			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}

			result, err := GenerateCA(tt.wantCert, tt.wantKey, tt.subject, tt.valid)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.Certificate)
			require.NotNil(t, result.PrivateKey)
			require.FileExists(t, tt.wantCert)
			require.FileExists(t, tt.wantKey)

			// Verify certificate file exists
			certData, err := os.ReadFile(tt.wantCert)
			require.NoError(t, err)
			require.NotEmpty(t, certData)

			// Verify key file exists
			keyData, err := os.ReadFile(tt.wantKey)
			require.NoError(t, err)
			require.NotEmpty(t, keyData)

			// Parse and verify certificate
			certBlock, _ := pem.Decode(certData)
			require.NotNil(t, certBlock)
			require.Equal(t, "CERTIFICATE", certBlock.Type)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)

			// Verify CA properties
			require.Equal(t, tt.wantIsCA, cert.IsCA)
			require.Equal(t, tt.wantKeyUsage, cert.KeyUsage)
			require.Equal(t, tt.subject.CommonName, cert.Subject.CommonName)
			require.Equal(t, tt.subject.Organization, cert.Subject.Organization)
			require.Equal(t, tt.subject.OrganizationalUnit, cert.Subject.OrganizationalUnit)
			require.NotNil(t, cert.SubjectKeyId)

			// Verify the self-signed root carries an AKI equal to its SKI
			require.Equal(t, cert.SubjectKeyId, cert.AuthorityKeyId)

			// Verify key usage includes client and server auth
			require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
			require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

			// Verify basic constraints
			require.True(t, cert.BasicConstraintsValid)

			// Verify validity
			require.WithinDuration(t, time.Now(), cert.NotBefore, time.Minute)
			require.WithinDuration(t, time.Now().Add(tt.valid), cert.NotAfter, time.Minute)

			// Parse and verify private key
			keyBlock, _ := pem.Decode(keyData)
			require.NotNil(t, keyBlock)
			require.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)

			privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			require.NoError(t, err)
			require.IsType(t, &rsa.PrivateKey{}, privKey)

			// Verify private key matches certificate public key
			require.Equal(t, &privKey.PublicKey, cert.PublicKey)

			// Verify file permissions
			certInfo, err := os.Stat(tt.wantCert)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())

			keyInfo, err := os.Stat(tt.wantKey)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
		})
	}
}

func TestGenerateCert(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a CA first for signing
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	ca, err := GenerateCA("testdata/ca.crt", "testdata/ca.key", caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Remove("testdata/ca.crt")
		_ = os.Remove("testdata/ca.key")
	})

	tests := []struct {
		name     string
		subject  pkix.Name
		valid    time.Duration
		wantCert string
		wantKey  string
		wantErr  bool
		errMsg   string
		wantDNS  []string
		wantIsCA bool
	}{
		{
			name:     "valid_cert",
			subject:  pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			wantCert: "testdata/cert.crt",
			wantKey:  "testdata/cert.key",
			wantDNS:  []string{"localhost"},
			wantIsCA: false,
		},
		{
			name:     "valid_cert_short_duration",
			subject:  pkix.Name{CommonName: "Short Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    1 * time.Hour,
			wantCert: "testdata/cert.crt",
			wantKey:  "testdata/cert.key",
			wantDNS:  []string{"localhost"},
			wantIsCA: false,
		},
		{
			name:     "valid_cert_multiple_ous",
			subject:  pkix.Name{CommonName: "Multi OU Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng", "Security"}},
			valid:    5 * 365 * 24 * time.Hour,
			wantCert: "testdata/cert.crt",
			wantKey:  "testdata/cert.key",
			wantDNS:  []string{"localhost"},
			wantIsCA: false,
		},
		{
			name:     "invalid_cert_path",
			subject:  pkix.Name{CommonName: "Bad Path", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			wantCert: "/nonexistent/dir/cert.crt",
			wantKey:  "testdata/cert.key",
			wantErr:  true,
			errMsg:   "write certificate file",
		},
		{
			name:     "invalid_key_path",
			subject:  pkix.Name{CommonName: "Bad Path", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			wantCert: "testdata/cert.crt",
			wantKey:  "/nonexistent/dir/cert.key",
			wantErr:  true,
			errMsg:   "write private key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				_ = os.Remove(tt.wantCert)
				_ = os.Remove(tt.wantKey)
			})

			err := GenerateCert(ca.Certificate, ca.PrivateKey, tt.wantCert, tt.wantKey, tt.subject, tt.valid)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.FileExists(t, tt.wantCert)
			require.FileExists(t, tt.wantKey)

			// Verify cert file exists
			certData, err := os.ReadFile(tt.wantCert)
			require.NoError(t, err)
			require.NotEmpty(t, certData)

			// Verify key file exists
			keyData, err := os.ReadFile(tt.wantKey)
			require.NoError(t, err)
			require.NotEmpty(t, keyData)

			// Parse and verify certificate
			certBlock, _ := pem.Decode(certData)
			require.NotNil(t, certBlock)
			require.Equal(t, "CERTIFICATE", certBlock.Type)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)

			// Verify certificate properties
			require.Equal(t, tt.wantIsCA, cert.IsCA)
			require.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage)
			require.Equal(t, tt.subject.CommonName, cert.Subject.CommonName)
			require.Equal(t, tt.subject.Organization, cert.Subject.Organization)
			require.Equal(t, tt.subject.OrganizationalUnit, cert.Subject.OrganizationalUnit)
			require.NotNil(t, cert.SubjectKeyId)

			// Verify DNS names
			require.Equal(t, tt.wantDNS, cert.DNSNames)

			// Verify key usage includes client and server auth
			require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
			require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

			// Verify validity
			require.WithinDuration(t, time.Now(), cert.NotBefore, time.Minute)
			require.WithinDuration(t, time.Now().Add(tt.valid), cert.NotAfter, time.Minute)

			// Verify certificate is signed by CA
			require.Equal(t, ca.Certificate.Subject.CommonName, cert.Issuer.CommonName)

			// Parse and verify private key
			keyBlock, _ := pem.Decode(keyData)
			require.NotNil(t, keyBlock)
			require.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)

			privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			require.NoError(t, err)
			require.IsType(t, &rsa.PrivateKey{}, privKey)

			// Verify private key matches certificate public key
			require.Equal(t, &privKey.PublicKey, cert.PublicKey)

			// Verify file permissions
			certInfo, err := os.Stat(tt.wantCert)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())

			keyInfo, err := os.Stat(tt.wantKey)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
		})
	}
}

func TestGenerateCertOptions(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	_, err := GenerateCA("testdata/opt-ca.crt", "testdata/opt-ca.key", caSubject, 24*time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Remove("testdata/opt-ca.crt")
		_ = os.Remove("testdata/opt-ca.key")
	})
	// Load the CA from disk, the certificate returned by GenerateCA is only
	// the template and can't be added to a CertPool for verification.
	ca, err := LoadCA("testdata/opt-ca.crt", "testdata/opt-ca.key")
	require.NoError(t, err)

	oidUID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	subject := pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}

	tests := []struct {
		name     string
		options  []CertOption
		wantUID  string
		wantDNS  []string
		wantIPs  []net.IP
		wantURIs []string
	}{
		{
			name:    "no_options_keeps_localhost",
			wantDNS: []string{"localhost"},
		},
		{
			name:    "user_id",
			options: []CertOption{UserID("alice")},
			wantUID: "alice",
			wantDNS: []string{"localhost"},
		},
		{
			name:    "empty_user_id_is_ignored",
			options: []CertOption{UserID("")},
			wantDNS: []string{"localhost"},
		},
		{
			name:    "empty_dns_names_keeps_localhost",
			options: []CertOption{DNSNames()},
			wantDNS: []string{"localhost"},
		},
		{
			name:    "single_dns_name",
			options: []CertOption{DNSNames("x1.example.com")},
			wantDNS: []string{"x1.example.com"},
		},
		{
			name:    "multiple_dns_names",
			options: []CertOption{DNSNames("ne1.example.com", "ne2.example.com", "*.lab.example.com")},
			wantDNS: []string{"ne1.example.com", "ne2.example.com", "*.lab.example.com"},
		},
		{
			name:    "single_ipv4_address",
			options: []CertOption{IPAddresses(net.ParseIP("192.0.2.10"))},
			wantDNS: []string{"localhost"},
			wantIPs: []net.IP{net.ParseIP("192.0.2.10")},
		},
		{
			name:    "multiple_ipv4_and_ipv6_addresses",
			options: []CertOption{IPAddresses(net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.20"), net.ParseIP("2001:db8::10"))},
			wantDNS: []string{"localhost"},
			wantIPs: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.20"), net.ParseIP("2001:db8::10")},
		},
		{
			name:     "etsi_x1_binding_identifier",
			options:  []CertOption{ETSIX1BindingIdentifier("ADMF", "admf-01")},
			wantDNS:  []string{"localhost"},
			wantURIs: []string{"urn:etsi:li:103221-1:cert-binding:ADMF:admf-01"},
		},
		{
			name:    "etsi_x1_binding_without_identifier_is_ignored",
			options: []CertOption{ETSIX1BindingIdentifier("ADMF", "")},
			wantDNS: []string{"localhost"},
		},
		{
			name: "all_options_combined",
			options: []CertOption{
				UserID("alice"),
				DNSNames("ne1.example.com", "ne2.example.com"),
				IPAddresses(net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")),
				ETSIX1BindingIdentifier("NE", "ne-01"),
			},
			wantUID:  "alice",
			wantDNS:  []string{"ne1.example.com", "ne2.example.com"},
			wantIPs:  []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")},
			wantURIs: []string{"urn:etsi:li:103221-1:cert-binding:NE:ne-01"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPath := "testdata/opt-cert.crt"
			keyPath := "testdata/opt-cert.key"
			t.Cleanup(func() {
				_ = os.Remove(certPath)
				_ = os.Remove(keyPath)
			})

			err := GenerateCert(ca.Certificate, ca.PrivateKey, certPath, keyPath, subject, time.Hour, tt.options...)
			require.NoError(t, err)

			certData, err := os.ReadFile(certPath)
			require.NoError(t, err)
			cert, err := PEMToCertificate(certData)
			require.NoError(t, err)

			// Verify the standard subject fields are not affected by the options
			require.Equal(t, subject.CommonName, cert.Subject.CommonName)
			require.Equal(t, subject.Organization, cert.Subject.Organization)
			require.Equal(t, subject.OrganizationalUnit, cert.Subject.OrganizationalUnit)

			// Verify UID attribute in the subject DN
			var uids []string
			for _, n := range cert.Subject.Names {
				if n.Type.Equal(oidUID) {
					uids = append(uids, n.Value.(string))
				}
			}
			if tt.wantUID == "" {
				require.Empty(t, uids)
			} else {
				require.Equal(t, []string{tt.wantUID}, uids)
			}

			// Verify DNS names
			require.Equal(t, tt.wantDNS, cert.DNSNames)

			// Verify IP addresses
			require.Len(t, cert.IPAddresses, len(tt.wantIPs))
			for i, ip := range tt.wantIPs {
				require.True(t, ip.Equal(cert.IPAddresses[i]), "IP %d: want %s, got %s", i, ip, cert.IPAddresses[i])
			}

			// Verify URI SANs
			var uris []string
			for _, u := range cert.URIs {
				uris = append(uris, u.String())
			}
			require.Equal(t, tt.wantURIs, uris)

			// Verify SKI is derived from the certificate's own key and AKI
			// matches the CA's SKI
			wantSKI, err := subjectKeyID(cert.PublicKey)
			require.NoError(t, err)
			require.Equal(t, wantSKI, cert.SubjectKeyId)
			require.Equal(t, ca.Certificate.SubjectKeyId, cert.AuthorityKeyId)

			// Verify the certificate still chains to the CA
			roots := x509.NewCertPool()
			roots.AddCert(ca.Certificate)
			_, err = cert.Verify(x509.VerifyOptions{
				Roots:     roots,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})
			require.NoError(t, err)
		})
	}
}

func TestGenerateCert_CAWithoutSKI(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	_, err := GenerateCA("testdata/noski-ca.crt", "testdata/noski-ca.key", caSubject, time.Hour)
	require.NoError(t, err)
	ca, err := LoadCA("testdata/noski-ca.crt", "testdata/noski-ca.key")
	require.NoError(t, err)

	// Go always adds an SKI to the CA certificates it creates, so simulate a
	// CA from another tool lacking the SKI extension by clearing it
	ca.Certificate.SubjectKeyId = nil

	certPath := "testdata/noski-cert.crt"
	keyPath := "testdata/noski-cert.key"
	t.Cleanup(func() {
		for _, f := range []string{"testdata/noski-ca.crt", "testdata/noski-ca.key", certPath, keyPath} {
			_ = os.Remove(f)
		}
	})

	subject := pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(ca.Certificate, ca.PrivateKey, certPath, keyPath, subject, time.Hour)
	require.NoError(t, err)

	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	cert, err := PEMToCertificate(certData)
	require.NoError(t, err)

	// Verify the AKI is derived from the CA's public key
	wantAKI, err := subjectKeyID(&ca.PrivateKey.PublicKey)
	require.NoError(t, err)
	require.Equal(t, wantAKI, cert.AuthorityKeyId)

	// Verify the SKI is derived from the certificate's own key
	wantSKI, err := subjectKeyID(cert.PublicKey)
	require.NoError(t, err)
	require.Equal(t, wantSKI, cert.SubjectKeyId)
}

func TestLoadCA(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a valid CA for testing
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	validCA, err := GenerateCA("testdata/ca.crt", "testdata/ca.key", caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Remove("testdata/ca.crt")
		_ = os.Remove("testdata/ca.key")
	})

	// Create invalid PEM files
	require.NoError(t, os.WriteFile("testdata/bad.crt", []byte("not a pem"), 0o644))
	require.NoError(t, os.WriteFile("testdata/bad.key", []byte("not a pem"), 0o644))
	t.Cleanup(func() {
		_ = os.Remove("testdata/bad.crt")
		_ = os.Remove("testdata/bad.key")
	})

	tests := []struct {
		name     string
		certPath string
		keyPath  string
		wantErr  bool
		errMsg   string
		wantCN   string
	}{
		{
			name:     "valid_ca",
			certPath: "testdata/ca.crt",
			keyPath:  "testdata/ca.key",
			wantCN:   "Test CA",
		},
		{
			name:     "missing_cert_file",
			certPath: "testdata/nonexistent.crt",
			keyPath:  "testdata/ca.key",
			wantErr:  true,
			errMsg:   "read CA certificate",
		},
		{
			name:     "missing_key_file",
			certPath: "testdata/ca.crt",
			keyPath:  "testdata/nonexistent.key",
			wantErr:  true,
			errMsg:   "read CA private key",
		},
		{
			name:     "invalid_cert_pem",
			certPath: "testdata/bad.crt",
			keyPath:  "testdata/ca.key",
			wantErr:  true,
			errMsg:   "parse CA certificate",
		},
		{
			name:     "invalid_key_pem",
			certPath: "testdata/ca.crt",
			keyPath:  "testdata/bad.key",
			wantErr:  true,
			errMsg:   "parse CA private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := LoadCA(tt.certPath, tt.keyPath)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.Certificate)
			require.NotNil(t, result.PrivateKey)

			// Verify certificate properties
			require.Equal(t, tt.wantCN, result.Certificate.Subject.CommonName)
			require.Equal(t, validCA.Certificate.Subject.CommonName, result.Certificate.Subject.CommonName)

			// Verify private key matches certificate
			require.Equal(t, &result.PrivateKey.PublicKey, result.Certificate.PublicKey)
		})
	}
}

func TestVerifyCertificate(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a CA and certificate for testing
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	ca, err := GenerateCA("testdata/ca.crt", "testdata/ca.key", caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	certSubject := pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(ca.Certificate, ca.PrivateKey, "testdata/cert.crt", "testdata/cert.key", certSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	// Generate another CA and certificate (not signed by the first CA)
	otherCASubject := pkix.Name{CommonName: "Other CA", Organization: []string{"OtherOrg"}, OrganizationalUnit: []string{"Eng"}}
	otherCA, err := GenerateCA("testdata/other-ca.crt", "testdata/other-ca.key", otherCASubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	otherCertSubject := pkix.Name{CommonName: "Other Device", Organization: []string{"OtherOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(otherCA.Certificate, otherCA.PrivateKey, "testdata/other-cert.crt", "testdata/other-cert.key", otherCertSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	t.Cleanup(func() {
		for _, f := range []string{
			"testdata/ca.crt", "testdata/ca.key",
			"testdata/cert.crt", "testdata/cert.key",
			"testdata/other-ca.crt", "testdata/other-ca.key",
			"testdata/other-cert.crt", "testdata/other-cert.key",
		} {
			_ = os.Remove(f)
		}
	})

	tests := []struct {
		name       string
		certPath   string
		caCertPath string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "valid_cert_signed_by_ca",
			certPath:   "testdata/cert.crt",
			caCertPath: "testdata/ca.crt",
			wantErr:    false,
		},
		{
			name:       "cert_not_signed_by_ca",
			certPath:   "testdata/other-cert.crt",
			caCertPath: "testdata/ca.crt",
			wantErr:    true,
			errMsg:     "certificate verification failed",
		},
		{
			name:       "missing_cert_file",
			certPath:   "testdata/nonexistent.crt",
			caCertPath: "testdata/ca.crt",
			wantErr:    true,
			errMsg:     "read certificate",
		},
		{
			name:       "missing_ca_file",
			certPath:   "testdata/cert.crt",
			caCertPath: "testdata/nonexistent.crt",
			wantErr:    true,
			errMsg:     "read CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCertificate(tt.certPath, tt.caCertPath)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestGetCertificateInfo(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a CA for testing
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	ca, err := GenerateCA("testdata/ca.crt", "testdata/ca.key", caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	// Generate a certificate for testing
	certSubject := pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(ca.Certificate, ca.PrivateKey, "testdata/cert.crt", "testdata/cert.key", certSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	t.Cleanup(func() {
		for _, f := range []string{
			"testdata/ca.crt", "testdata/ca.key",
			"testdata/cert.crt", "testdata/cert.key",
		} {
			_ = os.Remove(f)
		}
	})

	tests := []struct {
		name     string
		certPath string
		wantErr  bool
		errMsg   string
		wantCN   string
		wantIsCA bool
		wantDNS  []string
	}{
		{
			name:     "valid_certificate",
			certPath: "testdata/cert.crt",
			wantErr:  false,
			wantCN:   "Test Device",
			wantIsCA: false,
			wantDNS:  []string{"localhost"},
		},
		{
			name:     "valid_ca_certificate",
			certPath: "testdata/ca.crt",
			wantErr:  false,
			wantCN:   "Test CA",
			wantIsCA: true,
			wantDNS:  nil,
		},
		{
			name:     "missing_file",
			certPath: "testdata/nonexistent.crt",
			wantErr:  true,
			errMsg:   "read certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetCertificateInfo(tt.certPath)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, info)

			// Verify certificate info
			require.Contains(t, info.Subject, tt.wantCN)
			require.Equal(t, tt.wantIsCA, info.IsCA)
			require.Equal(t, tt.wantDNS, info.DNSNames)
			require.NotEmpty(t, info.Issuer)
			require.NotEmpty(t, info.SerialNumber)
			require.NotEmpty(t, info.SignatureAlgo)
			require.False(t, info.NotBefore.IsZero())
			require.False(t, info.NotAfter.IsZero())
			require.True(t, info.NotAfter.After(info.NotBefore))
		})
	}
}

func TestPEMToCertificate(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a valid certificate for testing
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	ca, err := GenerateCA("testdata/ca.crt", "testdata/ca.key", caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	certSubject := pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(ca.Certificate, ca.PrivateKey, "testdata/cert.crt", "testdata/cert.key", certSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	t.Cleanup(func() {
		for _, f := range []string{
			"testdata/ca.crt", "testdata/ca.key",
			"testdata/cert.crt", "testdata/cert.key",
		} {
			_ = os.Remove(f)
		}
	})

	// Read valid certificate PEM
	validCertPEM, err := os.ReadFile("testdata/cert.crt")
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		errMsg  string
		wantCN  string
	}{
		{
			name:    "valid_certificate",
			input:   validCertPEM,
			wantErr: false,
			wantCN:  "Test Device",
		},
		{
			name:    "empty_input",
			input:   []byte{},
			wantErr: true,
			errMsg:  "certificate file was empty",
		},
		{
			name:    "nil_input",
			input:   nil,
			wantErr: true,
			errMsg:  "certificate file was empty",
		},
		{
			name:    "invalid_pem_data",
			input:   []byte("not a pem certificate"),
			wantErr: true,
			errMsg:  "certificate file was empty",
		},
		{
			name:    "wrong_block_type",
			input:   []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"),
			wantErr: true,
			errMsg:  "file is not a valid certificate",
		},
		{
			name:    "invalid_certificate_data",
			input:   []byte("-----BEGIN CERTIFICATE-----\nMIIEpAIBAAKCAQEA\n-----END CERTIFICATE-----"),
			wantErr: true,
			errMsg:  "malformed certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := PEMToCertificate(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cert)
			require.Equal(t, tt.wantCN, cert.Subject.CommonName)
		})
	}
}

func TestPEMToPrivateKey(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a valid private key for testing
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	_, err := GenerateCA("testdata/ca.crt", "testdata/ca.key", caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.Remove("testdata/ca.crt")
		_ = os.Remove("testdata/ca.key")
	})

	// Read valid private key PEM
	validKeyPEM, err := os.ReadFile("testdata/ca.key")
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid_private_key",
			input:   validKeyPEM,
			wantErr: false,
		},
		{
			name:    "empty_input",
			input:   []byte{},
			wantErr: true,
			errMsg:  "certificate file was empty",
		},
		{
			name:    "nil_input",
			input:   nil,
			wantErr: true,
			errMsg:  "certificate file was empty",
		},
		{
			name:    "invalid_pem_data",
			input:   []byte("not a pem key"),
			wantErr: true,
			errMsg:  "certificate file was empty",
		},
		{
			name:    "wrong_block_type",
			input:   []byte("-----BEGIN CERTIFICATE-----\nMIIEpAIBAAKCAQEA\n-----END CERTIFICATE-----"),
			wantErr: true,
			errMsg:  "unknown private key type",
		},
		{
			name:    "unknown_key_type",
			input:   []byte("-----BEGIN EC PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END EC PRIVATE KEY-----"),
			wantErr: true,
			errMsg:  "unknown private key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := PEMToPrivateKey(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, key)
			require.IsType(t, &rsa.PrivateKey{}, key)
		})
	}
}
