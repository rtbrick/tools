package generator

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerateCA(t *testing.T) {
	tests := []struct {
		name         string
		subject      pkix.Name
		valid        time.Duration
		certPath     string
		keyPath      string
		wantErr      bool
		errMsg       string
		wantIsCA     bool
		wantKeyUsage x509.KeyUsage
	}{
		{
			name:         "valid_ca_defaults",
			subject:      pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:        10 * 365 * 24 * time.Hour,
			wantIsCA:     true,
			wantKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
		{
			name:         "valid_ca_short_duration",
			subject:      pkix.Name{CommonName: "Short CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:        1 * time.Hour,
			wantIsCA:     true,
			wantKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
		{
			name:         "valid_ca_multiple_ous",
			subject:      pkix.Name{CommonName: "Multi OU CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng", "Security"}},
			valid:        5 * 365 * 24 * time.Hour,
			wantIsCA:     true,
			wantKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		},
		{
			name:     "invalid_cert_path",
			subject:  pkix.Name{CommonName: "Bad Path CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			certPath: "/nonexistent/dir/ca.crt",
			keyPath:  "ca.key",
			wantErr:  true,
			errMsg:   "write certificate file",
		},
		{
			name:     "invalid_key_path",
			subject:  pkix.Name{CommonName: "Bad Path CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			certPath: "ca.crt",
			keyPath:  "/nonexistent/dir/ca.key",
			wantErr:  true,
			errMsg:   "write private key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			certPath := filepath.Join(dir, "ca.crt")
			keyPath := filepath.Join(dir, "ca.key")

			if tt.certPath != "" {
				certPath = tt.certPath
			}
			if tt.keyPath != "" {
				keyPath = tt.keyPath
			}

			result, err := GenerateCA(certPath, keyPath, tt.subject, tt.valid)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.Certificate)
			require.NotNil(t, result.PrivateKey)

			// Verify certificate file exists
			certData, err := os.ReadFile(certPath)
			require.NoError(t, err)
			require.NotEmpty(t, certData)

			// Verify key file exists
			keyData, err := os.ReadFile(keyPath)
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
			certInfo, err := os.Stat(certPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())

			keyInfo, err := os.Stat(keyPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
		})
	}
}

func TestGenerateCert(t *testing.T) {
	// Generate a CA first for signing
	caDir := t.TempDir()
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	ca, err := GenerateCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"), caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	tests := []struct {
		name     string
		subject  pkix.Name
		valid    time.Duration
		certPath string
		keyPath  string
		wantErr  bool
		errMsg   string
		wantDNS  []string
		wantIsCA bool
	}{
		{
			name:     "valid_cert",
			subject:  pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			wantDNS:  []string{"localhost"},
			wantIsCA: false,
		},
		{
			name:     "valid_cert_short_duration",
			subject:  pkix.Name{CommonName: "Short Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    1 * time.Hour,
			wantDNS:  []string{"localhost"},
			wantIsCA: false,
		},
		{
			name:     "valid_cert_multiple_ous",
			subject:  pkix.Name{CommonName: "Multi OU Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng", "Security"}},
			valid:    5 * 365 * 24 * time.Hour,
			wantDNS:  []string{"localhost"},
			wantIsCA: false,
		},
		{
			name:     "invalid_cert_path",
			subject:  pkix.Name{CommonName: "Bad Path", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			certPath: "/nonexistent/dir/cert.crt",
			keyPath:  "cert.key",
			wantErr:  true,
			errMsg:   "write certificate file",
		},
		{
			name:     "invalid_key_path",
			subject:  pkix.Name{CommonName: "Bad Path", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}},
			valid:    10 * 365 * 24 * time.Hour,
			certPath: "cert.crt",
			keyPath:  "/nonexistent/dir/cert.key",
			wantErr:  true,
			errMsg:   "write private key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			certPath := filepath.Join(dir, "cert.crt")
			keyPath := filepath.Join(dir, "cert.key")

			if tt.certPath != "" {
				certPath = tt.certPath
			}
			if tt.keyPath != "" {
				keyPath = tt.keyPath
			}

			err := GenerateCert(ca.Certificate, ca.PrivateKey, certPath, keyPath, tt.subject, tt.valid)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)

			// Verify cert file exists
			certData, err := os.ReadFile(certPath)
			require.NoError(t, err)
			require.NotEmpty(t, certData)

			// Verify key file exists
			keyData, err := os.ReadFile(keyPath)
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
			certInfo, err := os.Stat(certPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())

			keyInfo, err := os.Stat(keyPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
		})
	}
}

func TestLoadCA(t *testing.T) {
	// Generate a valid CA for testing
	caDir := t.TempDir()
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	validCA, err := GenerateCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"), caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	// Create invalid PEM files
	invalidCertDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(invalidCertDir, "bad.crt"), []byte("not a pem"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(invalidCertDir, "bad.key"), []byte("not a pem"), 0o644))

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
			certPath: filepath.Join(caDir, "ca.crt"),
			keyPath:  filepath.Join(caDir, "ca.key"),
			wantCN:   "Test CA",
		},
		{
			name:     "missing_cert_file",
			certPath: filepath.Join(caDir, "nonexistent.crt"),
			keyPath:  filepath.Join(caDir, "ca.key"),
			wantErr:  true,
			errMsg:   "read CA certificate",
		},
		{
			name:     "missing_key_file",
			certPath: filepath.Join(caDir, "ca.crt"),
			keyPath:  filepath.Join(caDir, "nonexistent.key"),
			wantErr:  true,
			errMsg:   "read CA private key",
		},
		{
			name:     "invalid_cert_pem",
			certPath: filepath.Join(invalidCertDir, "bad.crt"),
			keyPath:  filepath.Join(caDir, "ca.key"),
			wantErr:  true,
			errMsg:   "parse CA certificate",
		},
		{
			name:     "invalid_key_pem",
			certPath: filepath.Join(caDir, "ca.crt"),
			keyPath:  filepath.Join(invalidCertDir, "bad.key"),
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
	// Generate a CA and certificate for testing
	caDir := t.TempDir()
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	ca, err := GenerateCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"), caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	// Generate a valid certificate signed by the CA
	certDir := t.TempDir()
	certSubject := pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(ca.Certificate, ca.PrivateKey, filepath.Join(certDir, "cert.crt"), filepath.Join(certDir, "cert.key"), certSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	// Generate another CA and certificate (not signed by the first CA)
	otherDir := t.TempDir()
	otherCASubject := pkix.Name{CommonName: "Other CA", Organization: []string{"OtherOrg"}, OrganizationalUnit: []string{"Eng"}}
	otherCA, err := GenerateCA(filepath.Join(otherDir, "other-ca.crt"), filepath.Join(otherDir, "other-ca.key"), otherCASubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	otherCertDir := t.TempDir()
	otherCertSubject := pkix.Name{CommonName: "Other Device", Organization: []string{"OtherOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(otherCA.Certificate, otherCA.PrivateKey, filepath.Join(otherCertDir, "other-cert.crt"), filepath.Join(otherCertDir, "other-cert.key"), otherCertSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	tests := []struct {
		name       string
		certPath   string
		caCertPath string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "valid_cert_signed_by_ca",
			certPath:   filepath.Join(certDir, "cert.crt"),
			caCertPath: filepath.Join(caDir, "ca.crt"),
			wantErr:    false,
		},
		{
			name:       "cert_not_signed_by_ca",
			certPath:   filepath.Join(otherCertDir, "other-cert.crt"),
			caCertPath: filepath.Join(caDir, "ca.crt"),
			wantErr:    true,
			errMsg:     "certificate verification failed",
		},
		{
			name:       "missing_cert_file",
			certPath:   filepath.Join(certDir, "nonexistent.crt"),
			caCertPath: filepath.Join(caDir, "ca.crt"),
			wantErr:    true,
			errMsg:     "read certificate",
		},
		{
			name:       "missing_ca_file",
			certPath:   filepath.Join(certDir, "cert.crt"),
			caCertPath: filepath.Join(caDir, "nonexistent.crt"),
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
	// Generate a CA for testing
	caDir := t.TempDir()
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	ca, err := GenerateCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"), caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	// Generate a certificate for testing
	certDir := t.TempDir()
	certSubject := pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(ca.Certificate, ca.PrivateKey, filepath.Join(certDir, "cert.crt"), filepath.Join(certDir, "cert.key"), certSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

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
			certPath: filepath.Join(certDir, "cert.crt"),
			wantErr:  false,
			wantCN:   "Test Device",
			wantIsCA: false,
			wantDNS:  []string{"localhost"},
		},
		{
			name:     "valid_ca_certificate",
			certPath: filepath.Join(caDir, "ca.crt"),
			wantErr:  false,
			wantCN:   "Test CA",
			wantIsCA: true,
			wantDNS:  nil,
		},
		{
			name:     "missing_file",
			certPath: filepath.Join(certDir, "nonexistent.crt"),
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
	// Generate a valid certificate for testing
	caDir := t.TempDir()
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	ca, err := GenerateCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"), caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	certDir := t.TempDir()
	certSubject := pkix.Name{CommonName: "Test Device", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	err = GenerateCert(ca.Certificate, ca.PrivateKey, filepath.Join(certDir, "cert.crt"), filepath.Join(certDir, "cert.key"), certSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	// Read valid certificate PEM
	validCertPEM, err := os.ReadFile(filepath.Join(certDir, "cert.crt"))
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
	// Generate a valid private key for testing
	caDir := t.TempDir()
	caSubject := pkix.Name{CommonName: "Test CA", Organization: []string{"TestOrg"}, OrganizationalUnit: []string{"Eng"}}
	_, err := GenerateCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"), caSubject, 10*365*24*time.Hour)
	require.NoError(t, err)

	// Read valid private key PEM
	validKeyPEM, err := os.ReadFile(filepath.Join(caDir, "ca.key"))
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
