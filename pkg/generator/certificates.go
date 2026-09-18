package generator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec //not security relevant
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// CACertificate represents a CA certificate and its private key
type CACertificate struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// GenerateCA generates a new root CA certificate and private key
func GenerateCA(certPath, keyPath string, subject pkix.Name, valid time.Duration) (*CACertificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	caCert := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(valid),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	ous := joinOUs(caCert.Subject.OrganizationalUnit)
	sidSum := sha1.Sum([]byte(ous + "::" + caCert.Subject.CommonName)) //nolint:gosec //not security relevant
	caCert.SubjectKeyId = sidSum[:]

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA private key: %w", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}

	if err := writeCertificate(certPath, caBytes); err != nil {
		return nil, err
	}

	if err := writePrivateKey(keyPath, caKey); err != nil {
		return nil, err
	}

	return &CACertificate{
		Certificate: caCert,
		PrivateKey:  caKey,
	}, nil
}

// GenerateCert generates a certificate signed by the provided CA
func GenerateCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, certPath, keyPath string, subject pkix.Name, valid time.Duration) error {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      subject,
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(valid),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	ous := joinOUs(cert.Subject.OrganizationalUnit)
	sidSum := sha1.Sum([]byte(ous + "::" + cert.Subject.CommonName)) //nolint:gosec //not security relevant
	cert.SubjectKeyId = sidSum[:]

	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate certificate private key: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := writeCertificate(certPath, certBytes); err != nil {
		return err
	}

	if err := writePrivateKey(keyPath, certKey); err != nil {
		return err
	}

	return nil
}

// LoadCA loads a CA certificate and private key from PEM files
func LoadCA(certPath, keyPath string) (*CACertificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA private key: %w", err)
	}

	cert, err := PEMToCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	key, err := PEMToPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}

	return &CACertificate{
		Certificate: cert,
		PrivateKey:  key,
	}, nil
}

// VerifyCertificate verifies a certificate against a CA certificate
func VerifyCertificate(certPath, caCertPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}

	cert, err := PEMToCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	caCert, err := PEMToCertificate(caCertPEM)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// GetCertificateInfo returns information about a certificate
func GetCertificateInfo(certPath string) (*CertificateInfo, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	cert, err := PEMToCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	info := &CertificateInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		IsCA:          cert.IsCA,
		DNSNames:      cert.DNSNames,
		IPAddresses:   cert.IPAddresses,
		SerialNumber:  cert.SerialNumber.String(),
		KeyUsage:      cert.KeyUsage.String(),
		ExtKeyUsage:   cert.ExtKeyUsage,
		SignatureAlgo: cert.SignatureAlgorithm.String(),
	}

	return info, nil
}

// CertificateInfo holds certificate information for display
type CertificateInfo struct {
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	IsCA          bool
	DNSNames      []string
	IPAddresses   []net.IP
	SerialNumber  string
	KeyUsage      string
	ExtKeyUsage   []x509.ExtKeyUsage
	SignatureAlgo string
}

func joinOUs(ous []string) string {
	if len(ous) == 0 {
		return ""
	}
	var result strings.Builder
	result.WriteString(ous[0])
	for i := 1; i < len(ous); i++ {
		result.WriteString("/" + ous[i])
	}
	return result.String()
}

func writeCertificate(path string, certDER []byte) error {
	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		return fmt.Errorf("encode certificate: %w", err)
	}
	if err := os.WriteFile(path, certPEM.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write certificate file: %w", err)
	}
	return nil
}

func writePrivateKey(path string, key *rsa.PrivateKey) error {
	keyPEM := new(bytes.Buffer)
	if err := pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	if err := os.WriteFile(path, keyPEM.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write private key file: %w", err)
	}
	return nil
}

func PEMToCertificate(in []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(in)
	if block == nil {
		return nil, fmt.Errorf("certificate file was empty")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, fmt.Errorf("file is not a valid certificate; has type %v", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func PEMToPrivateKey(in []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(in)
	if block == nil {
		return nil, fmt.Errorf("certificate file was empty")
	}

	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("file is not a valid private key file; has type %v", block.Type)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	return nil, fmt.Errorf("unknown private key type %v", block.Type)
}
