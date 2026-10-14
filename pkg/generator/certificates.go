package generator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec //not security relevant
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
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

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA private key: %w", err)
	}

	kid, err := subjectKeyID(&caKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("compute CA subject key identifier: %w", err)
	}
	// RFC 5280 Section 4.2.1.2: conforming CAs MUST include the SKI. Section
	// 4.2.1.1 allows omitting the AKI on a self-signed root, it is set equal
	// to the SKI anyway as common CA tooling does, which eases chain
	// building after re-keying or cross-signing.
	caCert.SubjectKeyId = kid
	caCert.AuthorityKeyId = kid

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

// subjectKeyID computes a key identifier from the given public key per
// RFC 5280 Section 4.2.1.2 method (1): the 160-bit SHA-1 hash of the BIT
// STRING subjectPublicKey (excluding the tag, length, and number of unused
// bits). RFC 5280 doesn't mandate a method, it only requires the identifier
// to be derived from the key or otherwise unique. Method (1) is used as the
// most widely recognized form. Note that the Go standard library now
// defaults to RFC 7093 Section 2 method 1 (truncated SHA-256) for the CA
// certificates it generates an identifier for.
//
// The identifier is computed here instead of relying on Go because Go only
// generates it for CA certificates and never sets the AKI of a self-signed
// root.
func subjectKeyID(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var info struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, err
	}
	//nolint:gosec //RFC 5280 4.2.1.2 method (1), an identifier, not a security function
	sum := sha1.Sum(info.PublicKey.Bytes)
	return sum[:], nil
}

// CertOption sets an optional property on a certificate template before
// it is signed.
type CertOption func(*x509.Certificate) error

// UserID adds a UID attribute to the subject's distinguished name. An
// empty user ID is ignored.
func UserID(userId string) CertOption {
	// oidUID is the X.520 "userid" attribute (RFC 4519 / RFC 2247), used to
	// carry a UID in a certificate's subject Distinguished Name.
	var oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

	return func(c *x509.Certificate) error {
		if userId != "" {
			c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  oidUID,
				Value: userId,
			})
		}
		return nil
	}
}

// DNSNames adds the DNS names for which the certificate is issued. If no
// DNS names are given, the default DNS name is kept.
func DNSNames(dnsnames ...string) CertOption {
	return func(c *x509.Certificate) error {
		if len(dnsnames) > 0 {
			c.DNSNames = dnsnames
		}
		return nil
	}
}

// IPAddresses adds the IP addresses for which the certificate is issued.
func IPAddresses(ipAddresses ...net.IP) CertOption {
	return func(c *x509.Certificate) error {
		c.IPAddresses = ipAddresses
		return nil
	}
}

// ETSIX1BindingIdentifier adds the ETSI TS 103 221-1 X1 certificate binding
// as a URI subject alternative name of the form
// urn:etsi:li:103221-1:cert-binding:<role>:<name>. The binding is only
// added if both role and name are given.
func ETSIX1BindingIdentifier(role, name string) CertOption {
	const etsiLIX1CertBindingURNPrefix = "etsi:li:103221-1:cert-binding:"
	return func(c *x509.Certificate) error {
		if role != "" && name != "" {
			c.URIs = append(c.URIs, &url.URL{
				Scheme: "urn",
				Opaque: etsiLIX1CertBindingURNPrefix + role + ":" + name,
			})
		}
		return nil

	}
}

// GenerateCert generates a certificate signed by the provided CA
func GenerateCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, certPath, keyPath string, subject pkix.Name, valid time.Duration, options ...CertOption) error {

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1658),
		Subject:               subject,
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(valid),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Apply all optional certificate settings
	for _, o := range options {
		if err := o(cert); err != nil {
			return err
		}
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate certificate private key: %w", err)
	}

	ski, err := subjectKeyID(&certKey.PublicKey)
	if err != nil {
		log.Printf("compute subject key identifier: %v\n", err)
		return err
	}

	// RFC 5280 Section 4.2.1.2: end entity certificates SHOULD carry an SKI.
	// Go only generates one for CA certificates, so derive it from the
	// certificate's own key.
	cert.SubjectKeyId = ski

	// RFC 5280 Section 4.2.1.1: the AKI MUST be present in all certificates
	// except self-signed roots. Go copies it from the CA's SKI. A given CA
	// lacking an SKI is accepted, the AKI is then derived from the CA's
	// public key. This can't conflict with the CA, verifiers only reject a
	// mismatch when both the AKI and the issuer's SKI are present.
	if len(caCert.SubjectKeyId) == 0 {
		aki, err := subjectKeyID(&caKey.PublicKey)
		if err != nil {
			return fmt.Errorf("compute authority key identifier: %w", err)
		}
		cert.AuthorityKeyId = aki
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
