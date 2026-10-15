package pem

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func PemFileToBase64(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("file %s is not a valid PEM", path)
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func LoadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("file %s is not a valid PEM", path)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("file %s is not a certificate (type: %s)", path, block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}

	return cert, nil
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("file %s is not a valid PEM", path)
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("file %s is not an RSA private key (type: %s)", path, block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", path, err)
	}

	return key, nil
}

func ValidateCertAndKeyMatch(certPath, keyPath string) error {
	cert, err := LoadCertificate(certPath)
	if err != nil {
		return err
	}

	key, err := LoadPrivateKey(keyPath)
	if err != nil {
		return err
	}

	certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate %s does not contain RSA public key", certPath)
	}

	if certPubKey.N.Cmp(key.N) != 0 || certPubKey.E != key.E {
		return fmt.Errorf("certificate %s and key %s do not match", certPath, keyPath)
	}

	return nil
}

func ValidateIsCA(certPath string) error {
	cert, err := LoadCertificate(certPath)
	if err != nil {
		return err
	}

	if !cert.IsCA {
		return fmt.Errorf("certificate %s is not a CA certificate (IsCA=false)", certPath)
	}

	return nil
}

func ValidateNotCA(certPath string) error {
	cert, err := LoadCertificate(certPath)
	if err != nil {
		return err
	}

	if cert.IsCA {
		return fmt.Errorf("certificate %s is a CA certificate (IsCA=true), expected non-CA", certPath)
	}

	return nil
}
