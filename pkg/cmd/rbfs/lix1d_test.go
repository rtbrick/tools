package rbfs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func runCmd(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func createTempCert(t *testing.T, dir string, name string, isCA bool) (string, string) {
	t.Helper()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if !isCA {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o644))

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath
}

func TestServerCertificateCmd(t *testing.T) {
	tmpDir := t.TempDir()

	certPath, keyPath := createTempCert(t, tmpDir, "server", false)

	cmd := NewLix1dCmd()
	output, err := runCmd(t, cmd, "server", "certificate", "--cert", certPath, "--cert-key", keyPath)
	require.NoError(t, err)
	require.Contains(t, output, "set lawful-intercept protocol x1 mutual-tls server certificate ")
	require.Contains(t, output, "set lawful-intercept protocol x1 mutual-tls server key-plain-text ")
}

func TestServerCertificateCmd_CertKeyMismatch(t *testing.T) {
	tmpDir := t.TempDir()

	certPath1, _ := createTempCert(t, tmpDir, "server1", false)
	_, keyPath2 := createTempCert(t, tmpDir, "server2", false)

	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "server", "certificate", "--cert", certPath1, "--cert-key", keyPath2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "do not match")
}

func TestServerCertificateCmd_CARejected(t *testing.T) {
	tmpDir := t.TempDir()

	certPath, keyPath := createTempCert(t, tmpDir, "ca", true)

	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "server", "certificate", "--cert", certPath, "--cert-key", keyPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "is a CA certificate")
}

func TestServerCertificateCmd_MissingCert(t *testing.T) {
	tmpDir := t.TempDir()

	_, keyPath := createTempCert(t, tmpDir, "server", false)

	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "server", "certificate", "--cert-key", keyPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "required flag")
}

func TestServerCertificateCmd_MissingKey(t *testing.T) {
	tmpDir := t.TempDir()

	certPath, _ := createTempCert(t, tmpDir, "server", false)

	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "server", "certificate", "--cert", certPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "required flag")
}

func TestServerClientCACmd(t *testing.T) {
	tmpDir := t.TempDir()

	certPath, _ := createTempCert(t, tmpDir, "client-ca", true)

	cmd := NewLix1dCmd()
	output, err := runCmd(t, cmd, "server", "client-ca", "--cert", certPath)
	require.NoError(t, err)
	require.Contains(t, output, "set lawful-intercept protocol x1 mutual-tls server client-ca ")
}

func TestServerClientCACmd_NonCARejected(t *testing.T) {
	tmpDir := t.TempDir()

	certPath, _ := createTempCert(t, tmpDir, "server", false)

	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "server", "client-ca", "--cert", certPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a CA certificate")
}

func TestServerClientCACmd_MissingCert(t *testing.T) {
	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "server", "client-ca")
	require.Error(t, err)
	require.Contains(t, err.Error(), "required flag")
}

func TestClientRootCACmd(t *testing.T) {
	tmpDir := t.TempDir()

	certPath, _ := createTempCert(t, tmpDir, "root-ca", true)

	cmd := NewLix1dCmd()
	output, err := runCmd(t, cmd, "client", "root-ca", "--cert", certPath)
	require.NoError(t, err)
	require.Contains(t, output, "set lawful-intercept protocol x1 mutual-tls client root-ca ")
}

func TestClientRootCACmd_NonCARejected(t *testing.T) {
	tmpDir := t.TempDir()

	certPath, _ := createTempCert(t, tmpDir, "server", false)

	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "client", "root-ca", "--cert", certPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a CA certificate")
}

func TestClientRootCACmd_MissingCert(t *testing.T) {
	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "client", "root-ca")
	require.Error(t, err)
	require.Contains(t, err.Error(), "required flag")
}

func TestInvalidPEMFile(t *testing.T) {
	tmpDir := t.TempDir()

	badPath := filepath.Join(tmpDir, "bad.pem")
	require.NoError(t, os.WriteFile(badPath, []byte("not a pem"), 0o644))

	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "server", "client-ca", "--cert", badPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a valid PEM")
}

func TestMissingFile(t *testing.T) {
	cmd := NewLix1dCmd()
	_, err := runCmd(t, cmd, "server", "client-ca", "--cert", "/nonexistent/path.crt")
	require.Error(t, err)
	require.Contains(t, err.Error(), "read file")
}
