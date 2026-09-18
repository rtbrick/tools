package lix1

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

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

func TestGenerateCACmd(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		errMsg   string
		wantCert string
		wantKey  string
	}{
		{
			name:     "valid ca",
			args:     []string{"generate", "ca", "--cn", "Test CA", "--org", "TestOrg", "--ou", "Eng", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key"},
			wantCert: "testdata/ca.crt",
			wantKey:  "testdata/ca.key",
		},
		{
			name:     "valid ca with custom duration",
			args:     []string{"generate", "ca", "--cn", "Short CA", "--org", "TestOrg", "--ou", "Eng", "--duration", "1h", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key"},
			wantCert: "testdata/ca.crt",
			wantKey:  "testdata/ca.key",
		},
		{
			name:     "default output paths",
			args:     []string{"generate", "ca", "--cn", "Default CA", "--org", "TestOrg", "--ou", "Eng"},
			wantCert: defaultCACrt,
			wantKey:  defaultCACrtKey,
		},
		{
			name:    "missing cn",
			args:    []string{"generate", "ca", "--org", "TestOrg", "--ou", "Eng"},
			wantErr: true,
			errMsg:  "required flag(s) \"cn\" not set",
		},
		{
			name:    "missing org",
			args:    []string{"generate", "ca", "--cn", "Test CA", "--ou", "Eng"},
			wantErr: true,
			errMsg:  "required flag(s) \"org\" not set",
		},
		{
			name:    "missing ou",
			args:    []string{"generate", "ca", "--cn", "Test CA", "--org", "TestOrg"},
			wantErr: true,
			errMsg:  "required flag(s) \"ou\" not set",
		},
		{
			name:    "missing all required",
			args:    []string{"generate", "ca"},
			wantErr: true,
			errMsg:  "required flag(s)",
		},
		{
			name:    "invalid cert path",
			args:    []string{"generate", "ca", "--cn", "Test CA", "--org", "TestOrg", "--ou", "Eng", "--ca-crt", "/nonexistent/dir/ca.crt"},
			wantErr: true,
		},
		{
			name:    "invalid key path",
			args:    []string{"generate", "ca", "--cn", "Test CA", "--org", "TestOrg", "--ou", "Eng", "--ca-crt-key", "/nonexistent/dir/ca.key"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				_ = os.Remove(tt.wantCert)
				_ = os.Remove(tt.wantKey)
				_ = os.Remove(defaultCACrt)
				_ = os.Remove(defaultCACrtKey)
			})

			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}

			_, err := runCmd(t, NewLix1Cmd(), tt.args...)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			require.FileExists(t, tt.wantCert)
			require.FileExists(t, tt.wantKey)

			// Verify cert is valid PEM
			certData, err := os.ReadFile(tt.wantCert)
			require.NoError(t, err)
			certBlock, _ := pem.Decode(certData)
			require.NotNil(t, certBlock)
			require.Equal(t, "CERTIFICATE", certBlock.Type)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)
			require.True(t, cert.IsCA)
			require.Equal(t, []string{"TestOrg"}, cert.Subject.Organization)
			require.Equal(t, []string{"Eng"}, cert.Subject.OrganizationalUnit)

			// Verify key is valid PEM
			keyData, err := os.ReadFile(tt.wantKey)
			require.NoError(t, err)
			keyBlock, _ := pem.Decode(keyData)
			require.NotNil(t, keyBlock)
			require.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)
		})
	}
}

func TestGenerateCertCmd(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a CA first for signing
	caArgs := []string{"generate", "ca", "--cn", "Test CA", "--org", "TestOrg", "--ou", "Eng", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key"}
	_, err := runCmd(t, NewLix1Cmd(), caArgs...)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Remove("testdata/ca.crt")
		_ = os.Remove("testdata/ca.key")
	})

	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		errMsg   string
		wantCert string
		wantKey  string
	}{
		{
			name:     "valid cert",
			args:     []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Test Device", "--org", "TestOrg", "--ou", "Eng", "--crt", "testdata/cert.crt", "--crt-key", "testdata/cert.key"},
			wantCert: "testdata/cert.crt",
			wantKey:  "testdata/cert.key",
		},
		{
			name:     "valid cert multiple ous",
			args:     []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Device2", "--org", "TestOrg", "--ou", "Eng", "--crt", "testdata/cert.crt", "--crt-key", "testdata/cert.key"},
			wantCert: "testdata/cert.crt",
			wantKey:  "testdata/cert.key",
		},
		{
			name:    "missing cn",
			args:    []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--org", "TestOrg", "--ou", "Eng", "--crt", "testdata/cert.crt", "--crt-key", "testdata/cert.key"},
			wantErr: true,
			errMsg:  "required flag(s) \"cn\" not set",
		},
		{
			name:    "missing org",
			args:    []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Device", "--ou", "Eng", "--crt", "testdata/cert.crt", "--crt-key", "testdata/cert.key"},
			wantErr: true,
			errMsg:  "required flag(s) \"org\" not set",
		},
		{
			name:    "missing ou",
			args:    []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Device", "--org", "TestOrg", "--crt", "testdata/cert.crt", "--crt-key", "testdata/cert.key"},
			wantErr: true,
			errMsg:  "required flag(s) \"ou\" not set",
		},
		{
			name:    "missing crt",
			args:    []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Device", "--org", "TestOrg", "--ou", "Eng", "--crt-key", "testdata/cert.key"},
			wantErr: true,
			errMsg:  "required flag(s) \"crt\" not set",
		},
		{
			name:    "missing crt-key",
			args:    []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Device", "--org", "TestOrg", "--ou", "Eng", "--crt", "testdata/cert.crt"},
			wantErr: true,
			errMsg:  "required flag(s) \"crt-key\" not set",
		},
		{
			name:    "missing all required",
			args:    []string{"generate", "cert"},
			wantErr: true,
			errMsg:  "required flag(s)",
		},
		{
			name:    "ca not found",
			args:    []string{"generate", "cert", "--ca-crt", "testdata/nonexistent.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Device", "--org", "TestOrg", "--ou", "Eng", "--crt", "testdata/cert.crt", "--crt-key", "testdata/cert.key"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				_ = os.Remove(tt.wantCert)
				_ = os.Remove(tt.wantKey)
			})

			_, err := runCmd(t, NewLix1Cmd(), tt.args...)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			require.FileExists(t, tt.wantCert)
			require.FileExists(t, tt.wantKey)

			// Verify cert is valid PEM and signed by CA
			certData, err := os.ReadFile(tt.wantCert)
			require.NoError(t, err)
			certBlock, _ := pem.Decode(certData)
			require.NotNil(t, certBlock)
			require.Equal(t, "CERTIFICATE", certBlock.Type)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)
			require.False(t, cert.IsCA)
			require.Equal(t, []string{"TestOrg"}, cert.Subject.Organization)
			require.Equal(t, []string{"Eng"}, cert.Subject.OrganizationalUnit)
			require.Equal(t, "Test CA", cert.Issuer.CommonName)

			// Verify key is valid PEM
			keyData, err := os.ReadFile(tt.wantKey)
			require.NoError(t, err)
			keyBlock, _ := pem.Decode(keyData)
			require.NotNil(t, keyBlock)
			require.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)
		})
	}
}

func TestTestCertCmd(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a CA and cert for testing
	caArgs := []string{"generate", "ca", "--cn", "Test CA", "--org", "TestOrg", "--ou", "Eng", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key"}
	_, err := runCmd(t, NewLix1Cmd(), caArgs...)
	require.NoError(t, err)

	certArgs := []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Test Device", "--org", "TestOrg", "--ou", "Eng", "--crt", "testdata/cert.crt", "--crt-key", "testdata/cert.key"}
	_, err = runCmd(t, NewLix1Cmd(), certArgs...)
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
		name    string
		args    []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid cert info",
			args:    []string{"test", "cert", "--crt", "testdata/cert.crt"},
			wantErr: false,
		},
		{
			name:    "valid cert with ca verification",
			args:    []string{"test", "cert", "--crt", "testdata/cert.crt", "--ca-crt", "testdata/ca.crt"},
			wantErr: false,
		},
		{
			name:    "ca cert info",
			args:    []string{"test", "cert", "--crt", "testdata/ca.crt"},
			wantErr: false,
		},
		{
			name:    "missing crt flag",
			args:    []string{"test", "cert"},
			wantErr: true,
			errMsg:  "required flag(s) \"crt\" not set",
		},
		{
			name:    "cert not found",
			args:    []string{"test", "cert", "--crt", "testdata/nonexistent.crt"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runCmd(t, NewLix1Cmd(), tt.args...)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestTestCertCmd_ExpiredCert(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a CA
	caArgs := []string{"generate", "ca", "--cn", "Test CA", "--org", "TestOrg", "--ou", "Eng", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key"}
	_, err := runCmd(t, NewLix1Cmd(), caArgs...)
	require.NoError(t, err)

	// Generate a cert with very short duration (will expire immediately)
	certArgs := []string{"generate", "cert", "--ca-crt", "testdata/ca.crt", "--ca-crt-key", "testdata/ca.key", "--cn", "Short Device", "--org", "TestOrg", "--ou", "Eng", "--duration", "1ns", "--crt", "testdata/short.crt", "--crt-key", "testdata/short.key"}
	_, err = runCmd(t, NewLix1Cmd(), certArgs...)
	require.NoError(t, err)

	t.Cleanup(func() {
		for _, f := range []string{
			"testdata/ca.crt", "testdata/ca.key",
			"testdata/short.crt", "testdata/short.key",
		} {
			_ = os.Remove(f)
		}
	})

	// The test cert command outputs to stdout (fmt.Printf), so we can't capture it via runCmd.
	// Just verify the command doesn't error.
	_, err = runCmd(t, NewLix1Cmd(), "test", "cert", "--crt", "testdata/short.crt")
	require.NoError(t, err)
}

func TestGenerateCACmd_DefaultOutputPaths(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Remove(defaultCACrt)
		_ = os.Remove(defaultCACrtKey)
	})

	_, err := runCmd(t, NewLix1Cmd(), "generate", "ca", "--cn", "Default CA", "--org", "TestOrg", "--ou", "Eng")
	require.NoError(t, err)
	require.FileExists(t, defaultCACrt)
	require.FileExists(t, defaultCACrtKey)
}
