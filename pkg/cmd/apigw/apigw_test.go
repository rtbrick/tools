package apigw

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
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

func generateTestJWKSTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.json")
	pubPath := filepath.Join(dir, "pub.json")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privSet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: key, KeyID: "access", Algorithm: string(jose.RS256)},
		{Key: &key.PublicKey, KeyID: "access"},
	}}
	privData, err := json.Marshal(privSet)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(privPath, privData, 0o644))

	pubSet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: "access"},
	}}
	pubData, err := json.Marshal(pubSet)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pubPath, pubData, 0o644))

	return privPath
}

func TestGenerateJWKSCmd(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "default flags",
			args:    []string{"jwks"},
			wantErr: false,
		},
		{
			name:    "custom kid",
			args:    []string{"jwks", "--kid", "prod"},
			wantErr: false,
		},
		{
			name:    "custom paths",
			args:    []string{"jwks", "--priv", "test-priv.json", "--pub", "test-pub.json"},
			wantErr: false,
		},
		{
			name:    "invalid priv path",
			args:    []string{"jwks", "--priv", "/nonexistent/dir/priv.json"},
			wantErr: true,
			errMsg:  "no such file or directory",
		},
		{
			name:    "invalid pub path",
			args:    []string{"jwks", "--pub", "/nonexistent/dir/pub.json"},
			wantErr: true,
			errMsg:  "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			args := make([]string, len(tt.args))
			copy(args, tt.args)

			// Replace output paths with temp dir paths unless testing invalid paths
			if !tt.wantErr || tt.name == "invalid priv path" || tt.name == "invalid pub path" {
				for i, a := range args {
					if a == "--priv" && i+1 < len(args) && args[i+1] == "test-priv.json" {
						args[i+1] = filepath.Join(dir, "priv.json")
					}
					if a == "--pub" && i+1 < len(args) && args[i+1] == "test-pub.json" {
						args[i+1] = filepath.Join(dir, "pub.json")
					}
				}
			}

			out, err := runCmd(t, NewGenerateCmd(), args...)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.Contains(t, out, "Private JWKS written to")
			require.Contains(t, out, "Public JWKS written to")
		})
	}
}

func TestGenerateJWKSCmd_CreatesValidJWKS(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.json")
	pubPath := filepath.Join(dir, "pub.json")

	_, err := runCmd(t, NewGenerateCmd(), "jwks",
		"--priv", privPath, "--pub", pubPath, "--kid", "test")
	require.NoError(t, err)

	// Verify private JWKS
	privData, err := os.ReadFile(privPath)
	require.NoError(t, err)
	var privSet jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(privData, &privSet))
	require.Len(t, privSet.Keys, 2)

	for _, key := range privSet.Keys {
		require.Equal(t, "test", key.KeyID)
	}

	// Verify public JWKS
	pubData, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	var pubSet jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(pubData, &pubSet))
	require.Len(t, pubSet.Keys, 1)
	require.Equal(t, "test", pubSet.Keys[0].KeyID)
}

func TestGenerateTokenCmd(t *testing.T) {
	privPath := generateTestJWKSTemp(t)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid token",
			args:    []string{"token", "--priv", privPath, "--sub", "user1", "--name", "Test User", "--preferred-username", "testuser"},
			wantErr: false,
		},
		{
			name:    "missing sub",
			args:    []string{"token", "--priv", privPath, "--name", "Test User", "--preferred-username", "testuser"},
			wantErr: true,
			errMsg:  "required flag(s) \"sub\" not set",
		},
		{
			name:    "missing name",
			args:    []string{"token", "--priv", privPath, "--sub", "user1", "--preferred-username", "testuser"},
			wantErr: true,
			errMsg:  "required flag(s) \"name\" not set",
		},
		{
			name:    "missing preferred-username",
			args:    []string{"token", "--priv", privPath, "--sub", "user1", "--name", "Test User"},
			wantErr: true,
			errMsg:  "required flag(s) \"preferred-username\" not set",
		},
		{
			name:    "missing all required",
			args:    []string{"token", "--priv", privPath},
			wantErr: true,
			errMsg:  "required flag(s)",
		},
		{
			name:    "invalid priv path",
			args:    []string{"token", "--priv", "/nonexistent/priv.json", "--sub", "user1", "--name", "Test User", "--preferred-username", "testuser"},
			wantErr: true,
		},
		{
			name:    "custom kid and override-kid",
			args:    []string{"token", "--priv", privPath, "--sub", "user1", "--name", "Test User", "--preferred-username", "testuser", "--kid", "access", "--override-kid", "rotated"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runCmd(t, NewGenerateCmd(), tt.args...)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			token := strings.TrimSpace(out)
			require.NotEmpty(t, token)

			// Verify it's a valid JWT format (3 parts separated by dots)
			parts := strings.Split(token, ".")
			require.Len(t, parts, 3, "token should be a valid JWT with 3 parts")
		})
	}
}

func TestGenerateTLSCertCmd(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid tls",
			args:    []string{"tls", "--org", "TestOrg", "--cert", "server.crt", "--key", "server.key"},
			wantErr: false,
		},
		{
			name:    "missing org",
			args:    []string{"tls", "--cert", "server.crt", "--key", "server.key"},
			wantErr: true,
			errMsg:  "required flag(s) \"org\" not set",
		},
		{
			name:    "custom hosts",
			args:    []string{"tls", "--org", "TestOrg", "--host", "example.com", "--host", "127.0.0.1", "--cert", "server.crt", "--key", "server.key"},
			wantErr: false,
		},
		{
			name:    "invalid cert path",
			args:    []string{"tls", "--org", "TestOrg", "--cert", "/no/dir/cert.pem", "--key", "server.key"},
			wantErr: true,
		},
		{
			name:    "invalid key path",
			args:    []string{"tls", "--org", "TestOrg", "--cert", "server.crt", "--key", "/no/dir/key.pem"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "server.crt")
			keyPath := filepath.Join(dir, "server.key")

			args := make([]string, len(tt.args))
			copy(args, tt.args)

			// Replace paths unless testing invalid paths
			if !tt.wantErr {
				for i, a := range args {
					if a == "server.crt" && i > 0 && args[i-1] == "--cert" {
						args[i] = certPath
					}
					if a == "server.key" && i > 0 && args[i-1] == "--key" {
						args[i] = keyPath
					}
				}
			}

			out, err := runCmd(t, NewGenerateCmd(), args...)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Contains(t, out, "TLS certificate written to")
			require.Contains(t, out, "TLS key written to")

			// Verify cert file is valid PEM
			certData, err := os.ReadFile(certPath)
			require.NoError(t, err)
			certBlock, _ := pem.Decode(certData)
			require.NotNil(t, certBlock)
			require.Equal(t, "CERTIFICATE", certBlock.Type)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)
			require.Equal(t, []string{"TestOrg"}, cert.Subject.Organization)

			// Verify key file is valid PEM
			keyData, err := os.ReadFile(keyPath)
			require.NoError(t, err)
			keyBlock, _ := pem.Decode(keyData)
			require.NotNil(t, keyBlock)
			require.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)
		})
	}
}

func TestGenerateTLSCertCmd_Hosts(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		wantDNS []string
		wantIPs []string
	}{
		{
			name:    "dns only",
			hosts:   []string{"example.com", "www.example.com"},
			wantDNS: []string{"example.com", "www.example.com"},
			wantIPs: []string{},
		},
		{
			name:    "ip only",
			hosts:   []string{"127.0.0.1", "10.0.0.1"},
			wantDNS: []string{},
			wantIPs: []string{"127.0.0.1", "10.0.0.1"},
		},
		{
			name:    "mixed",
			hosts:   []string{"example.com", "127.0.0.1"},
			wantDNS: []string{"example.com"},
			wantIPs: []string{"127.0.0.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "server.crt")
			keyPath := filepath.Join(dir, "server.key")

			args := []string{"tls", "--org", "TestOrg", "--cert", certPath, "--key", keyPath}
			for _, h := range tt.hosts {
				args = append(args, "--host", h)
			}

			_, err := runCmd(t, NewGenerateCmd(), args...)
			require.NoError(t, err)

			certData, err := os.ReadFile(certPath)
			require.NoError(t, err)
			certBlock, _ := pem.Decode(certData)
			require.NotNil(t, certBlock)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			require.NoError(t, err)

			if len(cert.DNSNames) == 0 && len(tt.wantDNS) == 0 {
				require.Empty(t, cert.DNSNames)
			} else {
				require.Equal(t, tt.wantDNS, cert.DNSNames)
			}

			var gotIPs []string
			for _, ip := range cert.IPAddresses {
				gotIPs = append(gotIPs, ip.String())
			}
			if len(gotIPs) == 0 && len(tt.wantIPs) == 0 {
				require.Empty(t, gotIPs)
			} else {
				require.Equal(t, tt.wantIPs, gotIPs)
			}
		})
	}
}
