package generator

import (
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// generateTestJWKS creates a temp dir and generates JWKS files.
func generateTestJWKS(t *testing.T, kid string) (privPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	privPath = filepath.Join(dir, "priv.json")
	pubPath = filepath.Join(dir, "pub.json")
	require.NoError(t, GenerateJWKS(privPath, pubPath, kid))
	return privPath, pubPath
}

func TestGenerateJWKS(t *testing.T) {
	tests := []struct {
		name     string
		kid      string
		wantPriv int // expected number of keys in private JWKS
		wantPub  int // expected number of keys in public JWKS
	}{
		{
			name:     "default kid",
			kid:      "access",
			wantPriv: 2, // private + public
			wantPub:  1, // public only
		},
		{
			name:     "custom kid",
			kid:      "prod",
			wantPriv: 2,
			wantPub:  1,
		},
		{
			name:     "empty kid",
			kid:      "",
			wantPriv: 2,
			wantPub:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privPath, pubPath := generateTestJWKS(t, tt.kid)

			// Files exist
			_, err := os.Stat(privPath)
			require.NoError(t, err, "private JWKS file should exist")
			_, err = os.Stat(pubPath)
			require.NoError(t, err, "public JWKS file should exist")

			// Parse private JWKS
			privData, err := os.ReadFile(privPath)
			require.NoError(t, err)
			var privSet jose.JSONWebKeySet
			require.NoError(t, json.Unmarshal(privData, &privSet))
			require.Len(t, privSet.Keys, tt.wantPriv)

			// Parse public JWKS
			pubData, err := os.ReadFile(pubPath)
			require.NoError(t, err)
			var pubSet jose.JSONWebKeySet
			require.NoError(t, json.Unmarshal(pubData, &pubSet))
			require.Len(t, pubSet.Keys, tt.wantPub)

			// All keys have correct KID and use RS256
			for _, key := range privSet.Keys {
				require.Equal(t, tt.kid, key.KeyID)
				require.Equal(t, string(jose.RS256), key.Algorithm)
			}
			for _, key := range pubSet.Keys {
				require.Equal(t, tt.kid, key.KeyID)
			}

			// Private JWKS has one RSA private key and one RSA public key
			_, isPriv := privSet.Keys[0].Key.(*rsa.PrivateKey)
			_, isPub := privSet.Keys[1].Key.(*rsa.PublicKey)
			require.True(t, isPriv, "first key should be RSA private")
			require.True(t, isPub, "second key should be RSA public")
		})
	}
}

func TestLoadPrivateKeyFromJWKS(t *testing.T) {
	privPath, _ := generateTestJWKS(t, "access")

	tests := []struct {
		name    string
		path    string
		kid     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "match by kid",
			path:    privPath,
			kid:     "access",
			wantErr: false,
		},
		{
			name:    "first key (empty kid)",
			path:    privPath,
			kid:     "",
			wantErr: false,
		},
		{
			name:    "wrong kid",
			path:    privPath,
			kid:     "wrong",
			wantErr: true,
			errMsg:  "no private key with kid",
		},
		{
			name:    "missing file",
			path:    filepath.Join(t.TempDir(), "nonexistent.json"),
			kid:     "",
			wantErr: true,
			errMsg:  "read jwks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, kid, err := LoadPrivateKeyFromJWKS(tt.path, tt.kid)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				require.Nil(t, key)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, key)
			require.NotEmpty(t, kid)
		})
	}
}

func TestLoadPublicKeyFromJWKS(t *testing.T) {
	_, pubPath := generateTestJWKS(t, "access")

	tests := []struct {
		name    string
		path    string
		kid     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "match by kid",
			path:    pubPath,
			kid:     "access",
			wantErr: false,
		},
		{
			name:    "first key (empty kid)",
			path:    pubPath,
			kid:     "",
			wantErr: false,
		},
		{
			name:    "wrong kid",
			path:    pubPath,
			kid:     "wrong",
			wantErr: true,
			errMsg:  "no public key with kid",
		},
		{
			name:    "missing file",
			path:    filepath.Join(t.TempDir(), "nonexistent.json"),
			kid:     "",
			wantErr: true,
			errMsg:  "read jwks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadPublicKeyFromJWKS(tt.path, tt.kid)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				require.Nil(t, key)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, key)
		})
	}
}
