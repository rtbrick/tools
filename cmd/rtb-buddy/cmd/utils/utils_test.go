package utils

import (
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
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

// --- GenerateJWKS ---

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

// --- LoadPrivateKeyFromJWKS ---

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

// --- LoadPublicKeyFromJWKS ---

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

// --- GenerateToken ---

func TestGenerateToken(t *testing.T) {
	privPath, pubPath := generateTestJWKS(t, "access")

	tests := []struct {
		name        string
		privPath    string
		selectKid   string
		overrideKid string
		wantErr     bool
	}{
		{
			name:        "default (empty kid selects first)",
			privPath:    privPath,
			selectKid:   "",
			overrideKid: "",
			wantErr:     false,
		},
		{
			name:        "select by kid",
			privPath:    privPath,
			selectKid:   "access",
			overrideKid: "",
			wantErr:     false,
		},
		{
			name:        "override kid in header",
			privPath:    privPath,
			selectKid:   "access",
			overrideKid: "rotated",
			wantErr:     false,
		},
		{
			name:        "wrong kid",
			privPath:    privPath,
			selectKid:   "wrong",
			overrideKid: "",
			wantErr:     true,
		},
		{
			name:        "missing private key file",
			privPath:    filepath.Join(t.TempDir(), "nonexistent.json"),
			selectKid:   "",
			overrideKid: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(
				tt.privPath,
				"test-sub",
				"Test User",
				"testuser",
				"admin",
				"rtbrick",
				tt.selectKid,
				tt.overrideKid,
				1*time.Hour,
			)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, token)

			// Token should be parseable with correct claims
			parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
				pubKey, err := LoadPublicKeyFromJWKS(pubPath, "")
				if err != nil {
					return nil, err
				}
				return pubKey, nil
			})
			require.NoError(t, err)
			require.True(t, parsed.Valid)

			claims, ok := parsed.Claims.(*Claims)
			require.True(t, ok)
			require.Equal(t, "test-sub", claims.Subject)
			require.Equal(t, "Test User", claims.Name)
			require.Equal(t, "testuser", claims.PreferredUser)
			require.Equal(t, "admin", claims.Scope)
			require.Equal(t, "rtbrick", claims.Issuer)

			// Check header kid
			headerKid, _ := parsed.Header["kid"].(string)
			if tt.overrideKid != "" {
				require.Equal(t, tt.overrideKid, headerKid)
			} else {
				require.Equal(t, "access", headerKid)
			}
		})
	}
}

// --- InspectToken ---

func TestInspectToken(t *testing.T) {
	privPath, pubPath := generateTestJWKS(t, "access")

	token, err := GenerateToken(privPath, "sub123", "Alice", "alice", "user", "rtbrick", "", "", 1*time.Hour)
	require.NoError(t, err)

	overrideToken, err := GenerateToken(privPath, "sub123", "Alice", "alice", "user", "rtbrick", "access", "rotated", 1*time.Hour)
	require.NoError(t, err)

	tests := []struct {
		name        string
		raw         string
		jwksPath    string
		overrideKid string
		wantValid   bool
		wantErr     bool
	}{
		{
			name:        "unverified (no public key)",
			raw:         token,
			jwksPath:    "",
			overrideKid: "",
			wantValid:   false,
			wantErr:     false,
		},
		{
			name:        "verified with matching kid",
			raw:         token,
			jwksPath:    pubPath,
			overrideKid: "",
			wantValid:   true,
			wantErr:     false,
		},
		{
			name:        "verified with override kid",
			raw:         overrideToken,
			jwksPath:    pubPath,
			overrideKid: "access",
			wantValid:   true,
			wantErr:     false,
		},
		{
			name:        "invalid token",
			raw:         "not.a.jwt",
			jwksPath:    pubPath,
			overrideKid: "",
			wantErr:     true,
		},
		{
			name:        "empty input",
			raw:         "",
			jwksPath:    "",
			overrideKid: "",
			wantErr:     true,
		},
		{
			name:        "tampered token",
			raw:         token + "x",
			jwksPath:    pubPath,
			overrideKid: "",
			wantValid:   false,
			wantErr:     false, // signature fails but function returns valid=false
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, claims, valid, err := InspectToken(tt.raw, tt.jwksPath, tt.overrideKid)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, header)
			require.NotNil(t, claims)
			require.Equal(t, tt.wantValid, valid)

			// Verify claims for non-error cases
			if tt.raw == token || tt.raw == overrideToken {
				require.Equal(t, "sub123", claims["sub"])
				require.Equal(t, "Alice", claims["name"])
				require.Equal(t, "alice", claims["preferred_username"])
			}
		})
	}
}

// --- Integration ---

func TestIntegration_GenerateAndInspect(t *testing.T) {
	// Mimic: rtb-buddy apigw generate jwks
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.json")
	pubPath := filepath.Join(dir, "pub.json")
	require.NoError(t, GenerateJWKS(privPath, pubPath, "access"))

	// Mimic: rtb-buddy apigw generate token
	token, err := GenerateToken(
		privPath,
		"1234567890",
		"Alice",
		"alice",
		"supervisor",
		"rtbrick",
		"access",
		"",
		1*time.Hour,
	)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Mimic: echo "<token>" | rtb-buddy apigw inspect token
	header, claims, valid, err := InspectToken(token, pubPath, "")
	require.NoError(t, err)
	require.True(t, valid, "token should be valid when verified with correct public key")

	// Verify header
	require.Equal(t, "access", header["kid"])
	require.Equal(t, "RS256", header["alg"])

	// Verify claims
	require.Equal(t, "1234567890", claims["sub"])
	require.Equal(t, "Alice", claims["name"])
	require.Equal(t, "alice", claims["preferred_username"])
	require.Equal(t, "supervisor", claims["scope"])
	require.Equal(t, "rtbrick", claims["iss"])

	// Verify expiration is in the future
	exp, ok := claims["exp"].(float64)
	require.True(t, ok, "exp should be a number")
	require.Greater(t, exp, float64(time.Now().Unix()), "token should not be expired")
}
