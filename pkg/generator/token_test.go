package generator

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

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
			privPath:    "testdata/nonexistent.json",
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

func TestIntegration_GenerateAndInspect(t *testing.T) {
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}

	privPath := "testdata/priv.json"
	pubPath := "testdata/pub.json"
	t.Cleanup(func() {
		_ = os.Remove(privPath)
		_ = os.Remove(pubPath)
	})

	// Mimic: rtb-buddy apigw generate jwks
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
