package generator

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Name          string `json:"name"`
	PreferredUser string `json:"preferred_username"`
	Scope         string `json:"scope"`
	jwt.RegisteredClaims
}

func loadJWKS(path string) (*jose.JSONWebKeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read jwks: %w", err)
	}
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(data, &keySet); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	return &keySet, nil
}

func LoadPrivateKeyFromJWKS(path, kid string) (*rsa.PrivateKey, string, error) {
	keySet, err := loadJWKS(path)
	if err != nil {
		return nil, "", err
	}
	for _, jwk := range keySet.Keys {
		privKey, ok := jwk.Key.(*rsa.PrivateKey)
		if !ok {
			continue
		}
		if kid != "" && jwk.KeyID != kid {
			continue
		}
		return privKey, jwk.KeyID, nil
	}
	if kid != "" {
		return nil, "", fmt.Errorf("no private key with kid %q found in %s", kid, path)
	}
	return nil, "", fmt.Errorf("no private key found in %s", path)
}

func LoadPublicKeyFromJWKS(path, kid string) (*rsa.PublicKey, error) {
	keySet, err := loadJWKS(path)
	if err != nil {
		return nil, err
	}
	for _, jwk := range keySet.Keys {
		pubKey, ok := jwk.Key.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if kid != "" && jwk.KeyID != kid {
			continue
		}
		return pubKey, nil
	}
	if kid != "" {
		return nil, fmt.Errorf("no public key with kid %q found in %s", kid, path)
	}
	return nil, fmt.Errorf("no public key found in %s", path)
}

func GenerateToken(privPath, sub, name, preferredUser, scope, iss, selectKid, overrideKid string, dur time.Duration) (string, error) {
	privateKey, kid, err := LoadPrivateKeyFromJWKS(privPath, selectKid)
	if err != nil {
		return "", fmt.Errorf("load private key: %w", err)
	}

	if overrideKid != "" {
		kid = overrideKid
	}

	now := time.Now()
	claims := Claims{
		Name:          name,
		PreferredUser: preferredUser,
		Scope:         scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    iss,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(dur)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

func InspectToken(raw, jwksPath, overrideKid string) (header map[string]any, claims jwt.MapClaims, valid bool, err error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return nil, nil, false, fmt.Errorf("parse token: %w", err)
	}

	clm, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, false, fmt.Errorf("invalid token claims")
	}

	if jwksPath == "" {
		return token.Header, clm, false, nil
	}

	lookupKid, _ := token.Header["kid"].(string)
	if overrideKid != "" {
		lookupKid = overrideKid
	}
	publicKey, err := LoadPublicKeyFromJWKS(jwksPath, lookupKid)
	if err != nil {
		return token.Header, clm, false, fmt.Errorf("load public key: %w", err)
	}

	_, err = jwt.ParseWithClaims(raw, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})

	return token.Header, clm, err == nil, nil
}
