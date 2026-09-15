package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
)

func GenerateJWKS(privPath, pubPath, kid string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	privKeySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       key,
				KeyID:     kid,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
			{
				Key:       &key.PublicKey,
				KeyID:     kid,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
		},
	}

	privData, err := json.MarshalIndent(privKeySet, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal private jwks: %w", err)
	}

	if err := os.WriteFile(privPath, privData, 0o600); err != nil {
		return fmt.Errorf("write private jwks: %w", err)
	}

	pubKeySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &key.PublicKey,
				KeyID:     kid,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
		},
	}

	pubData, err := json.MarshalIndent(pubKeySet, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal public jwks: %w", err)
	}

	if err := os.WriteFile(pubPath, pubData, 0o644); err != nil {
		return fmt.Errorf("write public jwks: %w", err)
	}

	return nil
}
