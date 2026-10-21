package license

import (
	"errors"
	"net/url"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rtbrick/tools/pkg/httpclient"
)

// NewDefaultLicenseClient creates a new license service client.
func NewDefaultLicenseClient(voucher string, licenseServerURL *url.URL) *LicenseClient {
	c := httpclient.NewClient(licenseServerURL)

	return &LicenseClient{
		client:  c,
		voucher: voucher,
	}
}

func DecodeVoucher(voucher string) (*Voucher, error) {
	// Decode voucher without verification
	token, err := jwt.ParseSigned(voucher, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, errors.Join(ErrMalformedLicense, err)
	}

	var claims jwt.Claims
	var customClaims VoucherCustomClaims

	err = token.UnsafeClaimsWithoutVerification(&claims, &customClaims)
	if err != nil {
		return nil, errors.Join(ErrInvalidLicense, err)
	}

	return &Voucher{
		Token:        voucher,
		Claims:       &claims,
		CustomClaims: &customClaims,
	}, nil
}
func DecodeLicense(jwks *jose.JSONWebKeySet, license string) (*License, error) {
	// Decode token and verify license key
	token, err := jwt.ParseSigned(license, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, errors.Join(ErrMalformedLicense, err)
	}

	var claims jwt.Claims
	var customClaims LicenseCustomClaims

	err = token.Claims(jwks, &claims, &customClaims)
	if err != nil {
		return nil, errors.Join(ErrInvalidLicense, err)
	}

	return &License{
		Token:        license,
		Claims:       &claims,
		CustomClaims: &customClaims,
	}, nil
}

var (
	ErrMalformedLicense = errors.New("malformed license string")
	ErrInvalidLicense   = errors.New("invalid license signature")
)
