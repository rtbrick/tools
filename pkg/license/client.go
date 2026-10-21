package license

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/rtbrick/tools/pkg/httpclient"
)

type LicenseClient struct {
	client      *httpclient.HTTPClient
	voucher     string
	license     *License
	licenseETag string
	jwks        *jose.JSONWebKeySet
	jwksETag    string
}

func (c *LicenseClient) RequestLicense(ctx context.Context, request *VoucherNodeLicenseRequest) (*License, bool, error) {
	req, err := c.client.NewJSONRequestWithContext(
		ctx, http.MethodPost, "/api/vouchers/issue-license", request,
		httpclient.WithIfNoneMatch(c.licenseETag),
		httpclient.WithVoucher(c.voucher),
	)
	if err != nil {
		return nil, false, err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, false, err
	}

	if res.StatusCode == http.StatusNotModified {
		return c.license, false, nil
	}

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		var license License
		d := json.NewDecoder(res.Body)
		err = d.Decode(&license)
		if err != nil {
			return nil, false, err
		}

		c.licenseETag = res.Header.Get("ETag")
		c.license = &license

		return c.license, true, nil
	}

	return nil, false, &HttpError{Message: "license request failed", StatusCode: res.StatusCode}
}

func (c *LicenseClient) RequestJWKS(ctx context.Context) (*jose.JSONWebKeySet, bool, error) {
	req, err := c.client.NewJSONRequestWithContext(
		ctx, http.MethodGet, "/api/vouchers/certs", nil,
		httpclient.WithIfNoneMatch(c.jwksETag),
		httpclient.WithVoucher(c.voucher),
	)
	if err != nil {
		return nil, false, err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, false, err
	}

	if res.StatusCode == http.StatusNotModified {
		return c.jwks, false, nil
	}

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		var jwks jose.JSONWebKeySet
		d := json.NewDecoder(res.Body)
		err = d.Decode(&jwks)
		if err != nil {
			return nil, false, err
		}

		c.jwksETag = res.Header.Get("ETag")
		c.jwks = &jwks
		return c.jwks, true, nil
	}
	return nil, false, fmt.Errorf("license JWKS request failed (%d)", res.StatusCode)
}

type VoucherNodeLicenseRequest struct {
	Fingerprint     string `json:"fingerprint"`
	Role            string `json:"role"`
	PlatformChipset string `json:"platform_chipset"`
	PlatformModel   string `json:"platform_model"`
	Manufacturer    string `json:"manufacturer"`
	ImageID         string `json:"image_id"`
}
