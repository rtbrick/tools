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
	client  *httpclient.HTTPClient
	voucher string
}

func (c *LicenseClient) RequestLicense(ctx context.Context, request *VoucherNodeLicenseRequest) (*License, error) {
	req, err := c.client.NewJSONRequestWithContext(
		ctx, http.MethodPost, "/api/vouchers/issue-license", request,
		httpclient.WithVoucher(c.voucher),
	)
	if err != nil {
		return nil, err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		var license License
		d := json.NewDecoder(res.Body)
		err = d.Decode(&license)
		if err != nil {
			return nil, err
		}
		return &license, nil
	}
	return nil, &HttpError{Message: "license request failed", StatusCode: res.StatusCode}
}

func (c *LicenseClient) RequestJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := c.client.NewJSONRequestWithContext(
		ctx, http.MethodGet, "/api/vouchers/certs", nil,
		httpclient.WithVoucher(c.voucher),
	)
	if err != nil {
		return nil, err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		var jwks jose.JSONWebKeySet
		d := json.NewDecoder(res.Body)
		err = d.Decode(&jwks)
		if err != nil {
			return nil, err
		}

		return &jwks, nil
	}
	return nil, fmt.Errorf("license JWKS request failed (%d)", res.StatusCode)
}

type VoucherNodeLicenseRequest struct {
	Fingerprint     string `json:"fingerprint"`
	Role            string `json:"role"`
	PlatformChipset string `json:"platform_chipset"`
	PlatformModel   string `json:"platform_model"`
	Manufacturer    string `json:"manufacturer"`
	ImageID         string `json:"image_id"`
}
