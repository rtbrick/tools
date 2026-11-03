package license

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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

// ListDeviceLicenses lists all licenses, including expired and revoked ones, issued for a device.
// An empty result indicates that no license exists for the device. ErrUnauthorizedVoucher is returned
// if the license server rejects the voucher.
func (c *LicenseClient) ListDeviceLicenses(ctx context.Context, filter *DeviceLicenseFilter) ([]*DeviceLicense, error) {
	query := url.Values{}
	setIfNotEmpty := func(key, value string) {
		if value != "" {
			query.Set(key, value)
		}
	}
	setIfNotEmpty("role", filter.Role)
	setIfNotEmpty("platform_chipset", filter.PlatformChipset)
	setIfNotEmpty("platform_model", filter.PlatformModel)
	setIfNotEmpty("manufacturer", filter.Manufacturer)

	path := "/api/vouchers/licenses/" + url.PathEscape(filter.Fingerprint)
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	req, err := c.client.NewJSONRequestWithContext(
		ctx, http.MethodGet, path, nil,
		httpclient.WithVoucher(c.voucher),
	)
	if err != nil {
		return nil, err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		var licenses []*DeviceLicense
		d := json.NewDecoder(res.Body)
		err = d.Decode(&licenses)
		if err != nil {
			return nil, err
		}
		return licenses, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorizedVoucher
	}
	return nil, &HttpError{Message: "license status request failed", StatusCode: res.StatusCode}
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
}

// DeviceLicenseFilter narrows the licenses of a device. Empty values match all licenses.
type DeviceLicenseFilter struct {
	Fingerprint     string
	Role            string
	PlatformChipset string
	PlatformModel   string
	Manufacturer    string
}
