package voucher

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rtbrick/tools/pkg/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestVoucher(t *testing.T, licenseServerURL string) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, nil)
	require.NoError(t, err)
	token, err := jwt.Signed(signer).
		Claims(jwt.Claims{Subject: "test"}).
		Claims(license.VoucherCustomClaims{LicenseServerURL: &licenseServerURL}).
		Serialize()
	require.NoError(t, err)
	return token
}

func runCheckLicense(t *testing.T, handler http.HandlerFunc, args ...string) (string, error) {
	t.Helper()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	cmd := NewCheckLicenseCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(append([]string{"--voucher", newTestVoucher(t, ts.URL)}, args...))
	err := cmd.Execute()
	return buf.String(), err
}

func TestCheckLicense(t *testing.T) {
	var path, query string
	out, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		query = r.URL.RawQuery
		assert.Contains(t, r.Header.Get("Authorization"), "Voucher ")
		_, _ = w.Write([]byte(`[{
			"license_id": "lic-1",
			"fingerprint": "SERIAL-1",
			"status": "active",
			"purchase_order_id": "po-1",
			"purchase_order_name": "PO 1",
			"product": {"product_id": "p-1", "product_name": "mse", "display_name": "Multiservice Edge",
				"image_role": {"image_role_id": "r-1", "image_role": "multiservice-edge", "display_name": "MSE"}},
			"platform": {"platform_id": "pf-1", "platform_model": "S9510-28DC", "platform_chipset": "Q2A",
				"manufacturer": "ufispace", "vendor": {"vendor_id": "v-1", "vendor_name": "ufiSpace"}},
			"tsnotbefore": "2026-01-01T00:00:00Z",
			"tsnotafter": null,
			"tscreated": "2026-01-01T00:00:00Z"
		}]`))
	}, "--fingerprint", "SERIAL-1", "--model", "ufispace_S9510-28DC", "--role", "multiservice-edge")
	require.NoError(t, err)

	assert.Equal(t, "/api/vouchers/licenses/SERIAL-1", path)
	assert.Equal(t, "manufacturer=ufispace&platform_chipset=Q2A&platform_model=S9510-28DC&role=multiservice-edge", query)
	assert.Contains(t, out, "License 1 of 1")
	assert.Contains(t, out, "active")
	assert.Contains(t, out, "lic-1")
	assert.Contains(t, out, "Multiservice Edge")
	assert.Contains(t, out, "<unlimited>")
	assert.NotContains(t, out, "Revoked:")
}

func TestCheckLicense_JSON(t *testing.T) {
	out, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"license_id":"lic-1","status":"active","unknown_field":{"a":1}}]`))
	}, "--fingerprint", "SERIAL-1", "--format", "json")
	require.NoError(t, err)
	assert.Equal(t, `[
  {
    "license_id": "lic-1",
    "status": "active",
    "unknown_field": {
      "a": 1
    }
  }
]
`, out)
}

func TestCheckLicense_JSONNoLicense(t *testing.T) {
	out, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}, "--fingerprint", "SERIAL-1", "--format", "json")
	require.NoError(t, err)
	assert.Equal(t, "[]\n", out)
}

func TestCheckLicense_JSONUnauthorized(t *testing.T) {
	_, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}, "--fingerprint", "SERIAL-1", "--format", "json")
	require.ErrorIs(t, err, license.ErrUnauthorizedVoucher)
}

func TestCheckLicense_NoLicense(t *testing.T) {
	var query string
	out, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	}, "--fingerprint", "SERIAL-1")
	require.NoError(t, err)
	assert.Empty(t, query)
	assert.Contains(t, out, "No license found for device SERIAL-1")
}

func TestCheckLicense_Unauthorized(t *testing.T) {
	_, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}, "--fingerprint", "SERIAL-1")
	require.ErrorIs(t, err, license.ErrUnauthorizedVoucher)
}

func TestCheckLicense_ServerError(t *testing.T) {
	_, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, "--fingerprint", "SERIAL-1")
	var httpErr *license.HttpError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
}

func TestCheckLicense_UnknownModel(t *testing.T) {
	_, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected request")
	}, "--fingerprint", "SERIAL-1", "--model", "unknown")
	require.ErrorContains(t, err, `unknown model "unknown"`)
}

func TestCheckLicense_TextFormat(t *testing.T) {
	out, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}, "--fingerprint", "SERIAL-1", "--format", "text")
	require.NoError(t, err)
	assert.Contains(t, out, "No license found for device SERIAL-1")
}

func TestCheckLicense_UnknownFormat(t *testing.T) {
	_, err := runCheckLicense(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected request")
	}, "--fingerprint", "SERIAL-1", "--format", "yaml")
	require.ErrorContains(t, err, `unknown format "yaml"`)
}
