package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	baseURL, _ := url.Parse(ts.URL)
	client := NewClient(baseURL, WithInsecureSkipVerify())
	assert.NotNil(t, client)
}

func TestNewRequestWithContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.Header
	}))
	defer ts.Close()

	baseURL, _ := url.Parse(ts.URL)
	client := NewClient(baseURL)

	req, err := client.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)
	assert.Contains(t, req.Header.Get("User-Agent"), "rtb-buddy")
	assert.Equal(t, ts.URL+"/test", req.URL.String())
	_ = req
}

func TestNewJSONRequestWithContext(t *testing.T) {
	var testBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testBody, _ = io.ReadAll(r.Body)
	}))
	defer ts.Close()

	baseURL, _ := url.Parse(ts.URL)
	client := NewClient(baseURL)

	req, err := client.NewJSONRequestWithContext(context.Background(), "POST", "/test", map[string]string{"key": "value"})
	require.NoError(t, err)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	assert.Contains(t, string(testBody), `"key":"value"`)
}

func TestWithBearerToken(t *testing.T) {
	var authHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
	}))
	defer ts.Close()

	baseURL, _ := url.Parse(ts.URL)
	client := NewClient(baseURL)

	req, _ := client.NewRequestWithContext(context.Background(), "GET", "/test", nil, WithBearerToken("my-token"))
	_, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-token", authHeader)
}

func TestWithHeader(t *testing.T) {
	var customHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customHeader = r.Header.Get("X-Custom-Header")
	}))
	defer ts.Close()

	baseURL, _ := url.Parse(ts.URL)
	client := NewClient(baseURL)

	req, _ := client.NewRequestWithContext(context.Background(), "GET", "/test", nil, WithHeader("X-Custom-Header", "custom-value"))
	_, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, "custom-value", customHeader)
}

func TestWithQuery(t *testing.T) {
	var queryParam string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryParam = r.URL.RawQuery
	}))
	defer ts.Close()

	baseURL, _ := url.Parse(ts.URL)
	client := NewClient(baseURL)

	req, _ := client.NewRequestWithContext(context.Background(), "GET", "/test", nil, withQuery("foo=bar&baz=qux"))
	_, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, "foo=bar&baz=qux", queryParam)
}

func TestWithInsecureSkipVerify(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	baseURL, _ := url.Parse(ts.URL)
	client := NewClient(baseURL, WithInsecureSkipVerify())

	req, _ := client.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	_, err := client.Do(req)
	require.NoError(t, err)
}

func TestWithTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	baseURL, _ := url.Parse(ts.URL)
	client := NewClient(baseURL, WithTimeout(5*time.Second))
	assert.Equal(t, 5*time.Second, client.client.Timeout)
}
