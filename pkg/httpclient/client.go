package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient is a generic HTTP client for REST API calls
type HTTPClient struct {
	client  *http.Client
	baseURL *url.URL
}

// NewClient creates a new HTTP client with the given base URL and options
func NewClient(baseURL *url.URL, opts ...Option) *HTTPClient {
	c := &HTTPClient{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		},
		baseURL: baseURL,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// NewRequestWithContext creates an HTTP request with the given method and path
// The path is resolved relative to the base URL
func (c *HTTPClient) NewRequestWithContext(ctx context.Context, method, path string, body io.Reader, opts ...RequestOption) (*http.Request, error) {
	rel, err := url.Parse(strings.TrimPrefix(path, "/"))
	if err != nil {
		return nil, err
	}
	u := c.baseURL.ResolveReference(rel)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Add(headerUserAgent, userAgent)
	for _, o := range opts {
		o(req)
	}
	return req, nil
}

// newJSONRequestWithContext creates an HTTP request with a JSON body
// The Content-Type and Accept headers are set to application/json
func (c *HTTPClient) newJSONRequestWithContext(ctx context.Context, method, path string, body any, opts ...RequestOption) (*http.Request, error) {
	var req *http.Request
	var err error

	if body != nil {
		var jsonBody []byte
		if data, ok := body.([]byte); ok {
			jsonBody = data
		} else {
			jsonBody, err = json.Marshal(body)
			if err != nil {
				return nil, err
			}
		}
		buf := bytes.NewReader(jsonBody)
		req, err = c.NewRequestWithContext(ctx, method, path, buf, opts...)
		if err != nil {
			return nil, err
		}
	} else {
		req, err = c.NewRequestWithContext(ctx, method, path, nil, opts...)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set(HeaderContentType, ContentTypeJSON)
	req.Header.Set(HeaderAccept, acceptJSON+","+acceptAny)
	return req, nil
}

// Do performs the given HTTP request
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// GetBaseURL returns the current base URL
func (c *HTTPClient) GetBaseURL() *url.URL {
	return c.baseURL
}
