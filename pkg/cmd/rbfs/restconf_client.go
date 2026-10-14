package rbfs

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rtbrick/tools/pkg/generator"
	"github.com/rtbrick/tools/pkg/httpclient"
)

type restConfClient struct {
	*httpclient.HTTPClient
	basepath string
	element  string
	authMode bool
	tokenCfg tokenConfig
}

type tokenConfig struct {
	PrivKeyPath string
	Kid         string
	Sub         string
	Name        string
	Scope       string
	Issuer      string
	Duration    time.Duration
}

func newRestConfClient(basepath string, opts ...restconfOption) (*restConfClient, error) {
	c := &restConfClient{
		basepath: basepath,
		element:  basepath,
		authMode: defaultAuthMode,
		tokenCfg: tokenConfig{
			PrivKeyPath: defaultPrivKeyPath,
			Kid:         defaultKid,
			Sub:         defaultSub,
			Name:        defaultName,
			Scope:       defaultScope,
			Issuer:      defaultIssuer,
			Duration:    defaultDuration,
		},
	}
	for _, o := range opts {
		o(c)
	}

	port := defaultPortHTTP
	scheme := "http"
	if c.authMode {
		port = defaultPortHTTPS
		scheme = "https"
	}
	baseURL := &url.URL{
		Scheme: scheme,
		Host:   c.basepath + ":" + port,
		Path:   "/api/v1/rbfs/elements/" + c.element + "/services/restconfd/proxy/restconf/data/",
	}

	hc := httpclient.NewClient(baseURL, httpclient.WithInsecureSkipVerify())
	c.HTTPClient = hc
	return c, nil
}

type restconfOption func(*restConfClient)

func withElement(e string) restconfOption { return func(c *restConfClient) { c.element = e } }
func withAuthMode(m bool) restconfOption  { return func(c *restConfClient) { c.authMode = m } }
func withTokenConfig(tc tokenConfig) restconfOption {
	return func(c *restConfClient) { c.tokenCfg = tc }
}

func (c *restConfClient) Get(ctx context.Context, path, query string) ([]byte, error) {
	token, err := c.generateToken()
	if err != nil {
		return nil, err
	}
	fullURL := c.BuildURL(path, query)
	req, err := c.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil,
		httpclient.WithBearerToken(token),
		httpclient.WithHeader(httpclient.HeaderAccept, httpclient.AcceptYANGDataJSON),
	)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

func (c *restConfClient) Put(ctx context.Context, path, query string, body []byte) ([]byte, error) {
	token, err := c.generateToken()
	if err != nil {
		return nil, err
	}
	fullURL := c.BuildURL(path, query)
	req, err := c.NewRequestWithContext(ctx, http.MethodPut, fullURL, bytes.NewReader(body),
		httpclient.WithBearerToken(token),
		httpclient.WithHeader(httpclient.HeaderContentType, httpclient.ContentTypeYANGDataJSON),
		httpclient.WithHeader(httpclient.HeaderAccept, httpclient.AcceptYANGDataJSON),
	)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

func (c *restConfClient) Patch(ctx context.Context, path, query string, body []byte) ([]byte, error) {
	token, err := c.generateToken()
	if err != nil {
		return nil, err
	}
	fullURL := c.BuildURL(path, query)
	req, err := c.NewRequestWithContext(ctx, http.MethodPatch, fullURL, bytes.NewReader(body),
		httpclient.WithBearerToken(token),
		httpclient.WithHeader(httpclient.HeaderContentType, httpclient.ContentTypeYANGDataJSON),
		httpclient.WithHeader(httpclient.HeaderAccept, httpclient.AcceptYANGDataJSON),
	)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

func (c *restConfClient) Delete(ctx context.Context, path, query string) ([]byte, error) {
	token, err := c.generateToken()
	if err != nil {
		return nil, err
	}
	fullURL := c.BuildURL(path, query)
	req, err := c.NewRequestWithContext(ctx, http.MethodDelete, fullURL, nil,
		httpclient.WithBearerToken(token),
		httpclient.WithHeader(httpclient.HeaderAccept, httpclient.AcceptYANGDataJSON),
	)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

func (c *restConfClient) doRequest(req *http.Request) ([]byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return nil, &restconfError{StatusCode: resp.StatusCode, Body: body}
	}
	return body, nil
}

func (c *restConfClient) generateToken() (string, error) {
	if !c.authMode {
		return "", nil
	}
	return generator.GenerateToken(
		c.tokenCfg.PrivKeyPath,
		c.tokenCfg.Sub,
		c.tokenCfg.Name,
		"",
		c.tokenCfg.Scope,
		c.tokenCfg.Issuer,
		c.tokenCfg.Kid,
		"",
		c.tokenCfg.Duration,
	)
}

type restconfError struct {
	StatusCode int
	Body       []byte
}

func (e *restconfError) Error() string {
	return string(e.Body)
}

func (c *restConfClient) BuildURL(path, query string) string {
	return c.GetBaseURL().ResolveReference(&url.URL{Path: path, RawQuery: query}).String()
}
