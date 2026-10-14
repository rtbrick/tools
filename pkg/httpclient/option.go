package httpclient

import (
	"net/http"
	"time"
)

type Option func(*HTTPClient)

func WithInsecureSkipVerify() Option {
	return func(c *HTTPClient) {
		c.client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	}
}

func withTimeout(d time.Duration) Option {
	return func(c *HTTPClient) { c.client.Timeout = d }
}
