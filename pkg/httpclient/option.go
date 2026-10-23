package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

type Option func(*HTTPClient)

func WithInsecureSkipVerify() Option {
	return func(c *HTTPClient) {
		c.client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	}
}

// WithClientCert loads a client certificate/key pair for mTLS and appends it
// to the client's TLS configuration.
func WithClientCert(certFile, keyFile string) Option {
	return func(c *HTTPClient) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			panic(fmt.Sprintf("load client cert/key: %v", err))
		}
		c.client.Transport.(*http.Transport).TLSClientConfig.Certificates =
			append(c.client.Transport.(*http.Transport).TLSClientConfig.Certificates, cert)
	}
}

func WithTimeout(d time.Duration) Option {
	return func(c *HTTPClient) { c.client.Timeout = d }
}
