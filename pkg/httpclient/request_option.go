package httpclient

import "net/http"

type RequestOption func(*http.Request)

func WithBearerToken(token string) RequestOption {
	return func(r *http.Request) {
		r.Header.Set(headerAuthorization, authPrefixBearer+token)
	}
}

func WithHeader(key, value string) RequestOption {
	return func(r *http.Request) {
		r.Header.Set(key, value)
	}
}

func withQuery(query string) RequestOption {
	return func(r *http.Request) {
		r.URL.RawQuery = query
	}
}
