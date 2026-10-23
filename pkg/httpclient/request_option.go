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
func WithVoucher(value string) RequestOption {
	return func(r *http.Request) {
		r.Header.Set("Authorization", "Voucher "+value)
	}
}

func WithIfNoneMatch(etag string) RequestOption {
	return func(r *http.Request) {
		if etag != "" {
			r.Header.Set("If-None-Match", etag)
		}
	}
}
func withQuery(query string) RequestOption {
	return func(r *http.Request) {
		r.URL.RawQuery = query
	}
}
