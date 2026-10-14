package httpclient

// Header keys
const (
	HeaderContentType   = "Content-Type"
	HeaderAccept        = "Accept"
	headerAuthorization = "Authorization"
	headerUserAgent     = "User-Agent"
)

// Header values
const (
	ContentTypeJSON         = "application/json"
	ContentTypeYANGDataJSON = "application/yang-data+json"
	acceptJSON              = "application/json"
	AcceptYANGDataJSON      = "application/yang-data+json"
	acceptAny               = "*/*"
	authPrefixBearer        = "Bearer "
)
