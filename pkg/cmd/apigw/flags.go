package apigw

import "time"

const (
	flagPriv          = "priv"
	flagPub           = "pub"
	flagKid           = "kid"
	flagOverrideKid   = "override-kid"
	flagSub           = "sub"
	flagName          = "name"
	flagPreferredUser = "preferred-username"
	flagScope         = "scope"
	flagIss           = "iss"
	flagDur           = "dur"
	flagCert          = "cert"
	flagKey           = "key"
	flagOrg           = "org"
	flagHost          = "host"

	defaultKid      = "access"
	defaultIssuer   = "rtbrick"
	defaultDuration = 1 * time.Hour
	defaultPrivPath = "apigw-jwks-priv.json"
	defaultPubPath  = "apigw-jwks.json"
)
