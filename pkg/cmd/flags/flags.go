package flags

import "time"

const (
	FlagKid           = "kid"
	FlagSub           = "sub"
	FlagName          = "name"
	FlagScope         = "scope"
	FlagIss           = "iss"
	FlagDur           = "dur"
	FlagPrivKey       = "priv-key"
	FlagPubKey        = "pub-key"
	FlagOverrideKid   = "override-kid"
	FlagPreferredUser = "preferred-username"

	DefaultKid         = "access"
	DefaultIssuer      = "rtbrick"
	DefaultDuration    = 30 * time.Second
	DefaultPrivKeyPath = "apigw-jwks-priv.json"
	DefaultPubKeyPath  = "apigw-jwks.json"
	DefaultScope       = "supervisor"
	DefaultSub         = "78228339"
	DefaultName        = "rtb-buddy"
)
