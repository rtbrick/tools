package apigw

import (
	"github.com/rtbrick/tools/pkg/cmd/flags"
)

const (
	flagCert = flags.FlagCert
	flagKey  = "key"
	flagOrg  = "org"
	flagHost = "host"

	// Unexported aliases to shared flags
	flagKid           = flags.FlagKid
	flagSub           = flags.FlagSub
	flagName          = flags.FlagName
	flagScope         = flags.FlagScope
	flagIss           = flags.FlagIss
	flagDur           = flags.FlagDur
	flagPrivKey       = flags.FlagPrivKey
	flagPubKey        = flags.FlagPubKey
	flagOverrideKid   = flags.FlagOverrideKid
	flagPreferredUser = flags.FlagPreferredUser

	defaultKid         = flags.DefaultKid
	defaultIssuer      = flags.DefaultIssuer
	defaultDuration    = flags.DefaultDuration
	defaultPrivKeyPath = flags.DefaultPrivKeyPath
	defaultPubKeyPath  = flags.DefaultPubKeyPath
	defaultScope       = flags.DefaultScope
	defaultSub         = flags.DefaultSub
	defaultName        = flags.DefaultName
)
