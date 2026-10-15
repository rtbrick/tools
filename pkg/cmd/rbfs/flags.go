package rbfs

import (
	"github.com/rtbrick/tools/pkg/cmd/flags"
)

const (
	flagCert        = flags.FlagCert
	flagCertKey     = flags.FlagCertKey
	flagElement     = "element"
	flagOutput      = "output"
	flagOutputShort = "o"
	flagAuthMode    = "auth-mode"
	flagPath        = "path"
	flagPathShort   = "p"
	flagFile        = "file"
	flagFileShort   = "f"

	// Unexported aliases to shared flags
	flagPrivKey = flags.FlagPrivKey
	flagKid     = flags.FlagKid
	flagSub     = flags.FlagSub
	flagName    = flags.FlagName
	flagScope   = flags.FlagScope
	flagIss     = flags.FlagIss
	flagDur     = flags.FlagDur

	defaultAuthMode    = false
	defaultPrivKeyPath = flags.DefaultPrivKeyPath
	defaultKid         = flags.DefaultKid
	defaultScope       = flags.DefaultScope
	defaultIssuer      = flags.DefaultIssuer
	defaultDuration    = flags.DefaultDuration
	defaultPortHTTP    = "19091"
	defaultPortHTTPS   = "12321"
	defaultSub         = flags.DefaultSub
	defaultName        = flags.DefaultName
)
