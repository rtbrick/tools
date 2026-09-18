package lix1

import "time"

const (
	flagCACrt    = "ca-crt"
	flagCACrtKey = "ca-crt-key"
	flagCrt      = "crt"
	flagCrtKey   = "crt-key"
	flagCN       = "cn"
	flagOrg      = "org"
	flagOU       = "ou"
	flagDuration = "duration"

	defaultCACrt    = "ca.crt"
	defaultCACrtKey = "ca.key"
	defaultDuration = 10 * 365 * 24 * time.Hour
)
