package lix1

import "time"

const (
	flagCACrt        = "ca-crt"
	flagCACrtKey     = "ca-crt-key"
	flagCrt          = "crt"
	flagCrtKey       = "crt-key"
	flagCN           = "cn"
	flagOrg          = "org"
	flagOU           = "ou"
	flagDuration     = "duration"
	flagUID          = "uid"
	flagDNSName      = "dns"
	flagIPAddress    = "ip"
	flagX1Role       = "x1-role"
	flagX1Identifier = "x1-identifier"

	defaultCACrt    = "ca.crt"
	defaultCACrtKey = "ca.key"
	defaultDuration = 10 * 365 * 24 * time.Hour
)
