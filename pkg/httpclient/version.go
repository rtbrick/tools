package httpclient

import "runtime"

// Version is the current version of the httpclient library
const Version = "0.1.0"

var userAgent = "rtb-buddy/" + Version + " golang/" + runtime.Version()
