package voucher

const (
	flagVoucher     = "voucher"
	flagFingerprint = "fingerprint"
	flagRole        = "role"
	flagModel       = "model"
	flagOutput      = "output"
	flagFormat      = "format"
)

const (
	formatText = "text"
	formatJSON = "json"
)

var outputFormats = []string{formatText, formatJSON}
