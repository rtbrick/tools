package license

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// LicenseServiceClient downloads node licenses from the portal.
type LicenseServiceClient interface {
	// RequestLicense requests a license from the license server. The boolean indicates whether the license server issued a new license.
	RequestLicense(ctx context.Context, request *VoucherNodeLicenseRequest) (*License, bool, error)
	// RequestJWKS request a JWKS from the license server. The boolean indicates whether the license server issued a new JWKS.
	RequestJWKS(ctx context.Context) (*jose.JSONWebKeySet, bool, error)
}

type HttpError struct {
	Message    string
	StatusCode int
}

func (e *HttpError) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.StatusCode)
}

type Voucher struct {
	Token        string
	Claims       *jwt.Claims          `json:"claims"`
	CustomClaims *VoucherCustomClaims `json:"custom_claims"`
}
type VoucherCustomClaims struct {
	OrganizationUUID string  `json:"oid,omitempty"`
	VoucherName      string  `json:"vnm,omitempty"`
	ProductUUID      string  `json:"pid,omitempty"`
	LicenseServerURL *string `json:"ls,omitempty"`
}
type License struct {
	Token        string               `json:"token"`
	Claims       *jwt.Claims          `json:"claims"`
	CustomClaims *LicenseCustomClaims `json:"custom_claims"`
}

// LicenseCustomClaims models the rtbrick custom claims encoded into the issued license JWT.
type LicenseCustomClaims struct {
	Name              string  `json:"name,omitempty"`
	Fingerprint       string  `json:"fingerprint"`
	Role              string  `json:"role,omitempty"`
	Manufacturer      *string `json:"manufacturer,omitempty"`
	Chipset           *string `json:"chipset,omitempty"`
	Model             *string `json:"model,omitempty"`
	Image             *string `json:"image,omitempty"`
	VoucherUUID       string  `json:"vid,omitempty"`
	OrganizationUUID  string  `json:"oid,omitempty"`
	PurchaseOrderUUID string  `json:"poid,omitempty"`
}

// PredefinedModels maps hardware model keys to their chipset, vendor, and manufacturer.
var PredefinedModels = map[string]struct {
	Chipset      string
	Vendor       string
	Manufacturer string
	Model        string
}{
	//end of life
	"edgecore_AS7316-26XB":   {Chipset: "QAX", Vendor: "EdgeCore", Manufacturer: "accton", Model: "AS7316-26XB"},
	"edgecore_AS7535-28XB":   {Chipset: "Q2A", Vendor: "EdgeCore", Manufacturer: "accton", Model: "AS7535-28XB"},
	"edgecore_AS7946-30XB":   {Chipset: "Q2C", Vendor: "EdgeCore", Manufacturer: "accton", Model: "AS7946-30XB"},
	"edgecore_AS7946-74XKSB": {Chipset: "Q2C", Vendor: "EdgeCore", Manufacturer: "accton", Model: "AS7946-74XKSB"},
	"ufispace_S9510-28DC":    {Chipset: "Q2A", Vendor: "ufiSpace", Manufacturer: "ufispace", Model: "S9510-28DC"},
	"ufispace_S9600-102XC":   {Chipset: "Q2C", Vendor: "ufiSpace", Manufacturer: "ufispace", Model: "S9600-102XC"},
	"ufispace_S9600-32X":     {Chipset: "Q2C", Vendor: "ufiSpace", Manufacturer: "ufispace", Model: "S9600-32X"},
	"ufispace_S9600-72XC":    {Chipset: "Q2C", Vendor: "ufiSpace", Manufacturer: "ufispace", Model: "S9600-72XC"},
	"ufispace_S9500-22XST":   {Chipset: "QAX", Vendor: "ufiSpace", Manufacturer: "ufispace", Model: "S9500-22XST"},
}

// PredefinedRoles lists the valid device roles.
var PredefinedRoles = []string{
	"accessleaf",
	"l2bsa",
	"multiservice-edge",
	"spine",
}
