package license

import (
	"context"
	"fmt"
	"time"

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

// DeviceLicenseStatus describes the state of a device license at the time of the request.
type DeviceLicenseStatus string

const (
	DeviceLicenseStatusActive  DeviceLicenseStatus = "active"
	DeviceLicenseStatusPending DeviceLicenseStatus = "pending"
	DeviceLicenseStatusExpired DeviceLicenseStatus = "expired"
	DeviceLicenseStatusRevoked DeviceLicenseStatus = "revoked"
)

// DeviceLicense describes a license issued for a device and its current status.
type DeviceLicense struct {
	LicenseUUID       string              `json:"license_id"`
	Fingerprint       string              `json:"fingerprint"`
	Alias             *string             `json:"alias,omitempty"`
	Status            DeviceLicenseStatus `json:"status"`
	PurchaseOrderUUID string              `json:"purchase_order_id"`
	PurchaseOrderName string              `json:"purchase_order_name"`
	Product           *ProductInfo        `json:"product"`
	Platform          *PlatformInfo       `json:"platform"`
	Tsnotbefore       time.Time           `json:"tsnotbefore"`
	Tsnotafter        *time.Time          `json:"tsnotafter"`
	Tscreated         time.Time           `json:"tscreated"`
	Tsrevoked         *time.Time          `json:"tsrevoked,omitempty"`
}

type ProductInfo struct {
	UUID        string         `json:"product_id"`
	Name        string         `json:"product_name"`
	DisplayName string         `json:"display_name"`
	ImageRole   *ImageRoleInfo `json:"image_role"`
}

type ImageRoleInfo struct {
	ImageRoleUUID string `json:"image_role_id"`
	Name          string `json:"image_role"`
	DisplayName   string `json:"display_name"`
}

type PlatformInfo struct {
	PlatformUUID    string      `json:"platform_id"`
	PlatformModel   string      `json:"platform_model"`
	PlatformChipset string      `json:"platform_chipset"`
	Manufacturer    string      `json:"manufacturer"`
	Vendor          *VendorInfo `json:"vendor"`
}

type VendorInfo struct {
	VendorUUID string `json:"vendor_id"`
	Name       string `json:"vendor_name"`
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
	"ufispace_S9610-46DX":    {Chipset: "Q2CP", Vendor: "ufiSpace", Manufacturer: "ufispace", Model: "S9610-46DX"},
}

// PredefinedRoles lists the valid device roles.
var PredefinedRoles = []string{
	"accessleaf",
	"l2bsa",
	"multiservice-edge",
	"spine",
}
