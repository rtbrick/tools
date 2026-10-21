package voucher

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/fatih/color"
	"github.com/go-jose/go-jose/v4"
	"github.com/rtbrick/tools/pkg/license"
	"github.com/spf13/cobra"
)

var labelColor = color.New(color.FgCyan).SprintFunc()

func NewLicenseCmd() *cobra.Command {
	var voucher string
	var fingerprint string
	var role string
	var model string
	var imageID string

	cmd := &cobra.Command{
		Use:   "license",
		Short: "Request a license from a voucher",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			m, ok := license.PredefinedModels[model]
			if !ok {
				return fmt.Errorf("unknown model %q", model)
			}

			status, err := license.DecodeVoucher(voucher)
			if err != nil {
				return fmt.Errorf("failed to decode voucher: %w", err)
			}

			if status.CustomClaims == nil || status.CustomClaims.LicenseServerURL == nil {
				return fmt.Errorf("voucher does not contain a license server URL")
			}

			ls, err := url.Parse(*status.CustomClaims.LicenseServerURL)
			if err != nil {
				return fmt.Errorf("failed to parse license server URL: %w", err)
			}

			client := license.NewDefaultLicenseClient(voucher, ls)

			jwks, licToken, _, err := requestLicense(ctx, client, &license.VoucherNodeLicenseRequest{
				Fingerprint:     fingerprint,
				Role:            role,
				PlatformChipset: m.Chipset,
				PlatformModel:   m.Model,
				Manufacturer:    m.Manufacturer,
				ImageID:         imageID,
			})
			if err != nil {
				return fmt.Errorf("failed to request license: %w", err)
			}

			l, err := license.DecodeLicense(jwks, licToken)
			if err != nil {
				return fmt.Errorf("failed to decode license: %w", err)
			}

			strVal := func(s *string) string {
				if s == nil {
					return "<not set>"
				}
				return *s
			}

			cmd.Println(labelColor("License Token:"), l.Token)
			cmd.Println(labelColor("Issuer:"), l.Claims.Issuer)
			cmd.Println(labelColor("Subject:"), l.Claims.Subject)
			cmd.Println(labelColor("Fingerprint:"), l.CustomClaims.Fingerprint)
			cmd.Println(labelColor("Role:"), l.CustomClaims.Role)
			cmd.Println(labelColor("Manufacturer:"), strVal(l.CustomClaims.Manufacturer))
			cmd.Println(labelColor("Chipset:"), strVal(l.CustomClaims.Chipset))
			cmd.Println(labelColor("Model:"), strVal(l.CustomClaims.Model))
			cmd.Println(labelColor("Image:"), strVal(l.CustomClaims.Image))
			cmd.Println(labelColor("Voucher UUID:"), l.CustomClaims.VoucherUUID)

			return nil
		},
	}

	cmd.Flags().StringVar(&voucher, flagVoucher, "", "Voucher JWT string")
	cmd.Flags().StringVar(&fingerprint, flagFingerprint, "", "Device fingerprint")
	cmd.Flags().StringVar(&role, flagRole, "", "Device role")
	if err := cmd.RegisterFlagCompletionFunc(flagRole, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return license.PredefinedRoles, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
	cmd.Flags().StringVar(&model, flagModel, "", "Hardware model (one of predefined models)")
	if err := cmd.RegisterFlagCompletionFunc(flagModel, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var models []string
		for m := range license.PredefinedModels {
			models = append(models, m)
		}
		return models, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
	cmd.Flags().StringVar(&imageID, flagImageID, "", "Image ID (optional)")

	if err := cmd.MarkFlagRequired(flagVoucher); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagFingerprint); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagRole); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagModel); err != nil {
		panic(err)
	}

	return cmd
}

func requestLicense(ctx context.Context, client *license.LicenseClient, request *license.VoucherNodeLicenseRequest) (*jose.JSONWebKeySet, string, bool, error) {
	lic, isNew, err := client.RequestLicense(ctx, request)
	if err != nil {
		return nil, "", false, err
	}
	jwks, _, err := client.RequestJWKS(ctx)
	if err != nil {
		return nil, "", false, err
	}
	return jwks, lic.Token, isNew, nil
}
