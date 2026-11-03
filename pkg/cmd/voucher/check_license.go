package voucher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/fatih/color"
	"github.com/rtbrick/tools/pkg/license"
	"github.com/spf13/cobra"
)

var statusColors = map[license.DeviceLicenseStatus]func(a ...interface{}) string{
	license.DeviceLicenseStatusActive:  color.New(color.FgGreen, color.Bold).SprintFunc(),
	license.DeviceLicenseStatusPending: color.New(color.FgYellow, color.Bold).SprintFunc(),
	license.DeviceLicenseStatusExpired: color.New(color.FgRed, color.Bold).SprintFunc(),
	license.DeviceLicenseStatusRevoked: color.New(color.FgRed, color.Bold).SprintFunc(),
}

func NewCheckLicenseCmd() *cobra.Command {
	var voucher string
	var fingerprint string
	var role string
	var model string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "license",
		Short: "Check the license status of a device",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			filter := &license.DeviceLicenseFilter{
				Fingerprint: fingerprint,
				Role:        role,
			}
			if model != "" {
				m, ok := license.PredefinedModels[model]
				if !ok {
					return fmt.Errorf("unknown model %q", model)
				}
				filter.PlatformChipset = m.Chipset
				filter.PlatformModel = m.Model
				filter.Manufacturer = m.Manufacturer
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

			if jsonOutput {
				data, err := client.ListDeviceLicensesJSON(ctx, filter)
				if errors.Is(err, license.ErrUnauthorizedVoucher) {
					return err
				}
				if err != nil {
					return fmt.Errorf("failed to check license: %w", err)
				}
				var pretty bytes.Buffer
				if err := json.Indent(&pretty, data, "", "  "); err != nil {
					return fmt.Errorf("failed to format license status response: %w", err)
				}
				cmd.Println(pretty.String())
				return nil
			}

			licenses, err := client.ListDeviceLicenses(ctx, filter)
			if errors.Is(err, license.ErrUnauthorizedVoucher) {
				return err
			}
			if err != nil {
				return fmt.Errorf("failed to check license: %w", err)
			}

			if len(licenses) == 0 {
				cmd.Printf("No license found for device %s\n", fingerprint)
				return nil
			}

			printDeviceLicenses(cmd, licenses)
			return nil
		},
	}

	cmd.Flags().StringVar(&voucher, flagVoucher, "", "Voucher JWT string")
	cmd.Flags().StringVar(&fingerprint, flagFingerprint, "", "Device fingerprint (serial number)")
	cmd.Flags().StringVar(&role, flagRole, "", "Device role (optional)")
	if err := cmd.RegisterFlagCompletionFunc(flagRole, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return license.PredefinedRoles, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
	cmd.Flags().StringVar(&model, flagModel, "", "Hardware model (optional, one of predefined models)")
	if err := cmd.RegisterFlagCompletionFunc(flagModel, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var models []string
		for m := range license.PredefinedModels {
			models = append(models, m)
		}
		return models, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, "Print the raw license server response as pretty-printed JSON")

	if err := cmd.MarkFlagRequired(flagVoucher); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagFingerprint); err != nil {
		panic(err)
	}

	return cmd
}

func printDeviceLicenses(cmd *cobra.Command, licenses []*license.DeviceLicense) {
	timeVal := func(t *time.Time, unset string) string {
		if t == nil {
			return unset
		}
		return t.Local().Format(time.RFC3339)
	}

	for i, l := range licenses {
		if i > 0 {
			cmd.Println()
		}
		statusText := string(l.Status)
		if c, ok := statusColors[l.Status]; ok {
			statusText = c(statusText)
		}

		cmd.Printf("License %d of %d\n", i+1, len(licenses))
		cmd.Println(labelColor("  Status:"), statusText)
		cmd.Println(labelColor("  License ID:"), l.LicenseUUID)
		cmd.Println(labelColor("  Fingerprint:"), l.Fingerprint)
		if l.Alias != nil && *l.Alias != "" {
			cmd.Println(labelColor("  Alias:"), *l.Alias)
		}
		if l.Product != nil {
			cmd.Println(labelColor("  Product:"), l.Product.DisplayName)
			if l.Product.ImageRole != nil {
				cmd.Println(labelColor("  Role:"), l.Product.ImageRole.Name)
			}
		}
		if l.Platform != nil {
			if l.Platform.Vendor != nil {
				cmd.Println(labelColor("  Vendor:"), l.Platform.Vendor.Name)
			}
			cmd.Println(labelColor("  Manufacturer:"), l.Platform.Manufacturer)
			cmd.Println(labelColor("  Model:"), l.Platform.PlatformModel)
			cmd.Println(labelColor("  Chipset:"), l.Platform.PlatformChipset)
		}
		cmd.Println(labelColor("  Purchase Order:"), fmt.Sprintf("%s (%s)", l.PurchaseOrderName, l.PurchaseOrderUUID))
		cmd.Println(labelColor("  Created:"), timeVal(&l.Tscreated, ""))
		cmd.Println(labelColor("  Valid From:"), timeVal(&l.Tsnotbefore, ""))
		cmd.Println(labelColor("  Valid Until:"), timeVal(l.Tsnotafter, "<unlimited>"))
		if l.Tsrevoked != nil {
			cmd.Println(labelColor("  Revoked:"), timeVal(l.Tsrevoked, ""))
		}
	}
}
