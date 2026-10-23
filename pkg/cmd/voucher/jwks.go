package voucher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/rtbrick/tools/pkg/license"
	"github.com/spf13/cobra"
)

func NewJWKSCmd() *cobra.Command {
	var voucher string
	var output string

	cmd := &cobra.Command{
		Use:   "jwks",
		Short: "Request JWKS from a voucher",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

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

			jwks, err := client.RequestJWKS(ctx)
			if err != nil {
				return fmt.Errorf("failed to request JWKS: %w", err)
			}

			jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal JWKS: %w", err)
			}

			if output != "" {
				if err := os.WriteFile(output, jwksJSON, 0644); err != nil {
					return fmt.Errorf("failed to write JWKS to %s: %w", output, err)
				}
				cmd.Printf("JWKS written to %s\n", output)
			} else {
				cmd.Println(string(jwksJSON))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&voucher, flagVoucher, "", "Voucher JWT string")
	cmd.Flags().StringVar(&output, flagOutput, "", "Output path for JWKS file (only written if set)")

	if err := cmd.MarkFlagRequired(flagVoucher); err != nil {
		panic(err)
	}

	return cmd
}
