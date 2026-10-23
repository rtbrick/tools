package voucher

import (
	"github.com/spf13/cobra"
)

func NewRequestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request a license from a voucher",
	}
	cmd.AddCommand(NewLicenseCmd())
	cmd.AddCommand(NewJWKSCmd())
	return cmd
}
