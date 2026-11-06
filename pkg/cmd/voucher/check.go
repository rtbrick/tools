package voucher

import (
	"github.com/spf13/cobra"
)

func NewCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check the status of licenses issued for a voucher",
	}
	cmd.AddCommand(NewCheckLicenseCmd())
	return cmd
}
