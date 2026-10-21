package voucher

import (
	"github.com/spf13/cobra"
)

func NewVoucherCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "voucher",
		Short: "Manage vouchers and licenses",
	}
	cmd.AddCommand(NewRequestCmd())
	return cmd
}
