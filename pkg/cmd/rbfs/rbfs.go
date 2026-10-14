package rbfs

import (
	"github.com/spf13/cobra"
)

func NewRbfsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rbfs",
		Short: "RBF router management",
	}
	cmd.AddCommand(NewConfigCmd())
	return cmd
}
