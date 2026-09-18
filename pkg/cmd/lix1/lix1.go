package lix1

import (
	"github.com/spf13/cobra"
)

func NewLix1Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lix1",
		Short: "LI X1 mTLS certificate management",
	}
	cmd.AddCommand(newGenerateCmd())
	cmd.AddCommand(newTestCmd())
	return cmd
}
