package lix1

import (
	"github.com/spf13/cobra"
)

func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test certificates and endpoints",
	}
	cmd.AddCommand(newTestCertCmd())
	return cmd
}
