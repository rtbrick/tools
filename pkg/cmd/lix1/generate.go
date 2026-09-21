package lix1

import (
	"github.com/spf13/cobra"
)

func newGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate certificates and keys",
	}
	cmd.AddCommand(newGenerateCACmd())
	cmd.AddCommand(newGenerateCertCmd())
	return cmd
}
