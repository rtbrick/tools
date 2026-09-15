package apigw

import (
	"github.com/spf13/cobra"
)

func NewApigwCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apigw",
		Short: "Manage authentication for the RtBrick API Gateway",
	}
	cmd.AddCommand(NewGenerateCmd())
	cmd.AddCommand(NewInspectCmd())
	return cmd
}
