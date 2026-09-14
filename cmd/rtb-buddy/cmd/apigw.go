package cmd

import (
	"github.com/rtbrick/tools/cmd/rtb-buddy/cmd/apigw"
	"github.com/spf13/cobra"
)

func newApigwCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apigw",
		Short: "Manage authentication for the RtBrick API Gateway",
	}
	cmd.AddCommand(apigw.NewGenerateCmd())
	cmd.AddCommand(apigw.NewInspectCmd())
	return cmd
}
