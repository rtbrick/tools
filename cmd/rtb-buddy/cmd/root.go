package cmd

import (
	"github.com/rtbrick/tools/cmd/rtb-buddy/config"
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rtb-buddy",
		Short: "RtBrick certificate and management tool",
	}
	cmd.Version = config.VERSION
	cmd.AddCommand(newApigwCmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}
