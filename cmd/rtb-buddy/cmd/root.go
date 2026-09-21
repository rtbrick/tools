package cmd

import (
	"github.com/rtbrick/tools/cmd/rtb-buddy/config"
	"github.com/rtbrick/tools/pkg/cmd/apigw"
	"github.com/rtbrick/tools/pkg/cmd/lix1"
	"github.com/spf13/cobra"
)

func NewRootCmd(silenceErrors, silenceUsage bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "rtb-buddy",
		Short:         "RtBrick certificate and management tool",
		SilenceErrors: silenceErrors,
		SilenceUsage:  silenceUsage,
	}
	cmd.Version = config.VERSION
	cmd.AddCommand(apigw.NewApigwCmd())
	cmd.AddCommand(lix1.NewLix1Cmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}
