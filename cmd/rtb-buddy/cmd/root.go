package cmd

import (
	"os"

	"github.com/rtbrick/tools/cmd/rtb-buddy/config"
	"github.com/rtbrick/tools/pkg/cmd/apigw"
	"github.com/rtbrick/tools/pkg/cmd/lix1"
	"github.com/rtbrick/tools/pkg/cmd/rbfs"
	"github.com/spf13/cobra"
)

func NewRootCmd(silenceErrors, silenceUsage bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "rtb-buddy",
		Short:         "RtBrick certificate and management tool",
		SilenceErrors: silenceErrors,
		SilenceUsage:  silenceUsage,
	}
	cmd.SetOut(os.Stdout)
	cmd.Version = config.VERSION
	cmd.AddCommand(apigw.NewApigwCmd())
	cmd.AddCommand(lix1.NewLix1Cmd())
	cmd.AddCommand(rbfs.NewRbfsCmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}
