package cmd

import (
	"runtime"
	"runtime/debug"

	"github.com/rtbrick/tools/cmd/rtb-buddy/config"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build metadata",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Printf("Version:   %s\n", config.VERSION)
			cmd.Printf("Go:        %s\n", runtime.Version())
			cmd.Printf("Platform:  %s/%s\n", runtime.GOOS, runtime.GOARCH)

			info, ok := debug.ReadBuildInfo()
			if !ok {
				return nil
			}

			for _, s := range info.Settings {
				switch s.Key {
				case "-compiler":
					cmd.Printf("Compiler:  %s\n", s.Value)
				case "vcs":
					cmd.Printf("VCS:       %s\n", s.Value)
				case "vcs.revision":
					cmd.Printf("Revision:  %s\n", s.Value)
				case "vcs.time":
					cmd.Printf("Commit:    %s\n", s.Value)
				case "vcs.modified":
					cmd.Printf("Modified:  %s\n", s.Value)
				}
			}
			return nil
		},
	}
}
