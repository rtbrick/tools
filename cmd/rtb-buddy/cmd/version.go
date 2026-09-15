package cmd

import (
	"fmt"
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
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Version:   %s\n", config.VERSION)
			fmt.Printf("Go:        %s\n", runtime.Version())
			fmt.Printf("Platform:  %s/%s\n", runtime.GOOS, runtime.GOARCH)

			info, ok := debug.ReadBuildInfo()
			if !ok {
				return
			}

			for _, s := range info.Settings {
				switch s.Key {
				case "-compiler":
					fmt.Printf("Compiler:  %s\n", s.Value)
				case "vcs":
					fmt.Printf("VCS:       %s\n", s.Value)
				case "vcs.revision":
					fmt.Printf("Revision:  %s\n", s.Value)
				case "vcs.time":
					fmt.Printf("Commit:    %s\n", s.Value)
				case "vcs.modified":
					fmt.Printf("Modified:  %s\n", s.Value)
				}
			}
		},
	}
}
