package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/rtbrick/tools/cmd/rtb-buddy/config"
	"github.com/rtbrick/tools/pkg/cmd/apigw"
	"github.com/rtbrick/tools/pkg/cmd/lix1"
	"github.com/rtbrick/tools/pkg/cmd/rbfs"
	"github.com/rtbrick/tools/pkg/cmd/voucher"
	"github.com/spf13/cobra"
)

var logLevel string

func NewRootCmd(silenceErrors, silenceUsage bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "rtb-buddy",
		Short:         "RtBrick certificate and management tool",
		SilenceErrors: silenceErrors,
		SilenceUsage:  silenceUsage,
	}
	cmd.SetOut(os.Stdout)
	cmd.Version = config.VERSION
	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	if err := cmd.RegisterFlagCompletionFunc("log-level", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"debug", "info", "warn", "error"}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		var level slog.Level
		switch logLevel {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			return fmt.Errorf("unknown log level %q", logLevel)
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: false,
			Level:     level,
		})))
		return nil
	}
	cmd.AddCommand(apigw.NewApigwCmd())
	cmd.AddCommand(lix1.NewLix1Cmd())
	cmd.AddCommand(rbfs.NewRbfsCmd())
	cmd.AddCommand(voucher.NewVoucherCmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}
