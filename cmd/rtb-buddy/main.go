package main

import (
	"log/slog"
	"os"

	"github.com/rtbrick/tools/cmd/rtb-buddy/cmd"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelDebug,
	})))
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
