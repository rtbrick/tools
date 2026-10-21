package main

import (
	"os"

	"github.com/rtbrick/tools/cmd/rtb-buddy/cmd"
)

func main() {
	if err := cmd.NewRootCmd(false, false).Execute(); err != nil {
		os.Exit(1)
	}
}
