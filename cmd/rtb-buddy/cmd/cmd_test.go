package cmd

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func runCmd(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestNewRootCmd(t *testing.T) {
	tests := []struct {
		name          string
		silenceErrors bool
		silenceUsage  bool
	}{
		{
			name:          "both false",
			silenceErrors: false,
			silenceUsage:  false,
		},
		{
			name:          "both true",
			silenceErrors: true,
			silenceUsage:  true,
		},
		{
			name:          "silence errors only",
			silenceErrors: true,
			silenceUsage:  false,
		},
		{
			name:          "silence usage only",
			silenceErrors: false,
			silenceUsage:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := NewRootCmd(tt.silenceErrors, tt.silenceUsage)
			require.Equal(t, tt.silenceErrors, root.SilenceErrors)
			require.Equal(t, tt.silenceUsage, root.SilenceUsage)
		})
	}
}

func TestNewRootCmd_Subcommands(t *testing.T) {
	root := NewRootCmd(true, true)

	names := make([]string, len(root.Commands()))
	for i, cmd := range root.Commands() {
		names[i] = cmd.Name()
	}

	require.Contains(t, names, "apigw")
	require.Contains(t, names, "version")
}

func TestVersionCmd(t *testing.T) {
	out, err := runCmd(t, NewRootCmd(true, true), "version")
	require.NoError(t, err)
	require.Contains(t, out, "Version:")
	require.Contains(t, out, "Go:")
	require.Contains(t, out, "Platform:")
	require.Contains(t, out, runtime.GOOS+"/"+runtime.GOARCH)
}

func TestVersionCmd_NoArgs(t *testing.T) {
	_, err := runCmd(t, NewRootCmd(true, true), "version", "extra")
	require.Error(t, err)
}

func TestRootCmd_NoArgs(t *testing.T) {
	root := NewRootCmd(true, true)

	out, err := runCmd(t, root)
	require.NoError(t, err)
	_ = out // usage is shown but not an error
}

func TestRootCmd_UnknownFlag(t *testing.T) {
	root := NewRootCmd(true, true)
	_, err := runCmd(t, root, "version", "--unknown")
	require.Error(t, err)
}
