package apigw

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/rtbrick/tools/cmd/rtb-buddy/cmd/utils"
)

func NewGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate JWKS files and Token",
	}
	cmd.AddCommand(newJWKSCmd())
	cmd.AddCommand(newTokenCmd())
	return cmd
}

func newJWKSCmd() *cobra.Command {
	var privPath, pubPath, kid string

	cmd := &cobra.Command{
		Use:   "jwks",
		Short: "Generate an RSA key pair and JWKS files",
		Run: func(cmd *cobra.Command, args []string) {
			if err := utils.GenerateJWKS(privPath, pubPath, kid); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Private JWKS written to %s\n", privPath)
			fmt.Printf("Public JWKS written to %s\n", pubPath)
		},
	}

	cmd.Flags().StringVar(&privPath, flagPriv, defaultPrivPath, "Output path for the private JWKS file")
	cmd.Flags().StringVar(&pubPath, flagPub, defaultPubPath, "Output path for the public JWKS file")
	cmd.Flags().StringVar(&kid, flagKid, defaultKid, "Key ID for the JWKS entries")

	return cmd
}

func newTokenCmd() *cobra.Command {
	var privPath, sub, name, preferredUser, scope, iss, kid, overrideKid string
	var dur time.Duration

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Generate a signed JWT token",
		Run: func(cmd *cobra.Command, args []string) {
			token, err := utils.GenerateToken(privPath, sub, name, preferredUser, scope, iss, kid, overrideKid, dur)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(token)
		},
	}

	cmd.Flags().StringVar(&privPath, flagPriv, defaultPrivPath, "Private JWKS file path")
	cmd.Flags().StringVar(&sub, flagSub, "", "Token subject (username)")
	cmd.Flags().StringVar(&name, flagName, "", "Name claim")
	cmd.Flags().StringVar(&preferredUser, flagPreferredUser, "", "Preferred username claim")
	cmd.Flags().StringVar(&scope, flagScope, "", "Scope claim")
	cmd.Flags().StringVar(&iss, flagIss, defaultIssuer, "Token issuer")
	cmd.Flags().StringVar(&kid, flagKid, "", "Key ID to select from the JWKS (empty = first key)")
	cmd.Flags().StringVar(&overrideKid, flagOverrideKid, "", "Override the kid in the JWT header")
	cmd.Flags().DurationVar(&dur, flagDur, defaultDuration, "Token duration")

	if err := cmd.MarkFlagRequired(flagSub); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagName); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagPreferredUser); err != nil {
		panic(err)
	}

	return cmd
}
