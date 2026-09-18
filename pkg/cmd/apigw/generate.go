package apigw

import (
	"time"

	"github.com/rtbrick/tools/pkg/generator"
	"github.com/spf13/cobra"
)

func NewGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate JWKS files, Token, and TLS certificates",
	}
	cmd.AddCommand(newJWKSCmd())
	cmd.AddCommand(newTokenCmd())
	cmd.AddCommand(newTLSCmd())
	return cmd
}

func newJWKSCmd() *cobra.Command {
	var privPath, pubPath, kid string

	cmd := &cobra.Command{
		Use:   "jwks",
		Short: "Generate an RSA key pair and JWKS files",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := generator.GenerateJWKS(privPath, pubPath, kid); err != nil {
				return err
			}
			cmd.Printf("Private JWKS written to %s\n", privPath)
			cmd.Printf("Public JWKS written to %s\n", pubPath)
			return nil
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
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := generator.GenerateToken(privPath, sub, name, preferredUser, scope, iss, kid, overrideKid, dur)
			if err != nil {
				return err
			}
			cmd.Println(token)
			return nil
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

func newTLSCmd() *cobra.Command {
	var certPath, keyPath, org string
	var hosts []string

	cmd := &cobra.Command{
		Use:   "tls",
		Short: "Generate a self-signed TLS certificate and key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := generator.GenerateTLSCertificate(certPath, keyPath, org, hosts); err != nil {
				return err
			}
			cmd.Printf("TLS certificate written to %s\n", certPath)
			cmd.Printf("TLS key written to %s\n", keyPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&certPath, flagCert, "server.crt", "Output path for the TLS certificate PEM")
	cmd.Flags().StringVar(&keyPath, flagKey, "server.key", "Output path for the TLS key PEM")
	cmd.Flags().StringVar(&org, flagOrg, "", "Organization name for the certificate")
	cmd.Flags().StringSliceVar(&hosts, flagHost, []string{"localhost"}, "Hostnames/IPs to include in the certificate SANs")

	if err := cmd.MarkFlagRequired(flagOrg); err != nil {
		panic(err)
	}

	return cmd
}
