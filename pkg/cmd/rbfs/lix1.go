package rbfs

import (
	"github.com/rtbrick/tools/pkg/pem"
	"github.com/spf13/cobra"
)

func NewLix1Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lix1",
		Short: "Generate RBFS LI X1 mTLS CLI commands from certificates",
	}

	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Server-side mTLS configuration",
	}
	serverCmd.AddCommand(newServerCertificateCmd())
	serverCmd.AddCommand(newServerClientCACmd())

	clientCmd := &cobra.Command{
		Use:   "client",
		Short: "Client-side mTLS configuration",
	}
	clientCmd.AddCommand(newClientRootCACmd())

	pingCmd := NewLix1PingCmd()

	cmd.AddCommand(serverCmd)
	cmd.AddCommand(clientCmd)
	cmd.AddCommand(pingCmd)
	return cmd
}

func newServerCertificateCmd() *cobra.Command {
	var certPath, certKeyPath string

	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Generate server certificate and key commands",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := pem.ValidateNotCA(certPath); err != nil {
				return err
			}

			if err := pem.ValidateCertAndKeyMatch(certPath, certKeyPath); err != nil {
				return err
			}

			certB64, err := pem.PemFileToBase64(certPath)
			if err != nil {
				return err
			}

			keyB64, err := pem.PemFileToBase64(certKeyPath)
			if err != nil {
				return err
			}

			cmd.Printf("set lawful-intercept protocol x1 mutual-tls server certificate %s\n", certB64)
			cmd.Printf("set lawful-intercept protocol x1 mutual-tls server key-plain-text %s\n", keyB64)

			return nil
		},
	}

	cmd.Flags().StringVar(&certPath, flagCert, "", "Server certificate PEM file")
	cmd.Flags().StringVar(&certKeyPath, flagCertKey, "", "Server private key PEM file")
	if err := cmd.MarkFlagRequired(flagCert); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagCertKey); err != nil {
		panic(err)
	}
	return cmd
}

func newServerClientCACmd() *cobra.Command {
	var certPath string

	cmd := &cobra.Command{
		Use:   "client-ca",
		Short: "Generate server client CA command",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := pem.ValidateIsCA(certPath); err != nil {
				return err
			}

			certB64, err := pem.PemFileToBase64(certPath)
			if err != nil {
				return err
			}

			cmd.Printf("set lawful-intercept protocol x1 mutual-tls server client-ca %s\n", certB64)

			return nil
		},
	}

	cmd.Flags().StringVar(&certPath, flagCert, "", "Client CA certificate PEM file")
	if err := cmd.MarkFlagRequired(flagCert); err != nil {
		panic(err)
	}
	return cmd
}

func newClientRootCACmd() *cobra.Command {
	var certPath string

	cmd := &cobra.Command{
		Use:   "root-ca",
		Short: "Generate client root CA command",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := pem.ValidateIsCA(certPath); err != nil {
				return err
			}

			certB64, err := pem.PemFileToBase64(certPath)
			if err != nil {
				return err
			}

			cmd.Printf("set lawful-intercept protocol x1 mutual-tls client root-ca %s\n", certB64)

			return nil
		},
	}

	cmd.Flags().StringVar(&certPath, flagCert, "", "Root CA certificate PEM file")
	if err := cmd.MarkFlagRequired(flagCert); err != nil {
		panic(err)
	}
	return cmd
}
