package lix1

import (
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/rtbrick/tools/pkg/generator"
	"github.com/spf13/cobra"
)

func newGenerateCACmd() *cobra.Command {
	var caCrt, caCrtKey, cn, org, ou string
	var duration time.Duration

	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Generate a root CA certificate and private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			subject := pkix.Name{
				Organization:       []string{org},
				OrganizationalUnit: []string{ou},
				CommonName:         cn,
			}

			ca, err := generator.GenerateCA(caCrt, caCrtKey, subject, duration)
			if err != nil {
				return err
			}

			fmt.Printf("CA certificate: %s\n", caCrt)
			fmt.Printf("CA private key: %s\n", caCrtKey)
			fmt.Printf("Subject: %s\n", ca.Certificate.Subject)
			fmt.Printf("Valid until: %s\n", ca.Certificate.NotAfter.Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVar(&caCrt, flagCACrt, defaultCACrt, "CA certificate output path")
	cmd.Flags().StringVar(&caCrtKey, flagCACrtKey, defaultCACrtKey, "CA private key output path")
	cmd.Flags().StringVar(&cn, flagCN, "", "Common Name for the certificate")
	cmd.Flags().StringVar(&org, flagOrg, "", "Organization for the certificate")
	cmd.Flags().StringVar(&ou, flagOU, "", "Organizational Unit for the certificate")
	cmd.Flags().DurationVar(&duration, flagDuration, defaultDuration, "Certificate validity duration")

	if err := cmd.MarkFlagRequired(flagCN); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagOrg); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagOU); err != nil {
		panic(err)
	}

	return cmd
}
