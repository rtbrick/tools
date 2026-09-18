package lix1

import (
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/rtbrick/tools/pkg/generator"
	"github.com/spf13/cobra"
)

func newGenerateCertCmd() *cobra.Command {
	var caCrt, caCrtKey, crt, crtKey, cn, org, ou string
	var duration time.Duration

	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Generate a certificate signed by the CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			ca, err := generator.LoadCA(caCrt, caCrtKey)
			if err != nil {
				return err
			}

			subject := pkix.Name{
				Organization:       []string{org},
				OrganizationalUnit: []string{ou},
				CommonName:         cn,
			}

			err = generator.GenerateCert(ca.Certificate, ca.PrivateKey, crt, crtKey, subject, duration)
			if err != nil {
				return err
			}

			fmt.Printf("Certificate: %s\n", crt)
			fmt.Printf("Private key: %s\n", crtKey)
			fmt.Printf("Subject: %s\n", subject)
			fmt.Printf("Valid until: %s\n", time.Now().Add(duration).Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVar(&caCrt, flagCACrt, defaultCACrt, "CA certificate input path")
	cmd.Flags().StringVar(&caCrtKey, flagCACrtKey, defaultCACrtKey, "CA private key input path")
	cmd.Flags().StringVar(&crt, flagCrt, "", "Certificate output path")
	cmd.Flags().StringVar(&crtKey, flagCrtKey, "", "Private key output path")
	cmd.Flags().StringVar(&cn, flagCN, "", "Common Name for the certificate")
	cmd.Flags().StringVar(&org, flagOrg, "", "Organization for the certificate")
	cmd.Flags().StringVar(&ou, flagOU, "", "Organizational Unit for the certificate")
	cmd.Flags().DurationVar(&duration, flagDuration, defaultDuration, "Certificate validity duration")

	if err := cmd.MarkFlagRequired(flagCrt); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired(flagCrtKey); err != nil {
		panic(err)
	}
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
