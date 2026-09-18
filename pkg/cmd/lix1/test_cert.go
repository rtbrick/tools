package lix1

import (
	"fmt"
	"time"

	"github.com/rtbrick/tools/pkg/generator"
	"github.com/spf13/cobra"
)

func newTestCertCmd() *cobra.Command {
	var crt, caCrt string

	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Test certificate validity and chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := generator.GetCertificateInfo(crt)
			if err != nil {
				return err
			}

			fmt.Printf("Subject: %s\n", info.Subject)
			fmt.Printf("Issuer: %s\n", info.Issuer)
			fmt.Printf("Serial: %s\n", info.SerialNumber)
			fmt.Printf("Signature Algorithm: %s\n", info.SignatureAlgo)
			fmt.Printf("Not Before: %s\n", info.NotBefore.Format(time.RFC3339))
			fmt.Printf("Not After: %s\n", info.NotAfter.Format(time.RFC3339))
			fmt.Printf("Is CA: %t\n", info.IsCA)

			if len(info.DNSNames) > 0 {
				fmt.Printf("DNS Names: %v\n", info.DNSNames)
			}
			if len(info.IPAddresses) > 0 {
				fmt.Printf("IP Addresses: %v\n", info.IPAddresses)
			}

			// Check expiry
			if time.Now().After(info.NotAfter) {
				fmt.Printf("\nStatus: EXPIRED\n")
			} else {
				remaining := time.Until(info.NotAfter)
				fmt.Printf("\nStatus: VALID (expires in %s)\n", remaining.Round(time.Hour))
			}

			// Verify chain if CA is provided
			if caCrt != "" {
				fmt.Printf("\nVerifying certificate chain against CA...\n")
				err := generator.VerifyCertificate(crt, caCrt)
				if err != nil {
					fmt.Printf("Chain verification: FAILED (%v)\n", err)
				} else {
					fmt.Printf("Chain verification: OK\n")
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&crt, flagCrt, "", "Certificate to test")
	cmd.Flags().StringVar(&caCrt, flagCACrt, defaultCACrt, "CA certificate for chain validation")

	if err := cmd.MarkFlagRequired(flagCrt); err != nil {
		panic(err)
	}

	return cmd
}
