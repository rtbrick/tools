package apigw

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rtbrick/tools/pkg/generator"
	"github.com/spf13/cobra"
)

func NewInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect JWT tokens",
	}
	cmd.AddCommand(newInspectTokenCmd())
	return cmd
}

func newInspectTokenCmd() *cobra.Command {
	var pubPath, overrideKid string

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Decode and verify a JWT from stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("error reading stdin: %w", err)
			}
			raw := strings.TrimSpace(string(data))
			if raw == "" {
				return fmt.Errorf("no token provided on stdin")
			}

			pubAvailable := pubPath != ""
			if pubAvailable {
				if _, err := os.Stat(pubPath); os.IsNotExist(err) {
					pubAvailable = false
				}
			}

			checkPath := pubPath
			if !pubAvailable {
				checkPath = ""
			}

			header, claims, valid, err := generator.InspectToken(raw, checkPath, overrideKid)
			if err != nil {
				return err
			}

			fmt.Println("Header:")
			hdrJSON, _ := json.MarshalIndent(header, "", "  ")
			fmt.Println(string(hdrJSON))

			fmt.Println("\nClaims:")
			clmJSON, _ := json.MarshalIndent(claims, "", "  ")
			fmt.Println(string(clmJSON))

			fmt.Printf("\nSignature: ")
			if !pubAvailable {
				fmt.Printf("not verified (public key not found: %s)\n", pubPath)
			} else if valid {
				fmt.Println("valid")
			} else {
				fmt.Println("invalid")
			}

			if exp, ok := claims["exp"]; ok {
				if expFloat, ok := exp.(float64); ok {
					expTime := time.Unix(int64(expFloat), 0)
					if time.Now().After(expTime) {
						fmt.Printf("Expired: yes (expired %s)\n", expTime.Format(time.RFC3339))
					} else {
						fmt.Printf("Expired: no (valid until %s)\n", expTime.Format(time.RFC3339))
					}
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&pubPath, flagPub, defaultPubPath, "Public JWKS file path for signature verification")
	cmd.Flags().StringVar(&overrideKid, flagOverrideKid, "", "Override the kid for key lookup in the JWKS")

	return cmd
}
