package apigw

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rtbrick/tools/cmd/rtb-buddy/cmd/utils"
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
		Run: func(cmd *cobra.Command, args []string) {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
				os.Exit(1)
			}
			raw := strings.TrimSpace(string(data))
			if raw == "" {
				fmt.Fprintf(os.Stderr, "error: no token provided on stdin\n")
				os.Exit(1)
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

			header, claims, valid, err := utils.InspectToken(raw, checkPath, overrideKid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
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
		},
	}

	cmd.Flags().StringVar(&pubPath, flagPub, defaultPubPath, "Public JWKS file path for signature verification")
	cmd.Flags().StringVar(&overrideKid, flagOverrideKid, "", "Override the kid for key lookup in the JWKS")

	return cmd
}
