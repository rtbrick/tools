package rbfs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func NewRestconfCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restconf",
		Short: "RESTCONF operations",
	}
	cmd.AddCommand(newGetCmd())
	return cmd
}

func newGetCmd() *cobra.Command {
	var (
		element      string
		outputPath   string
		authMode     bool
		privKeyPath  string
		kid          string
		sub          string
		name         string
		scope        string
		issuer       string
		durationStr  string
		restconfPath string
	)

	cmd := &cobra.Command{
		Use:   "get <basepath>",
		Short: "Get RESTCONF config from RBFS router",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			basepath := args[0]

			if element == "" {
				element = basepath
			}

			duration, err := time.ParseDuration(durationStr)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}

			client, err := newRestConfClient(basepath,
				withElement(element),
				withAuthMode(authMode),
				withTokenConfig(tokenConfig{
					PrivKeyPath: privKeyPath,
					Kid:         kid,
					Sub:         sub,
					Name:        name,
					Scope:       scope,
					Issuer:      issuer,
					Duration:    duration,
				}),
			)
			if err != nil {
				return err
			}

			respBody, err := client.Get(cmd.Context(), restconfPath, "content=config")
			if err != nil {
				return err
			}

			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, respBody, "", "  "); err != nil {
				return fmt.Errorf("format JSON: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, prettyJSON.Bytes(), 0o644); err != nil {
					return fmt.Errorf("write output file: %w", err)
				}
				cmd.Printf("Config written to %s\n", outputPath)
			} else {
				cmd.Println(prettyJSON.String())
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&element, flagElement, "", "Element name (defaults to basepath)")
	cmd.Flags().StringVarP(&outputPath, flagOutput, flagOutputShort, "", "Output file path (default: print to stdout)")
	cmd.Flags().BoolVar(&authMode, flagAuthMode, defaultAuthMode, "Authentication mode: http (port 19091) or https (port 12321 with JWT)")
	cmd.Flags().StringVar(&privKeyPath, flagPrivKey, defaultPrivKeyPath, "Private JWKS file path for token generation")
	cmd.Flags().StringVar(&kid, flagKid, defaultKid, "Key ID to select from JWKS")
	cmd.Flags().StringVar(&sub, flagSub, defaultSub, "Token subject")
	cmd.Flags().StringVar(&name, flagName, defaultName, "Token name claim")
	cmd.Flags().StringVar(&scope, flagScope, defaultScope, "Token scope")
	cmd.Flags().StringVar(&issuer, flagIss, defaultIssuer, "Token issuer")
	cmd.Flags().StringVar(&durationStr, flagDur, defaultDuration.String(), "Token duration")
	cmd.Flags().StringVarP(&restconfPath, flagPath, flagPathShort, "", "RESTCONF data path (e.g. rtbrick-config:lldp)")

	return cmd
}
