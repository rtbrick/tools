package rbfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rtbrick/tools/pkg/generator"
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
		authMode     string
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

			var token string
			var err error

			if authMode == "https" {
				duration, err := time.ParseDuration(durationStr)
				if err != nil {
					return fmt.Errorf("invalid duration: %w", err)
				}

				token, err = generator.GenerateToken(
					privKeyPath,
					sub,
					name,
					"",
					scope,
					issuer,
					kid,
					"",
					duration,
				)
				if err != nil {
					return fmt.Errorf("generate token: %w", err)
				}
			}
			query := "?content=config"
			url := buildURL(authMode, basepath, element, restconfPath, query)
			respBody, err := doRequest(cmd.Context(), url, token, authMode)
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
	cmd.Flags().StringVar(&authMode, flagAuthMode, defaultAuthMode, "Authentication mode: http (port 19091) or https (port 12321 with JWT)")
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

func buildURL(authMode, basepath, element, restconfPath, query string) string {
	port := defaultPortHTTP
	scheme := "http"
	if authMode == "https" {
		port = defaultPortHTTPS
		scheme = "https"
	}
	path := ""
	if restconfPath != "" {
		path = "/" + restconfPath
	}
	return fmt.Sprintf("%s://%s:%s/api/v1/rbfs/elements/%s/services/restconfd/proxy/restconf/data%s%s", scheme, basepath, port, element, path, query)
}

func doRequest(ctx context.Context, url, token, authMode string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/yang-data+json")

	if authMode == "https" && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
