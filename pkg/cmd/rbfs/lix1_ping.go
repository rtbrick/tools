package rbfs

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

// buildLix1dPingBody builds the XML PingRequest body for rbfs lix1 ping
// Produces XML matching ETSI TS 103 221-1 format:
// <X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10">
//
//	<x1RequestMessage xsi:type="PingRequest">
//	  <admfIdentifier>ADMF-ID-01</admfIdentifier>
//	  <neIdentifier>NE-ID-102</neIdentifier>
//	  <messageTimestamp>2026-09-22T20:51:00Z</messageTimestamp>
//	  <version>v1.12.1</version>
//	  <x1TransactionId>f81d4fae-7dec-11d0-a765-00a0c91e6bf6</x1TransactionId>
//	  <pingType>basic</pingType>
//	  <requestedNumberOfRepetitions>1</requestedNumberOfRepetitions>
//	</x1RequestMessage>
//
// </X1Request>
func buildLix1dPingBody(admfID, neID, version, pingType string, txTime time.Time) ([]byte, error) {
	txID := fmt.Sprintf("%d-%d", txTime.Unix(), txTime.Nanosecond())

	body := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10">
  <x1RequestMessage xsi:type="PingRequest">
    <admfIdentifier>%s</admfIdentifier>
    <neIdentifier>%s</neIdentifier>
    <messageTimestamp>%s</messageTimestamp>
    <version>%s</version>
    <x1TransactionId>%s</x1TransactionId>
    <pingType>%s</pingType>
    <requestedNumberOfRepetitions>1</requestedNumberOfRepetitions>
  </x1RequestMessage>
</X1Request>`,
		admfID+"-01",
		neID+"-102",
		txTime.Format(time.RFC3339),
		version,
		txID,
		pingType,
	))

	return body, nil
}

// NewLix1PingCmd creates the rbfs lix1 ping command
func NewLix1PingCmd() *cobra.Command {
	var admfID, neID, version, pingType, cert, certKey string
	var insecure bool

	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Send X1 PingRequest to RBFS router (LI X1 over mTLS)",
		Args:  cobra.ExactArgs(1), // <path>
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			// Build XML body
			txTime := time.Now()
			body, err := buildLix1dPingBody(admfID, neID, version, pingType, txTime)
			if err != nil {
				return fmt.Errorf("build ping body: %w", err)
			}

			// Build HTTP client
			tlsConfig := &tls.Config{
				InsecureSkipVerify: insecure,
			}
			if cert != "" && certKey != "" {
				// Load client certificate for mTLS
				certData, err := tls.LoadX509KeyPair(cert, certKey)
				if err != nil {
					return fmt.Errorf("load client cert/key: %w", err)
				}
				tlsConfig.Certificates = append(tlsConfig.Certificates, certData)
			}

			// Parse element from path (could be hostname or include more details)
			element := path
			url := fmt.Sprintf("https://%s:12322/X1/NE", element)

			req, err := http.NewRequest("POST", url, bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("create request: %w", err)
			}
			req.Header.Set("Content-Type", "application/xml")

			client := &http.Client{
				Timeout:   30 * time.Second,
				Transport: &http.Transport{TLSClientConfig: tlsConfig},
			}

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("do request: %w", err)
			}
			defer resp.Body.Close()

			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}
			prettyResp, err := PrettyPrintXML(respBody)
			if err != nil {
				return fmt.Errorf("pretty print XML: %w", err)
			}

			cmd.Printf("Status: %d\n", resp.StatusCode)
			cmd.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))
			cmd.Print("Response:\n")
			cmd.Printf("%s\n", prettyResp)

			return nil
		},
	}

	// Flags - mandatory: cert, cert-key
	cmd.Flags().StringVar(&admfID, "admf-identifier", "ADMF-ID", "ADMf Identifier base")
	cmd.Flags().StringVar(&neID, "ne-identifier", "NE-ID", "NE Identifier base")
	cmd.Flags().StringVar(&version, "version", "v1.12.1", "X1 version")
	cmd.Flags().StringVar(&pingType, "ping-type", "basic", "Ping type")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().StringVar(&cert, "cert", "", "Client certificate PEM path (required)")
	cmd.Flags().StringVar(&certKey, "cert-key", "", "Client private key PEM path (required)")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("cert-key")

	return cmd
}

// PrettyPrintXML takes raw XML bytes and returns an indented XML string.
func PrettyPrintXML(raw []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var buf bytes.Buffer
	encoder := xml.NewEncoder(&buf)
	encoder.Indent("", "  ") // Use 2 spaces for indentation

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if err := encoder.EncodeToken(token); err != nil {
			return "", err
		}
	}

	if err := encoder.Flush(); err != nil {
		return "", err
	}

	return buf.String(), nil
}
