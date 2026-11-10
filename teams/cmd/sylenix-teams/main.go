// SPDX-License-Identifier: Apache-2.0

// Command sylenix-teams is the minimal paid-tier policy service.
//
//	sylenix-teams serve --tls-cert CERT --tls-key KEY --tokens FILE --pubkey KEY --data-dir DIR
//	sylenix-teams token hash --team NAME < token
//	sylenix-teams publish --url https://host/v1/policy --policy policy.yaml --token-file FILE
//
// The server speaks HTTPS only, stores only SHA-256 token hashes, and verifies
// every published policy signature before replacing the stored policy.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"sylenix-guard-poc/teams/policyserver"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "serve":
		code = runServe(os.Args[2:])
	case "token":
		code = runToken(os.Args[2:])
	case "publish":
		code = runPublish(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Println("sylenix-teams", version)
		return
	default:
		usage()
		code = 2
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  sylenix-teams serve --tls-cert CERT --tls-key KEY --tokens FILE --pubkey KEY --data-dir DIR [--listen 127.0.0.1:8443]
  sylenix-teams token hash --team NAME < token
  sylenix-teams publish --url https://host/v1/policy --policy policy.yaml [--signature policy.yaml.sig] [--token-file FILE] [--ca CA] [--pubkey KEY]`)
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:8443", "HTTPS listen address")
	certPath := fs.String("tls-cert", "", "TLS certificate PEM (required)")
	keyPath := fs.String("tls-key", "", "TLS private key PEM (required)")
	tokensPath := fs.String("tokens", "", "team token hash file (required)")
	pubPath := fs.String("pubkey", "", "team Ed25519 public key (required)")
	dataDir := fs.String("data-dir", "", "directory for signed policy files (required)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *certPath == "" || *keyPath == "" || *tokensPath == "" || *pubPath == "" || *dataDir == "" {
		fmt.Fprintln(os.Stderr, "sylenix-teams serve: --tls-cert, --tls-key, --tokens, --pubkey and --data-dir are required")
		return 2
	}
	if !strings.Contains(*listen, ":") {
		fmt.Fprintln(os.Stderr, "sylenix-teams serve: --listen must be host:port")
		return 2
	}
	tokens, err := policyserver.LoadTokenFile(*tokensPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams serve:", err)
		return 2
	}
	pub, err := loadPublicKey(*pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams serve:", err)
		return 2
	}
	srv, err := policyserver.New(policyserver.Config{
		DataDir:   *dataDir,
		PublicKey: pub,
		Tokens:    tokens,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams serve:", err)
		return 2
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	fmt.Fprintf(os.Stderr, "[sylenix-teams] serving %s and %s on https://%s\n", policyserver.APIPath, policyserver.EventsAPI, *listen)
	if err := httpSrv.ListenAndServeTLS(*certPath, *keyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "sylenix-teams serve:", err)
		return 1
	}
	return 0
}

func runToken(args []string) int {
	if len(args) == 0 || args[0] != "hash" {
		fmt.Fprintln(os.Stderr, "usage: sylenix-teams token hash --team NAME < token")
		return 2
	}
	fs := flag.NewFlagSet("token hash", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	team := fs.String("team", "", "team name for the token-file entry")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *team == "" {
		fmt.Fprintln(os.Stderr, "sylenix-teams token hash: --team is required")
		return 2
	}
	if err := policyserver.ValidateTeamName(*team); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams token hash:", err)
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams token hash:", err)
		return 2
	}
	token := strings.TrimRight(string(raw), "\r\n")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		fmt.Fprintln(os.Stderr, "sylenix-teams token hash: token must be non-empty and contain no whitespace")
		return 2
	}
	fmt.Printf("%s:%s\n", *team, policyserver.HashToken(token))
	return 0
}

func runPublish(args []string) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rawURL := fs.String("url", "", "HTTPS policy endpoint, for example https://policy.example.com/v1/policy")
	policyPath := fs.String("policy", "", "policy file to publish")
	sigPath := fs.String("signature", "", "detached signature file (default: policy + .sig)")
	tokenFile := fs.String("token-file", "", "file containing the team bearer token (or SYLENIX_TEAM_TOKEN)")
	caPath := fs.String("ca", "", "optional extra CA certificate PEM")
	pubPath := fs.String("pubkey", "", "optional team public key for a local pre-check")
	timeout := fs.Duration("timeout", 15*time.Second, "HTTP timeout")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *rawURL == "" || *policyPath == "" {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish: --url and --policy are required")
		return 2
	}
	u, err := url.Parse(*rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish: --url must be an absolute https URL without userinfo, query or fragment")
		return 2
	}
	if *sigPath == "" {
		*sigPath = *policyPath + ".sig"
	}
	policy, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
		return 2
	}
	sig, err := os.ReadFile(*sigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
		return 2
	}
	if *pubPath != "" {
		pub, err := loadPublicKey(*pubPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
			return 2
		}
		if err := policyserver.VerifySignature(pub, policy, sig); err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
			return 1
		}
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
		return 2
	}
	body, err := policyserver.EncodeEnvelope(policy, sig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
		return 2
	}
	client, err := httpsClient(*caPath, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
		return 2
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-teams publish:", err)
		return 1
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "sylenix-teams publish: server returned %s: %s\n", resp.Status, strings.TrimSpace(string(respBody)))
		return 1
	}
	fmt.Println("published signed policy")
	return 0
}

func readToken(path string) (string, error) {
	var raw []byte
	var err error
	if path != "" {
		raw, err = os.ReadFile(path)
		if err != nil {
			return "", err
		}
	} else {
		raw = []byte(os.Getenv("SYLENIX_TEAM_TOKEN"))
		if len(raw) == 0 {
			return "", errors.New("pass --token-file or set SYLENIX_TEAM_TOKEN")
		}
	}
	token := strings.TrimRight(string(raw), "\r\n")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("team token must be non-empty and contain no whitespace")
	}
	return token, nil
}

func httpsClient(caPath string, timeout time.Duration) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		raw, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("%s contains no PEM certificates", caPath)
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   tlsConfig,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unsupported public key encoding")
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not Ed25519")
		}
		return ed, nil
	}
	raw := bytes.TrimSpace(data)
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unsupported public key encoding")
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}
