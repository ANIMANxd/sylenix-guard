// SPDX-License-Identifier: Apache-2.0

package policyserver_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sylenix-guard-poc/teams/policyserver"
)

func TestTokenFileStoresHashesOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens")
	token := "high-entropy-token"
	hash := policyserver.HashToken(token)
	if err := os.WriteFile(path, []byte("# comment\n\nacme:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := policyserver.LoadTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if tokens["acme"] != hash {
		t.Fatalf("hash mismatch: %v", tokens)
	}
	if strings.Contains(hash, token) {
		t.Fatal("token hash must not contain the plaintext token")
	}

	for name, body := range map[string]string{
		"plaintext": "acme:" + token + "\n",
		"duplicate": "acme:" + hash + "\nacme:" + hash + "\n",
		"badhex":    "acme:not-a-hash\n",
		"notoken":   "acme:\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := policyserver.LoadTokenFile(path); err == nil {
				t.Fatalf("accepted invalid token file %q", body)
			}
		})
	}
}

func TestServerAuthenticatesAndVerifiesSignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srv, err := policyserver.New(policyserver.Config{
		DataDir:   dir,
		PublicKey: pub,
		Tokens:    map[string]string{"acme": policyserver.HashToken("correct-token")},
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewTLSServer(srv)
	defer httpSrv.Close()
	endpoint := httpSrv.URL + policyserver.APIPath

	policy := []byte("version: 1\napproval: deny\n")
	sig := ed25519.Sign(priv, policy)
	body, err := policyserver.EncodeEnvelope(policy, sig)
	if err != nil {
		t.Fatal(err)
	}

	do := func(method, token string, body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := do(http.MethodGet, "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET without token: %d", resp.StatusCode)
	}
	resp = do(http.MethodPut, "wrong-token", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PUT with wrong token: %d", resp.StatusCode)
	}

	tampered := append([]byte(nil), policy...)
	tampered[0] ^= 1
	resp = do(http.MethodPut, "correct-token", mustEnvelope(t, tampered, sig))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT tampered policy: %d", resp.StatusCode)
	}

	resp = do(http.MethodPut, "correct-token", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT valid policy: %d", resp.StatusCode)
	}

	resp = do(http.MethodGet, "correct-token", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET valid policy: %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	gotPolicy, gotSig, err := policyserver.DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPolicy, policy) || !bytes.Equal(gotSig, sig) {
		t.Fatal("server returned different policy or signature")
	}

	// A byte changed on disk but a valid signature file left behind must not be
	// served as valid policy.
	stored := filepath.Join(dir, "policy-acme.yaml")
	disk, err := os.ReadFile(stored)
	if err != nil {
		t.Fatal(err)
	}
	disk[0] ^= 1
	if err := os.WriteFile(stored, disk, 0o600); err != nil {
		t.Fatal(err)
	}
	resp = do(http.MethodGet, "correct-token", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET tampered stored policy: %d", resp.StatusCode)
	}
}

func mustEnvelope(t *testing.T, policy, sig []byte) []byte {
	t.Helper()
	body, err := policyserver.EncodeEnvelope(policy, sig)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
