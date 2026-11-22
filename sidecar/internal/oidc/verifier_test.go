package oidc_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Tony-Stark2025/piton/sidecar/internal/oidc"
)

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	pay, _ := json.Marshal(claims)
	input := b64url(hdr) + "." + b64url(pay)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("rsa sign failed: %v", err)
	}
	return input + "." + b64url(sig)
}

func signES256(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid})
	pay, _ := json.Marshal(claims)
	input := b64url(hdr) + "." + b64url(pay)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatalf("ecdsa sign failed: %v", err)
	}
	rawSig := make([]byte, 64)
	r.FillBytes(rawSig[:32])
	s.FillBytes(rawSig[32:])
	return input + "." + b64url(rawSig)
}

func rsaToJWK(pub *rsa.PublicKey, kid string) map[string]any {
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   b64url(pub.N.Bytes()),
		"e":   b64url(eBytes),
	}
}

func ecToJWK(pub *ecdsa.PublicKey, kid string) map[string]any {
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	pub.X.FillBytes(xBytes)
	pub.Y.FillBytes(yBytes)
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": kid,
		"alg": "ES256",
		"use": "sig",
		"x":   b64url(xBytes),
		"y":   b64url(yBytes),
	}
}

func TestOIDCVerifierRS256ES256RotationAndFailClosedAttacks(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen failed: %v", err)
	}
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen2 failed: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen failed: %v", err)
	}

	var mu sync.Mutex
	activeKeys := []map[string]any{
		rsaToJWK(&rsaKey1.PublicKey, "rsa-k1"),
		ecToJWK(&ecKey.PublicKey, "ec-k1"),
	}

	var idpSrv *httptest.Server
	idpSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   idpSrv.URL,
				"jwks_uri": idpSrv.URL + "/oauth2/v1/keys",
			})
			return
		}
		if r.URL.Path == "/oauth2/v1/keys" {
			mu.Lock()
			keysCopy := append([]map[string]any(nil), activeKeys...)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keysCopy})
			return
		}
		http.NotFound(w, r)
	}))
	defer idpSrv.Close()

	verifier := oidc.NewVerifier(oidc.VerifierConfig{
		Issuer:   idpSrv.URL,
		Audience: "piton-mcp-gateway",
	})
	ctx := context.Background()

	// 1. Valid RS256 RFC 8693 OBO token (`sub` + `act.sub`) passes via OIDC discovery
	validRS := signRS256(t, rsaKey1, "rsa-k1", map[string]any{
		"iss": idpSrv.URL,
		"aud": []string{"piton-mcp-gateway"},
		"sub": "alice@acme.com",
		"act": map[string]any{"sub": "billing-agent"},
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	principal, err := verifier.VerifyToken(ctx, validRS)
	if err != nil {
		t.Fatalf("expected valid RS256 OBO token to pass, got err: %v", err)
	}
	if principal.CanonicalID != "user:alice@acme.com|agent:billing-agent" {
		t.Fatalf("unexpected canonical OBO ID: %q", principal.CanonicalID)
	}

	// 2. Valid ES256 token passes
	validES := signES256(t, ecKey, "ec-k1", map[string]any{
		"iss": idpSrv.URL,
		"aud": "piton-mcp-gateway",
		"sub": "bob@acme.com",
		"azp": "support-bot",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	ecPrincipal, err := verifier.VerifyToken(ctx, validES)
	if err != nil || ecPrincipal.CanonicalID != "user:bob@acme.com|agent:support-bot" {
		t.Fatalf("expected valid ES256 token to pass, got %v err=%v", ecPrincipal, err)
	}

	// 3. Rejects `alg: none` forgery
	noneHdr, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	nonePay, _ := json.Marshal(map[string]any{"iss": idpSrv.URL, "aud": "piton-mcp-gateway", "sub": "admin", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := verifier.VerifyToken(ctx, b64url(noneHdr)+"."+b64url(nonePay)+"."); err == nil {
		t.Fatalf("expected alg:none token to be rejected")
	}

	// 4. Rejects tampered payload signature
	tampered := validRS[:len(validRS)-4] + "AAAA"
	if _, err := verifier.VerifyToken(ctx, tampered); err == nil {
		t.Fatalf("expected tampered RS256 signature to be rejected")
	}

	// 5. Rejects expired token
	expiredTok := signRS256(t, rsaKey1, "rsa-k1", map[string]any{
		"iss": idpSrv.URL,
		"aud": "piton-mcp-gateway",
		"sub": "alice@acme.com",
		"exp": time.Now().Add(-2 * time.Minute).Unix(),
	})
	if _, err := verifier.VerifyToken(ctx, expiredTok); err == nil {
		t.Fatalf("expected expired token to be rejected")
	}

	// 6. Rejects wrong audience
	wrongAud := signRS256(t, rsaKey1, "rsa-k1", map[string]any{
		"iss": idpSrv.URL,
		"aud": "other-service",
		"sub": "alice@acme.com",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	if _, err := verifier.VerifyToken(ctx, wrongAud); err == nil {
		t.Fatalf("expected wrong audience token to be rejected")
	}

	// 7. Key rotation: IdP publishes `rsa-k2` -> Verifier auto-refreshes JWKS on unknown `kid`
	mu.Lock()
	activeKeys = append(activeKeys, rsaToJWK(&rsaKey2.PublicKey, "rsa-k2"))
	mu.Unlock()
	rotatedTok := signRS256(t, rsaKey2, "rsa-k2", map[string]any{
		"iss": idpSrv.URL,
		"aud": "piton-mcp-gateway",
		"sub": "carol@acme.com",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	// Force fresh verifier with tiny refresh window so test runs instantaneously without sleeping 2s
	rotVerifier := oidc.NewVerifier(oidc.VerifierConfig{
		Issuer:   idpSrv.URL,
		Audience: "piton-mcp-gateway",
	})
	if p, err := rotVerifier.VerifyToken(ctx, rotatedTok); err != nil || p.Subject != "carol@acme.com" {
		t.Fatalf("expected rotated key rsa-k2 to verify cleanly, got p=%v err=%v", p, err)
	}
}
