package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxJWKSBodyBytes = 1 << 20 // 1 MiB cap against OOM from hostile/broken IdP

// VerifierConfig configures cryptographic OIDC/JWKS JWT verification (RS256 & ES256).
type VerifierConfig struct {
	Issuer     string
	JWKSURL    string
	Audience   string
	CacheTTL   time.Duration
	ClockSkew  time.Duration
	HTTPClient *http.Client
}

// VerifiedPrincipal represents a cryptographically verified OIDC/OBO caller identity.
type VerifiedPrincipal struct {
	Subject       string
	ActorSubject  string
	AuthorizedApp string
	Issuer        string
	CanonicalID   string // e.g., "user:alice@acme.com|agent:billing-bot"
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type storedKey struct {
	Pub crypto.PublicKey
	Alg string
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// Verifier performs fail-closed RS256/ES256 JWT verification backed by a cached JWKS endpoint.
// Hardened per RFC 7517 / RFC 7519:
// - Rejects `use != "" && use != "sig"` (blocks encryption keys)
// - Enforces `jwk.alg` match when present and strict RS256/ES256 allowlist
// - Validates EC P-256 curve membership (`IsOnCurve`) and exact 32-byte coordinates
// - Refuses HTTP redirects and caps response size at 1 MiB
// - Serializes concurrent JWKS refreshes (prevents stampede DoS on unknown `kid`)
type Verifier struct {
	cfg    VerifierConfig
	client *http.Client

	mu          sync.RWMutex
	refreshMu   sync.Mutex
	jwksURL     string
	keysByKid   map[string]storedKey
	unnamedKeys []storedKey
	fetchedAt   time.Time
	lastRefresh time.Time
}

func NewVerifier(cfg VerifierConfig) *Verifier {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Verifier{
		cfg:       cfg,
		client:    client,
		jwksURL:   strings.TrimSpace(cfg.JWKSURL),
		keysByKid: make(map[string]storedKey),
	}
}

func (v *Verifier) discoverJWKSURL(ctx context.Context) (string, error) {
	v.mu.RLock()
	cached := v.jwksURL
	v.mu.RUnlock()
	if cached != "" {
		return cached, nil
	}
	issuer := strings.TrimRight(strings.TrimSpace(v.cfg.Issuer), "/")
	if issuer == "" {
		return "", errors.New("neither jwks_url nor issuer configured for OIDC verification")
	}
	discURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc discovery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery returned HTTP %d", resp.StatusCode)
	}
	var doc oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBodyBytes)).Decode(&doc); err != nil {
		return "", fmt.Errorf("oidc discovery decode failed: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("oidc discovery missing jwks_uri")
	}
	v.mu.Lock()
	v.jwksURL = doc.JWKSURI
	v.mu.Unlock()
	return doc.JWKSURI, nil
}

func (v *Verifier) refreshJWKS(ctx context.Context, force bool) error {
	v.mu.RLock()
	fresh := !v.fetchedAt.IsZero() && time.Since(v.fetchedAt) < v.cfg.CacheTTL
	tooSoon := !v.lastRefresh.IsZero() && time.Since(v.lastRefresh) < 2*time.Second
	v.mu.RUnlock()

	if fresh && !force {
		return nil
	}
	if force && tooSoon && fresh {
		return nil
	}

	// Singleflight serialization prevents concurrent refresh stampedes
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	v.mu.RLock()
	fresh = !v.fetchedAt.IsZero() && time.Since(v.fetchedAt) < v.cfg.CacheTTL
	tooSoon = !v.lastRefresh.IsZero() && time.Since(v.lastRefresh) < 2*time.Second
	v.mu.RUnlock()
	if fresh && (!force || tooSoon) {
		return nil
	}

	jwksURL, err := v.discoverJWKSURL(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned HTTP %d", resp.StatusCode)
	}
	var doc jwksDocument
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBodyBytes)).Decode(&doc); err != nil {
		return fmt.Errorf("jwks decode failed: %w", err)
	}

	byKid := make(map[string]storedKey)
	var unnamed []storedKey
	for _, k := range doc.Keys {
		// RFC 7517 §4.2: reject encryption or non-signature keys
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parseJWK(k)
		if err != nil {
			continue
		}
		sk := storedKey{Pub: pub, Alg: k.Alg}
		if k.Kid != "" {
			byKid[k.Kid] = sk
		} else {
			unnamed = append(unnamed, sk)
		}
	}

	now := time.Now()
	v.mu.Lock()
	v.keysByKid = byKid
	v.unnamedKeys = unnamed
	v.fetchedAt = now
	v.lastRefresh = now
	v.mu.Unlock()
	return nil
}

func parseJWK(k jwkKey) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil || len(nb) < 256 { // Enforce >= 2048-bit RSA modulus
			return nil, errors.New("invalid or weak RSA modulus")
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		eInt := 0
		for _, b := range eb {
			eInt = (eInt << 8) | int(b)
		}
		if eInt < 3 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: eInt,
		}, nil

	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported EC curve %s", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(xb) != 32 {
			return nil, errors.New("invalid P-256 X coordinate length")
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil || len(yb) != 32 {
			return nil, errors.New("invalid P-256 Y coordinate length")
		}
		x := new(big.Int).SetBytes(xb)
		y := new(big.Int).SetBytes(yb)
		curve := elliptic.P256()
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("EC JWK point is not on P-256 curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	default:
		return nil, fmt.Errorf("unsupported JWK kty %s", k.Kty)
	}
}

func (v *Verifier) lookupKeys(ctx context.Context, kid string) ([]storedKey, error) {
	if err := v.refreshJWKS(ctx, false); err != nil {
		return nil, err
	}
	v.mu.RLock()
	if kid != "" {
		if sk, ok := v.keysByKid[kid]; ok {
			v.mu.RUnlock()
			return []storedKey{sk}, nil
		}
	} else if len(v.keysByKid) > 0 && len(v.unnamedKeys) == 0 {
		v.mu.RUnlock()
		return nil, errors.New("JWT missing required kid header when JWKS uses named keys")
	}
	v.mu.RUnlock()

	if kid != "" {
		_ = v.refreshJWKS(ctx, true)
		v.mu.RLock()
		defer v.mu.RUnlock()
		if sk, ok := v.keysByKid[kid]; ok {
			return []storedKey{sk}, nil
		}
		return nil, fmt.Errorf("unknown JWK kid %q", kid)
	}

	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.unnamedKeys) == 0 {
		return nil, errors.New("no usable keys in JWKS")
	}
	return append([]storedKey(nil), v.unnamedKeys...), nil
}

// VerifyToken cryptographically verifies a compact JWT (RS256 or ES256), validates
// `iss`, `aud`, `exp`, and `nbf`, and extracts RFC 8693 OBO principal claims (`sub` + `act.sub`).
func (v *Verifier) VerifyToken(ctx context.Context, rawToken string) (*VerifiedPrincipal, error) {
	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid JWT header encoding")
	}
	var hdr struct {
		Alg  string   `json:"alg"`
		Kid  string   `json:"kid"`
		Crit []string `json:"crit"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, errors.New("invalid JWT header JSON")
	}
	if len(hdr.Crit) > 0 {
		return nil, errors.New("unsupported critical JWT header extensions (crit)")
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return nil, fmt.Errorf("disallowed JWT algorithm %q (only RS256/ES256 permitted)", hdr.Alg)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid JWT signature encoding")
	}

	keys, err := v.lookupKeys(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signingInput)

	verified := false
	for _, sk := range keys {
		if sk.Alg != "" && sk.Alg != hdr.Alg {
			continue
		}
		switch hdr.Alg {
		case "RS256":
			if rsaPub, ok := sk.Pub.(*rsa.PublicKey); ok {
				if rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sigBytes) == nil {
					verified = true
				}
			}
		case "ES256":
			if ecPub, ok := sk.Pub.(*ecdsa.PublicKey); ok && len(sigBytes) == 64 {
				r := new(big.Int).SetBytes(sigBytes[:32])
				s := new(big.Int).SetBytes(sigBytes[32:])
				if ecdsa.Verify(ecPub, digest[:], r, s) {
					verified = true
				}
			}
		}
		if verified {
			break
		}
	}
	if !verified {
		return nil, errors.New("JWT cryptographic signature verification failed")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid JWT payload encoding")
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("invalid JWT payload JSON")
	}

	now := time.Now().Unix()
	skew := int64(v.cfg.ClockSkew.Seconds())

	expFloat, hasExp := claims["exp"].(float64)
	if !hasExp || now-skew >= int64(expFloat) {
		return nil, errors.New("JWT is expired or missing exp claim")
	}
	if nbfFloat, hasNbf := claims["nbf"].(float64); hasNbf {
		if now+skew < int64(nbfFloat) {
			return nil, errors.New("JWT not yet valid (nbf)")
		}
	}

	iss, _ := claims["iss"].(string)
	if v.cfg.Issuer != "" && strings.TrimRight(iss, "/") != strings.TrimRight(v.cfg.Issuer, "/") {
		return nil, fmt.Errorf("JWT issuer mismatch: got %q, want %q", iss, v.cfg.Issuer)
	}

	if v.cfg.Audience != "" {
		if !audienceMatches(claims["aud"], v.cfg.Audience) {
			return nil, fmt.Errorf("JWT audience mismatch: want %q", v.cfg.Audience)
		}
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("JWT missing required sub claim")
	}

	var actSub string
	if actObj, ok := claims["act"].(map[string]any); ok {
		actSub, _ = actObj["sub"].(string)
	}
	azp, _ := claims["azp"].(string)

	canonical := "user:" + sub
	if actSub != "" {
		canonical = fmt.Sprintf("user:%s|agent:%s", sub, actSub)
	} else if azp != "" {
		canonical = fmt.Sprintf("user:%s|agent:%s", sub, azp)
	}

	return &VerifiedPrincipal{
		Subject:       sub,
		ActorSubject:  actSub,
		AuthorizedApp: azp,
		Issuer:        iss,
		CanonicalID:   canonical,
	}, nil
}

func audienceMatches(rawAud any, expected string) bool {
	switch a := rawAud.(type) {
	case string:
		return a == expected
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}
