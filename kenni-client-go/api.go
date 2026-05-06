package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// /api/me — server-side proxy. Pulls the user's stored Kenni access token
// (auto-refreshing if expired via oauth2.TokenSource) and uses it to call
// our own /api/protected-resource. Done server-side so the access token
// never reaches the browser.
func (a *app) handleMe(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.apiEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "KENNI_API_SCOPE is not configured on this app.",
		})
		return
	}

	sess := a.currentSession(r)
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Not signed in."})
		return
	}

	sess.mu.Lock()
	ts := a.oauth2Config.TokenSource(r.Context(), sess.Token)
	tok, err := ts.Token()
	if err != nil {
		sess.mu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":  "Could not retrieve access token.",
			"detail": err.Error(),
		})
		return
	}
	if tok.AccessToken != sess.Token.AccessToken {
		sess.Token = tok // persist refreshed token
	}
	accessToken := tok.AccessToken
	sess.mu.Unlock()

	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet,
		requestOrigin(r)+"/api/protected-resource", nil)
	req.Header.Set("authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// /api/client-credentials — POSTs grant_type=client_credentials to Kenni's
// token endpoint with HTTP Basic auth, then decodes the access token's claims
// for display.
func (a *app) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST only"})
		return
	}
	if !a.cfg.m2mEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "Set KENNI_M2M_CLIENT_ID, KENNI_M2M_CLIENT_SECRET, and KENNI_M2M_SCOPE.",
		})
		return
	}

	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("scope", a.cfg.M2MScope)

	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
		a.discovery.TokenEndpoint, strings.NewReader(body.Encode()))
	// RFC 6749 §2.3.1: form-urlencode each credential before joining and
	// base64-encoding for HTTP Basic.
	basic := base64.StdEncoding.EncodeToString([]byte(
		url.QueryEscape(a.cfg.M2MClientID) + ":" + url.QueryEscape(a.cfg.M2MClientSecret),
	))
	req.Header.Set("authorization", "Basic "+basic)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var detail any
		_ = json.Unmarshal(raw, &detail)
		writeJSON(w, resp.StatusCode, map[string]any{
			"error":  "Token endpoint rejected the request.",
			"detail": detail,
		})
		return
	}

	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &token); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token_type": token.TokenType,
		"expires_in": token.ExpiresIn,
		"scope":      token.Scope,
		"claims":     decodeJWTClaims(token.AccessToken), // nil if opaque
	})
}

// /api/protected-resource — bearer-protected endpoint demonstrating local
// access-token verification. Verifies signature (via Kenni's JWKS), issuer,
// audience, and expiry using go-oidc's verifier (configured with the API
// audience). Then asserts the configured KENNI_API_SCOPE is on the token.
func (a *app) handleProtectedResource(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.apiEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "KENNI_API_SCOPE is not configured on this app.",
		})
		return
	}

	authz := r.Header.Get("authorization")
	if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "Missing Authorization: Bearer header.",
		})
		return
	}
	raw := strings.TrimSpace(authz[len("Bearer "):])

	tok, err := a.apiVerifier.Verify(r.Context(), raw)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":  "Token verification failed.",
			"detail": err.Error(),
		})
		return
	}

	var c struct {
		Sub        string `json:"sub"`
		NationalID string `json:"national_id"`
		Scope      string `json:"scope"`
		Exp        int64  `json:"exp"`
	}
	if err := tok.Claims(&c); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	scopes := strings.Fields(c.Scope)
	if !contains(scopes, a.cfg.APIScope) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":  "Token is missing required scope '" + a.cfg.APIScope + "'.",
			"scopes": scopes,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":     "Halló!",
		"served_by":   "Go (golang.org/x/oauth2 + go-oidc/v3) example",
		"sub":         c.Sub,
		"national_id": c.NationalID,
		"scopes":      scopes,
		"expires_at":  time.Unix(c.Exp, 0).UTC().Format(time.RFC3339),
	})
}

func decodeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil // opaque token
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
