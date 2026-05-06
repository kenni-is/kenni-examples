package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Short-lived cookies that carry the OAuth state / nonce / PKCE-verifier from
// the login redirect to the callback. Cleared as soon as we've used them.
const (
	cookieState    = "kenni_oauth_state"
	cookieNonce    = "kenni_oauth_nonce"
	cookieVerifier = "kenni_oauth_verifier"
)

type indexData struct {
	SignedIn   bool
	Name       string
	NationalID string
	APIEnabled bool
	M2MEnabled bool
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := indexData{
		APIEnabled: a.cfg.apiEnabled(),
		M2MEnabled: a.cfg.m2mEnabled(),
	}
	if sess := a.currentSession(r); sess != nil {
		data.SignedIn = true
		data.Name = sess.Name
		data.NationalID = sess.NationalID
	}
	w.Header().Set("content-type", "text/html; charset=utf-8")
	if err := a.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randString(32)
	nonce := randString(32)
	pkceVerifier := oauth2.GenerateVerifier()

	setShortCookie(w, cookieState, state)
	setShortCookie(w, cookieNonce, nonce)
	setShortCookie(w, cookieVerifier, pkceVerifier)

	authURL := a.oauth2Config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkceVerifier),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Surface IdP-side errors before doing anything else.
	if errMsg := q.Get("error"); errMsg != "" {
		http.Error(w,
			fmt.Sprintf("OIDC error: %s — %s", errMsg, q.Get("error_description")),
			http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie(cookieState)
	if err != nil {
		http.Error(w, "state cookie missing", http.StatusBadRequest)
		return
	}
	if q.Get("state") != stateCookie.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	verifierCookie, err := r.Cookie(cookieVerifier)
	if err != nil {
		http.Error(w, "PKCE verifier cookie missing", http.StatusBadRequest)
		return
	}
	nonceCookie, err := r.Cookie(cookieNonce)
	if err != nil {
		http.Error(w, "nonce cookie missing", http.StatusBadRequest)
		return
	}

	token, err := a.oauth2Config.Exchange(r.Context(), q.Get("code"),
		oauth2.VerifierOption(verifierCookie.Value),
	)
	if err != nil {
		http.Error(w, "code exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}
	idToken, err := a.idVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "id_token verify failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if idToken.Nonce != nonceCookie.Value {
		http.Error(w, "nonce did not match", http.StatusBadRequest)
		return
	}

	var claims struct {
		Sub        string `json:"sub"`
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
		NationalID string `json:"national_id"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	displayName := claims.Name
	if displayName == "" {
		displayName = strings.TrimSpace(claims.GivenName + " " + claims.FamilyName)
	}

	id := newSessionID()
	a.sessions.save(id, &session{
		Token:      token,
		IDToken:    rawIDToken,
		Sub:        claims.Sub,
		Name:       displayName,
		NationalID: claims.NationalID,
	})

	a.setSessionCookie(w, id)
	clearShortCookie(w, cookieState)
	clearShortCookie(w, cookieNonce)
	clearShortCookie(w, cookieVerifier)

	http.Redirect(w, r, "/", http.StatusFound)
}

// Local sign-out only — Kenni's session cookie is untouched, so the next
// sign-in is silent. Use /auth/rp-logout to also end Kenni's session.
func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if id := a.sessionID(r); id != "" {
		a.sessions.delete(id)
	}
	a.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// RP-initiated logout: clear the local session first, then redirect the
// browser to Kenni's end_session_endpoint with id_token_hint +
// post_logout_redirect_uri. Order matters — if the Kenni redirect fails,
// the local session is still cleared.
func (a *app) handleRpLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var idTokenHint string
	if sess := a.currentSession(r); sess != nil {
		idTokenHint = sess.IDToken
	}
	if id := a.sessionID(r); id != "" {
		a.sessions.delete(id)
	}
	a.clearSessionCookie(w)

	if a.discovery.EndSessionEndpoint == "" {
		http.Error(w, "issuer does not advertise end_session_endpoint", http.StatusInternalServerError)
		return
	}
	u, err := url.Parse(a.discovery.EndSessionEndpoint)
	if err != nil {
		http.Error(w, "invalid end_session_endpoint", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("client_id", a.cfg.ClientID)
	q.Set("post_logout_redirect_uri", a.cfg.PostLogoutRedirectURI)
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func randString(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func setShortCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(10 * time.Minute / time.Second),
	})
}

func clearShortCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}
