// Kenni — Go example.
//
// Sign in with Kenni (OIDC: Authorization Code + PKCE), call a protected
// API endpoint with the user's access token, and run a client-credentials
// grant. Uses golang.org/x/oauth2 + github.com/coreos/go-oidc/v3 — the de
// facto OIDC stack for Go.
package main

import (
	"context"
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

//go:embed index.html
var templatesFS embed.FS

const listenAddr = "localhost:8081"

type config struct {
	Issuer                string
	ClientID              string
	ClientSecret          string
	RedirectURI           string
	PostLogoutRedirectURI string
	APIScope              string
	APIAudience           string
	M2MClientID           string
	M2MClientSecret       string
	M2MScope              string
}

func (c config) apiEnabled() bool { return c.APIScope != "" }
func (c config) m2mEnabled() bool {
	return c.M2MClientID != "" && c.M2MClientSecret != "" && c.M2MScope != ""
}

// Subset of the discovery document we actually use.
type discoveryClaims struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
	TokenEndpoint      string `json:"token_endpoint"`
}

type app struct {
	cfg          config
	oauth2Config oauth2.Config
	idVerifier   *oidc.IDTokenVerifier
	apiVerifier  *oidc.IDTokenVerifier // nil when API feature is disabled
	discovery    discoveryClaims
	sessions     *sessionStore
	tmpl         *template.Template
}

func main() {
	// Best-effort .env load. Real env vars still win.
	_ = godotenv.Load()

	cfg := loadConfig()
	a := newApp(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/auth/login", a.handleLogin)
	mux.HandleFunc("/auth/callback", a.handleCallback)
	mux.HandleFunc("/auth/logout", a.handleLogout)
	mux.HandleFunc("/auth/rp-logout", a.handleRpLogout)
	mux.HandleFunc("/api/me", a.handleMe)
	mux.HandleFunc("/api/client-credentials", a.handleClientCredentials)
	mux.HandleFunc("/api/protected-resource", a.handleProtectedResource)

	log.Printf("listening on http://%s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func loadConfig() config {
	cfg := config{
		Issuer:                required("KENNI_ISSUER"),
		ClientID:              required("KENNI_CLIENT_ID"),
		ClientSecret:          required("KENNI_CLIENT_SECRET"),
		RedirectURI:           getenv("KENNI_REDIRECT_URI", "http://"+listenAddr+"/auth/callback"),
		PostLogoutRedirectURI: getenv("KENNI_POST_LOGOUT_REDIRECT_URI", "http://"+listenAddr+"/"),
		APIScope:              os.Getenv("KENNI_API_SCOPE"),
		APIAudience:           os.Getenv("KENNI_API_AUDIENCE"),
		M2MClientID:           os.Getenv("KENNI_M2M_CLIENT_ID"),
		M2MClientSecret:       os.Getenv("KENNI_M2M_CLIENT_SECRET"),
		M2MScope:              os.Getenv("KENNI_M2M_SCOPE"),
	}
	if cfg.APIAudience == "" {
		cfg.APIAudience = cfg.ClientID + "-api"
	}
	return cfg
}

func newApp(cfg config) *app {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		log.Fatalf("OIDC discovery failed: %v", err)
	}

	var disc discoveryClaims
	if err := provider.Claims(&disc); err != nil {
		log.Fatalf("discovery claims parse failed: %v", err)
	}

	scopes := []string{oidc.ScopeOpenID, "profile", "national_id", oidc.ScopeOfflineAccess}
	if cfg.APIScope != "" {
		scopes = append(scopes, cfg.APIScope)
	}

	a := &app{
		cfg: cfg,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopes,
		},
		// Verifies id_tokens issued for our client_id (ClientID claim → aud check).
		idVerifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		discovery:  disc,
		sessions:   newSessionStore(),
		tmpl:       template.Must(template.ParseFS(templatesFS, "index.html")),
	}

	if cfg.apiEnabled() {
		// Verifies access tokens our protected resource accepts. The audience
		// claim on a Kenni access token is the API audience (e.g.
		// `<client_id>-api`), not the client_id.
		a.apiVerifier = provider.Verifier(&oidc.Config{ClientID: cfg.APIAudience})
	}

	return a
}

func required(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env var: %s", key)
	}
	return v
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
