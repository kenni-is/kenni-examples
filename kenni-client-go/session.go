package main

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// In-memory session store keyed by an opaque, random session ID. Restart-safe
// only in the sense that "we lose all sessions on restart, sign in again" —
// fine for a demo. Replace with Redis / DB / signed cookies for production.

const sessionCookie = "kenni_session"

type session struct {
	mu         sync.Mutex
	Token      *oauth2.Token
	IDToken    string
	Sub        string
	Name       string
	NationalID string
}

type sessionStore struct {
	mu sync.RWMutex
	m  map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: make(map[string]*session)}
}

func (s *sessionStore) get(id string) *session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[id]
}

func (s *sessionStore) save(id string, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = sess
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

func newSessionID() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *app) sessionID(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func (a *app) currentSession(r *http.Request) *session {
	id := a.sessionID(r)
	if id == "" {
		return nil
	}
	return a.sessions.get(id)
}

func (a *app) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(8 * time.Hour / time.Second),
	})
}

func (a *app) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}
