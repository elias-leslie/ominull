package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type oidcState struct {
	Nonce    string
	Verifier string
	Expires  time.Time
}

type oidcProviderState struct {
	Issuer   string
	ClientID string
	Redirect string
	Provider *oidc.Provider
}

type oidcClaims struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Issuer  string `json:"iss"`
}

const maxOIDCStates = 1024

func (s *Server) oidcStateStore() (map[string]oidcState, *sync.Mutex) {
	// The setup mutex protects short-lived OIDC state as well. State is kept in
	// memory so authorization codes and PKCE verifiers never enter SQLite or a
	// log. The fields are lazily attached through package-level storage below.
	return oidcStatesFor(s)
}

var oidcStateRegistry struct {
	sync.Mutex
	items map[*Server]map[string]oidcState
}

func oidcStatesFor(s *Server) (map[string]oidcState, *sync.Mutex) {
	oidcStateRegistry.Lock()
	defer oidcStateRegistry.Unlock()
	if oidcStateRegistry.items == nil {
		oidcStateRegistry.items = map[*Server]map[string]oidcState{}
	}
	if oidcStateRegistry.items[s] == nil {
		oidcStateRegistry.items[s] = map[string]oidcState{}
	}
	return oidcStateRegistry.items[s], &oidcStateRegistry.Mutex
}

func (s *Server) oidcSettings(ctx context.Context) (*oidcProviderState, error) {
	issuer, err := s.store.GetSetting("oidc.issuer")
	if err != nil {
		return nil, err
	}
	clientID, err := s.store.GetSetting("oidc.client_id")
	if err != nil {
		return nil, err
	}
	redirect, err := s.store.GetSetting("oidc.redirect_url")
	if err != nil {
		return nil, err
	}
	issuer, clientID, redirect = strings.TrimSpace(issuer), strings.TrimSpace(clientID), strings.TrimSpace(redirect)
	if issuer == "" || clientID == "" || redirect == "" {
		return nil, fmt.Errorf("OIDC is not configured: issuer, client id, and redirect URL are required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	return &oidcProviderState{Issuer: issuer, ClientID: clientID, Redirect: redirect, Provider: provider}, nil
}

func oidcRandom(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	provider, err := s.oidcSettings(ctx)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	state, err := oidcRandom(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not create OIDC state")
		return
	}
	nonce, err := oidcRandom(24)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not create OIDC nonce")
		return
	}
	verifier, err := oidcRandom(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not create PKCE verifier")
		return
	}
	states, mu := s.oidcStateStore()
	mu.Lock()
	now := time.Now().UTC()
	for key, pending := range states {
		if now.After(pending.Expires) {
			delete(states, key)
		}
	}
	if len(states) >= maxOIDCStates {
		mu.Unlock()
		writeJSONError(w, http.StatusServiceUnavailable, "too many pending OIDC sign-ins; retry shortly")
		return
	}
	states[state] = oidcState{Nonce: nonce, Verifier: verifier, Expires: now.Add(10 * time.Minute)}
	mu.Unlock()
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{Name: "ominull_oidc_state", Value: state, Path: "/oidc", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	config := oauth2.Config{ClientID: provider.ClientID, Endpoint: provider.Provider.Endpoint(), RedirectURL: provider.Redirect, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	url := config.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("code_challenge", oidcS256(verifier)), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	http.Redirect(w, r, url, http.StatusFound)
}

func oidcS256(value string) string {
	hash := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	cookie, err := r.Cookie("ominull_oidc_state")
	if err != nil || state == "" || cookie.Value != state {
		writeJSONError(w, http.StatusBadRequest, "OIDC state validation failed")
		return
	}
	states, mu := s.oidcStateStore()
	mu.Lock()
	stored, ok := states[state]
	delete(states, state)
	mu.Unlock()
	if !ok || time.Now().UTC().After(stored.Expires) {
		writeJSONError(w, http.StatusBadRequest, "OIDC state expired")
		return
	}
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{Name: "ominull_oidc_state", Value: "", Path: "/oidc", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if strings.TrimSpace(r.URL.Query().Get("code")) == "" {
		writeJSONError(w, http.StatusBadRequest, "OIDC authorization code missing")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	provider, err := s.oidcSettings(ctx)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	secret := ""
	s.setupMu.Lock()
	configPath := s.setupConfigPath
	s.setupMu.Unlock()
	if configPath != "" {
		secretPath := filepath.Join(filepath.Dir(configPath), "oidc-client.secret")
		info, statErr := os.Lstat(secretPath)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				writeJSONError(w, http.StatusServiceUnavailable, "OIDC client secret file is not a protected regular file")
				return
			}
			raw, readErr := os.ReadFile(secretPath)
			if readErr != nil {
				writeJSONError(w, http.StatusServiceUnavailable, "OIDC client secret could not be read")
				return
			}
			secret = strings.TrimSpace(string(raw))
		} else if !errors.Is(statErr, os.ErrNotExist) {
			writeJSONError(w, http.StatusServiceUnavailable, "OIDC client secret path could not be checked")
			return
		}
	}
	oauthConfig := oauth2.Config{ClientID: provider.ClientID, ClientSecret: secret, Endpoint: provider.Provider.Endpoint(), RedirectURL: provider.Redirect, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	token, err := oauthConfig.Exchange(ctx, r.URL.Query().Get("code"), oauth2.SetAuthURLParam("code_verifier", stored.Verifier))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "OIDC code exchange failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		writeJSONError(w, http.StatusUnauthorized, "OIDC provider returned no ID token")
		return
	}
	verifier := provider.Provider.Verifier(&oidc.Config{ClientID: provider.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "OIDC ID token verification failed")
		return
	}
	if !secureStringEqual(idToken.Nonce, stored.Nonce) {
		writeJSONError(w, http.StatusUnauthorized, "OIDC nonce validation failed")
		return
	}
	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil || claims.Subject == "" || claims.Email == "" || claims.Issuer != provider.Issuer {
		writeJSONError(w, http.StatusUnauthorized, "OIDC identity claims are incomplete")
		return
	}
	identity, listed, err := s.store.ResolveOperatorIdentity(provider.Issuer, claims.Subject, claims.Email)
	if err != nil || !listed {
		writeJSONError(w, http.StatusForbidden, "OIDC identity is not an Ominull operator")
		return
	}
	if err := s.store.SetSetting("oidc.last_success", time.Now().UTC().Format(time.RFC3339)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "OIDC sign-in state could not be saved")
		return
	}
	s.setConsoleSession(w, r, accessOperator{Email: identity.Email, Role: identity.Role, Issuer: identity.Issuer, Subject: identity.Subject})
	s.auditAs(r, identity.Email, "OIDC_SIGNIN", identity.Subject, "Signed in through verified OIDC issuer")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
