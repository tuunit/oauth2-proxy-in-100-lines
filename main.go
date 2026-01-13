package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"golang.org/x/oauth2"
)

var config *oauth2.Config

func init() {
	config = &oauth2.Config{
		ClientID:     "oauth2-proxy",
		ClientSecret: "72341b6d-7065-4518-a0e4-50ee15025608",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:9080/realms/oauth2-proxy/protocol/openid-connect/auth",
			TokenURL: "http://localhost:9080/realms/oauth2-proxy/protocol/openid-connect/token",
		},
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/", handleProtected)

	log.Println("Proxy on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Step 1: Redirect to OIDC provider
func handleLogin(w http.ResponseWriter, r *http.Request) {
	authURL := config.AuthCodeURL("state")
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// Step 2: Exchange code for token
func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "no code", http.StatusBadRequest)
		return
	}

	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("exchange: %v", err), http.StatusInternalServerError)
		return
	}

	// Store token in cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token.AccessToken,
		HttpOnly: true,
		Path:     "/",
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Step 3: Validate token + proxy request
func handleProtected(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	// Forward with auth header
	r.Header.Set("Authorization", "Bearer "+cookie.Value)
	proxy := httputil.NewSingleHostReverseProxy(
		&url.URL{Scheme: "http", Host: "localhost:8081"},
	)
	proxy.ServeHTTP(w, r)
}
