package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

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
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/", handleProtected)

	log.Println("Proxy on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	authURL := config.AuthCodeURL("state")
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

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

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token.AccessToken,
		HttpOnly: true,
		Path:     "/",
	})

	// NEW: Store token expiry time
	http.SetCookie(w, &http.Cookie{
		Name:  "token_expiry",
		Value: strconv.FormatInt(token.Expiry.Unix(), 10),
		Path:  "/",
	})

	// NEW: Store refresh token if available
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token.RefreshToken,
		HttpOnly: true,
		Path:     "/",
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{"access_token", "refresh_token", "token_expiry"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			MaxAge:   -1,
			Path:     "/",
			HttpOnly: true,
		})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	accessCookie, err := r.Cookie("access_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	// NEW: Check token expiry and refresh if needed
	expiryCookie, _ := r.Cookie("token_expiry")
	refreshCookie, _ := r.Cookie("refresh_token")

	var expiry time.Time
	if expiryCookie != nil {
		if unix, err := strconv.ParseInt(expiryCookie.Value, 10, 64); err == nil {
			expiry = time.Unix(unix, 0)
		}
	}

	if time.Now().After(expiry) && refreshCookie != nil {
		token := &oauth2.Token{RefreshToken: refreshCookie.Value}
		newToken, err := config.TokenSource(context.Background(), token).Token()
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    newToken.AccessToken,
			HttpOnly: true,
			Path:     "/",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "token_expiry",
			Value: strconv.FormatInt(newToken.Expiry.Unix(), 10),
			Path:  "/",
		})
		accessCookie.Value = newToken.AccessToken
	}

	r.Header.Set("Authorization", "Bearer "+accessCookie.Value)
	proxy := httputil.NewSingleHostReverseProxy(
		&url.URL{Scheme: "http", Host: "localhost:8081"},
	)
	proxy.ServeHTTP(w, r)
}
