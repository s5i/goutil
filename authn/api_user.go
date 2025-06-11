package authn

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// RequireUser is a middleware function that ensures that the user is authenticated.
// Use User to get the username.
func (a *Authn) RequireUser(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del(userHeader)
		r.Header.Del(middlewareTokenHeader)
		for _, c := range r.Cookies() {
			if c.Name != a.jwtCookieName {
				continue
			}
			user, ok := a.jwtVerify(c.Value)
			if !ok {
				a.oAuthDialog(w, r)
				return
			}
			r.Header.Add(userHeader, user)
			r.Header.Add(middlewareTokenHeader, a.middlewareToken)
			next.ServeHTTP(w, r)
			return
		}
		a.oAuthDialog(w, r)
		return
	}
}

// User extracts username from request's headers.
// Requires Auth.RequireUser middleware.
func (a *Authn) User(r *http.Request) (string, bool) {
	if r.Header.Get(middlewareTokenHeader) != a.middlewareToken {
		return "", false
	}
	user := r.Header.Get(userHeader)
	return user, user != ""
}

// UnsafeUser extracts username from request's headers.
//
// WARNING: users can spoof the header.
// Only use this if you are absolutely certain that Auth.RequireUser middleware was applied.
func UnsafeUser(r *http.Request) (string, bool) {
	user := r.Header.Get(userHeader)
	return user, user != ""
}

// Authn provides authentication via OAuth.
type Authn struct {
	oAuthCfg        *oauth2.Config
	oAuthInFlightMu sync.Mutex
	oAuthInFlight   map[string]*oauthState
	jwtSecret       []byte
	jwtTTL          time.Duration
	jwtCookieName   string
	middlewareToken string
}

const (
	userHeader            = "X-S5I-Authenticated-User"
	middlewareTokenHeader = "X-S5I-Middleware-Token"
)
