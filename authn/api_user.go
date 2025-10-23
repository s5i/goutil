package authn

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// Token represents an authentication token.
type Token struct {
	// Required.
	Issuer string // e.g. "google", "discord"
	ID     string

	// Optional.
	DisplayName string
	IsFake      bool
}

// RequireToken is a middleware function that ensures that the user is authenticated.
// Use Authn.Token to get the Token.
func (a *Authn) RequireToken(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del(keyHeader)
		r.Header.Del(issuerHeader)
		r.Header.Del(idHeader)
		r.Header.Del(displayNameHeader)
		r.Header.Del(isFakeHeader)

		for _, c := range r.Cookies() {
			if c.Name != a.jwtCookieName {
				continue
			}
			token, ok := a.jwtVerify(c.Value)
			if !ok {
				a.oAuthDialog(w, r)
				return
			}

			r.Header.Add(keyHeader, a.middlewareKey)
			r.Header.Add(issuerHeader, token.Issuer)
			r.Header.Add(idHeader, token.ID)
			r.Header.Add(displayNameHeader, token.DisplayName)
			if token.IsFake {
				r.Header.Add(isFakeHeader, "1")
			}

			next.ServeHTTP(w, r)
			return
		}

		a.oAuthDialog(w, r)
	}
}

// Token extracts an authentication Token from request's headers.
// Requires Authn.RequireToken middleware.
func (a *Authn) Token(r *http.Request) (*Token, bool) {
	if r.Header.Get(keyHeader) != a.middlewareKey {
		return nil, false
	}

	return UnsafeToken(r)
}

// UnsafeToken extracts an authentication Token from request's headers.
//
// WARNING: users can spoof the header.
// Only use this if you are absolutely certain that Auth.RequireToken middleware was applied.
func UnsafeToken(r *http.Request) (*Token, bool) {
	t := &Token{
		Issuer:      r.Header.Get(issuerHeader),
		ID:          r.Header.Get(idHeader),
		DisplayName: r.Header.Get(displayNameHeader),
		IsFake:      r.Header.Get(isFakeHeader) == "1",
	}

	if t.Issuer == "" || t.ID == "" {
		return nil, false
	}

	return t, true
}

// Authn provides authentication via OAuth.
type Authn struct {
	googleCfg  *oauth2.Config
	discordCfg *oauth2.Config
	fakeCfg    *FakeOAuthConfig

	oAuthInFlightMu sync.Mutex
	oAuthInFlight   map[string]*oauthState
	jwtSecret       []byte
	jwtTTL          time.Duration
	jwtCookieName   string
	middlewareKey   string
}

const (
	keyHeader         = "X-S5I-Authn-Key"
	issuerHeader      = "X-S5I-Authn-Token-Issuer"
	idHeader          = "X-S5I-Authn-Token-ID"
	displayNameHeader = "X-S5I-Authn-Token-DisplayName"
	isFakeHeader      = "X-S5I-Authn-Token-IsFake"
)
