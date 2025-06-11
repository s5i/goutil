package authn

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/multierr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// New instantiates an Authn object. Mandatory options are ClientID, ClientSecret, Hostname, and CallbackPath.
func New(options ...Option) (*Authn, error) {
	opts := newOpts()
	var errs error
	for _, opt := range options {
		errs = multierr.Append(errs, opt(opts))
	}
	if errs != nil {
		return nil, errs
	}

	callbackURL, err := url.JoinPath("http://", opts.Hostname, opts.CallbackPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build callback URL: %v", err)
	}
	ret := &Authn{
		oAuthCfg: &oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{"email"},
			Endpoint:     google.Endpoint,
		},
		oAuthInFlight:   map[string]*oauthState{},
		jwtSecret:       []byte(opts.JWTSecret),
		jwtTTL:          opts.JWTTTL,
		jwtCookieName:   opts.JWTCookieName,
		middlewareToken: randomString(32),
	}
	opts.Mux.HandleFunc(opts.CallbackPath, ret.oAuthCallback)
	return ret, nil
}

type Option func(*opts) error

// OptClientID sets the OAuth client ID.
func OptClientID(clientID string) Option {
	return func(o *opts) error {
		if clientID == "" {
			return fmt.Errorf("client ID cannot be empty")
		}
		o.ClientID = clientID
		return nil
	}
}

// OptClientSecret sets the OAuth client secret.
func OptClientSecret(clientSecret string) Option {
	return func(o *opts) error {
		if clientSecret == "" {
			return fmt.Errorf("client secret cannot be empty")
		}
		o.ClientSecret = clientSecret
		return nil
	}
}

// OptHostname sets the hostname used for OAuth callbacks.
func OptHostname(hostname string) Option {
	if hostname == "" {
		return func(o *opts) error {
			return fmt.Errorf("hostname cannot be empty")
		}
	}
	return func(o *opts) error {
		o.Hostname = hostname
		return nil
	}
}

// OptCallbackPath sets the path for OAuth callbacks.
func OptCallbackPath(callbackPath string) Option {
	return func(o *opts) error {
		o.CallbackPath = callbackPath
		return nil
	}
}

// OptMux sets the HTTP ServeMux for handling OAuth callbacks.
//
// If omitted, defaults to http.DefaultServeMux.
func OptMux(mux *http.ServeMux) Option {
	return func(o *opts) error {
		o.Mux = mux
		return nil
	}
}

// OptJWTSecret sets the JWT secret for signing tokens.
//
// If omitted, defaults to a random string.
// This is OK for long-running single-instance deployments.
// For other cases, you should provide a consistent secret to ensure JWTs can be verified across instances / restarts.
func OptJWTSecret(jwtSecret string) Option {
	return func(o *opts) error {
		if jwtSecret == "" {
			return fmt.Errorf("JWT secret cannot be empty")
		}

		o.JWTSecret = jwtSecret
		return nil
	}
}

// OptJWTTTL sets the JWT cookie's TTL.
//
// If omitted, defaults to 24h.
func OptJWTTTL(jwtTTL time.Duration) Option {
	return func(o *opts) error {
		if jwtTTL <= 0 {
			return fmt.Errorf("JWT TTL must be greater than zero")
		}

		o.JWTTTL = jwtTTL
		return nil
	}
}

// OptJWTCookieName sets the JWT cookie's name.
//
// If omitted, defaults to "token".
func OptJWTCookieName(jwtCookieName string) Option {
	return func(o *opts) error {
		if jwtCookieName == "" {
			return fmt.Errorf("JWT cookie name cannot be empty")
		}

		o.JWTCookieName = jwtCookieName
		return nil
	}
}

type opts struct {
	ClientID      string
	ClientSecret  string
	Hostname      string
	CallbackPath  string
	Mux           *http.ServeMux
	JWTSecret     string
	JWTTTL        time.Duration
	JWTCookieName string
}

func newOpts() *opts {
	return &opts{
		Mux:           http.DefaultServeMux,
		JWTSecret:     randomString(32),
		JWTTTL:        24 * time.Hour,
		JWTCookieName: "token",
	}
}
