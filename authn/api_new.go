package authn

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ravener/discord-oauth2"
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

	ret := &Authn{
		oAuthInFlight: map[string]*oauthState{},
		jwtSecret:     []byte(opts.JWTSecret),
		jwtTTL:        opts.JWTTTL,
		jwtCookieName: opts.JWTCookieName,
		middlewareKey: randomString(32),
	}

	if opts.GoogleClientID != "" {
		googleCallbackPath, err := url.JoinPath(opts.CallbackPath, "/google")
		if err != nil {
			return nil, fmt.Errorf("failed to build callback path: %v", err)
		}
		googleCallbackURL, err := url.JoinPath("http://", opts.Hostname, googleCallbackPath)
		if err != nil {
			return nil, fmt.Errorf("failed to build callback URL: %v", err)
		}
		ret.googleCfg = &oauth2.Config{
			ClientID:     opts.GoogleClientID,
			ClientSecret: opts.GoogleClientSecret,
			RedirectURL:  googleCallbackURL,
			Scopes:       []string{"email"},
			Endpoint:     google.Endpoint,
		}
		opts.Mux.HandleFunc(googleCallbackPath, ret.googleOAuthCallback)
	}

	if opts.DiscordClientID != "" {
		discordCallbackPath, err := url.JoinPath(opts.CallbackPath, "/discord")
		if err != nil {
			return nil, fmt.Errorf("failed to build callback path: %v", err)
		}
		discordCallbackURL, err := url.JoinPath("http://", opts.Hostname, discordCallbackPath)
		if err != nil {
			return nil, fmt.Errorf("failed to build callback URL: %v", err)
		}
		ret.discordCfg = &oauth2.Config{
			ClientID:     opts.DiscordClientID,
			ClientSecret: opts.DiscordClientSecret,
			RedirectURL:  discordCallbackURL,
			Scopes:       []string{discord.ScopeIdentify},
			Endpoint:     discord.Endpoint,
		}
		opts.Mux.HandleFunc(discordCallbackPath, ret.discordOAuthCallback)
	}

	switch {
	case ret.googleCfg != nil:
	case ret.discordCfg != nil:
	default:
		return nil, fmt.Errorf("missing OAuth provider config")
	}

	return ret, nil
}

type Option func(*opts) error

// OptGoogleClientID sets the Google OAuth client ID.
func OptGoogleClientID(clientID string) Option {
	return func(o *opts) error {
		if clientID == "" {
			return fmt.Errorf("client ID cannot be empty")
		}
		o.GoogleClientID = clientID
		return nil
	}
}

// OptGoogleClientSecret sets the Google OAuth client secret.
func OptGoogleClientSecret(clientSecret string) Option {
	return func(o *opts) error {
		if clientSecret == "" {
			return fmt.Errorf("client secret cannot be empty")
		}
		o.GoogleClientSecret = clientSecret
		return nil
	}
}

// OptDiscordClientID sets the Discord OAuth client ID.
func OptDiscordClientID(clientID string) Option {
	return func(o *opts) error {
		if clientID == "" {
			return fmt.Errorf("client ID cannot be empty")
		}
		o.DiscordClientID = clientID
		return nil
	}
}

// OptDiscordClientSecret sets the Discord OAuth client secret.
func OptDiscordClientSecret(clientSecret string) Option {
	return func(o *opts) error {
		if clientSecret == "" {
			return fmt.Errorf("client secret cannot be empty")
		}
		o.DiscordClientSecret = clientSecret
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

// OptCallbackBasePath sets the path for OAuth callbacks.
// The full callback path is appended with OAuth provider's specific suffix.
func OptCallbackBasePath(callbackPath string) Option {
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
	GoogleClientID      string
	GoogleClientSecret  string
	DiscordClientID     string
	DiscordClientSecret string
	Hostname            string
	CallbackPath        string
	Mux                 *http.ServeMux
	JWTSecret           string
	JWTTTL              time.Duration
	JWTCookieName       string
}

func newOpts() *opts {
	return &opts{
		Mux:           http.DefaultServeMux,
		JWTSecret:     randomString(32),
		JWTTTL:        24 * time.Hour,
		JWTCookieName: "token",
	}
}
