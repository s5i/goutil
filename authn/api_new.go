package authn

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ravener/discord-oauth2"
	"go.uber.org/multierr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// New instantiates an Authn object.
func New(options ...Option) (*Authn, error) {
	o := newOpts()
	for _, opt := range options {
		opt(o)
	}
	if err := o.verify(); err != nil {
		return nil, err
	}

	a := &Authn{
		oAuthInFlight: map[string]*oauthState{},
		jwtSecret:     []byte(o.JWTSecret),
		jwtTTL:        o.JWTTTL,
		jwtCookieName: o.JWTCookieName,
		middlewareKey: randomString(32),
	}

	if err := o.setupHandlers(a); err != nil {
		return nil, err
	}

	if err := a.verify(); err != nil {
		return nil, err
	}

	return a, nil
}

// GoogleOAuthConfig contains Google OAuth configuration.
// https://console.cloud.google.com/auth/clients
type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
}

// DiscordOAuthConfig contains Discord OAuth configuration.
// https://discord.com/developers/applications/.../oauth2
type DiscordOAuthConfig struct {
	ClientID     string
	ClientSecret string
}

// FakeOAuthConfig configures fake OAuth.
// Useful for local development and testing.
type FakeOAuthConfig struct {
	// Configures the returned Token.
	IssuerFunc      func(ctx context.Context) string // default: returns "fakeoauth"
	IDFunc          func(ctx context.Context) string // default: returns "fakeuser"
	DisplayNameFunc func(ctx context.Context) string // default: returns "Fake User"
}

// Option is a configuration option for New.
type Option func(*opts)

// OptGoogleOAuth configures Google OAuth.
func OptGoogleOAuth(cfg *GoogleOAuthConfig) Option {
	return func(o *opts) {
		o.GoogleCfg = cfg
	}
}

// OptDiscordOAuth configures Discord OAuth.
func OptDiscordOAuth(cfg *DiscordOAuthConfig) Option {
	return func(o *opts) {
		o.DiscordCfg = cfg
	}
}

// OptFakeOAuth configures fake OAuth for local development and testing.
func OptFakeOAuth(cfg *FakeOAuthConfig) Option {
	return func(o *opts) {
		o.FakeCfg = cfg
	}
}

// OptHostname sets the hostname used for OAuth callbacks.
func OptHostname(hostname string) Option {
	return func(o *opts) {
		o.Hostname = hostname
	}
}

// OptCallbackBasePath sets the path for OAuth callbacks.
// The full callback path is appended with OAuth provider's specific suffix.
func OptCallbackBasePath(callbackPath string) Option {
	return func(o *opts) {
		o.CallbackPath = callbackPath
	}
}

// OptMux sets the HTTP ServeMux for handling OAuth callbacks.
//
// If omitted, defaults to http.DefaultServeMux.
func OptMux(mux *http.ServeMux) Option {
	return func(o *opts) {
		o.Mux = mux
	}
}

// OptJWTSecret sets the JWT secret for signing tokens.
//
// If omitted, defaults to a random string.
// This is OK for long-running single-instance deployments.
// For other cases, you should provide a consistent secret to ensure JWTs can be verified across instances / restarts.
func OptJWTSecret(jwtSecret string) Option {
	return func(o *opts) {
		o.JWTSecret = jwtSecret
	}
}

// OptJWTTTL sets the JWT cookie's TTL.
//
// If omitted, defaults to 24h.
func OptJWTTTL(jwtTTL time.Duration) Option {
	return func(o *opts) {
		o.JWTTTL = jwtTTL
	}
}

// OptJWTCookieName sets the JWT cookie's name.
//
// If omitted, defaults to "token".
func OptJWTCookieName(jwtCookieName string) Option {
	return func(o *opts) {
		o.JWTCookieName = jwtCookieName
	}
}

// OptGoogleClientID sets the Google OAuth client ID.
// DEPRECATED: use OptGoogleOAuth instead.
func OptGoogleClientID(clientID string) Option {
	return func(o *opts) {
		if o.GoogleCfg == nil {
			o.GoogleCfg = &GoogleOAuthConfig{}
		}
		o.GoogleCfg.ClientID = clientID
	}
}

// OptGoogleClientSecret sets the Google OAuth client secret.
// DEPRECATED: use OptGoogleOAuth instead.
func OptGoogleClientSecret(clientSecret string) Option {
	return func(o *opts) {
		if o.GoogleCfg == nil {
			o.GoogleCfg = &GoogleOAuthConfig{}
		}
		o.GoogleCfg.ClientSecret = clientSecret
	}
}

// OptDiscordClientID sets the Discord OAuth client ID.
// DEPRECATED: use OptDiscordOAuth instead.
func OptDiscordClientID(clientID string) Option {
	return func(o *opts) {
		if o.DiscordCfg == nil {
			o.DiscordCfg = &DiscordOAuthConfig{}
		}
		o.DiscordCfg.ClientID = clientID
	}
}

// OptDiscordClientSecret sets the Discord OAuth client secret.
// DEPRECATED: use OptDiscordOAuth instead.
func OptDiscordClientSecret(clientSecret string) Option {
	return func(o *opts) {
		if o.DiscordCfg == nil {
			o.DiscordCfg = &DiscordOAuthConfig{}
		}
		o.DiscordCfg.ClientSecret = clientSecret
	}
}

type opts struct {
	GoogleCfg  *GoogleOAuthConfig
	DiscordCfg *DiscordOAuthConfig
	FakeCfg    *FakeOAuthConfig

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

func (o *opts) verify() error {
	var errs error

	if o.Hostname == "" {
		errs = multierr.Append(errs, fmt.Errorf("hostname cannot be empty"))
	}
	if o.JWTTTL < 0 {
		errs = multierr.Append(errs, fmt.Errorf("JWT TTL must be greater than zero"))
	}
	if o.JWTCookieName == "" {
		errs = multierr.Append(errs, fmt.Errorf("JWT cookie name cannot be empty"))
	}
	if o.JWTSecret == "" {
		errs = multierr.Append(errs, fmt.Errorf("JWT secret cannot be empty"))
	}

	if o.GoogleCfg != nil {
		if o.GoogleCfg.ClientID == "" {
			errs = multierr.Append(errs, fmt.Errorf("Google OAuth client ID cannot be empty"))
		}
		if o.GoogleCfg.ClientSecret == "" {
			errs = multierr.Append(errs, fmt.Errorf("Google OAuth client secret cannot be empty"))
		}
	}

	if o.DiscordCfg != nil {
		if o.DiscordCfg.ClientID == "" {
			errs = multierr.Append(errs, fmt.Errorf("Discord OAuth client ID cannot be empty"))
		}
		if o.DiscordCfg.ClientSecret == "" {
			errs = multierr.Append(errs, fmt.Errorf("Discord OAuth client secret cannot be empty"))
		}
	}

	if errs != nil {
		return errs
	}

	return nil
}

func (o *opts) setupHandlers(a *Authn) error {
	var errs error
	if err := o.setupGoogleHandler(a); err != nil {
		errs = multierr.Append(errs, err)
	}
	if err := o.setupDiscordHandler(a); err != nil {
		errs = multierr.Append(errs, err)
	}
	a.fakeCfg = o.FakeCfg

	return errs
}

func (o *opts) setupGoogleHandler(a *Authn) error {
	if o.GoogleCfg == nil {
		return nil
	}

	cbPath, err := url.JoinPath(o.CallbackPath, "/google")
	if err != nil {
		return fmt.Errorf("failed to build callback path: %v", err)
	}

	cbURL, err := url.JoinPath("https://", o.Hostname, cbPath)
	if err != nil {
		return fmt.Errorf("failed to build callback URL: %v", err)
	}

	a.googleCfg = &oauth2.Config{
		ClientID:     o.GoogleCfg.ClientID,
		ClientSecret: o.GoogleCfg.ClientSecret,
		RedirectURL:  cbURL,
		Scopes:       []string{"email"},
		Endpoint:     google.Endpoint,
	}
	o.Mux.HandleFunc(cbPath, a.googleOAuthCallback)

	return nil
}

func (o *opts) setupDiscordHandler(a *Authn) error {
	if o.DiscordCfg == nil {
		return nil
	}

	cbPath, err := url.JoinPath(o.CallbackPath, "/discord")
	if err != nil {
		return fmt.Errorf("failed to build callback path: %v", err)
	}

	cbURL, err := url.JoinPath("https://", o.Hostname, cbPath)
	if err != nil {
		return fmt.Errorf("failed to build callback URL: %v", err)
	}

	a.discordCfg = &oauth2.Config{
		ClientID:     o.DiscordCfg.ClientID,
		ClientSecret: o.DiscordCfg.ClientSecret,
		RedirectURL:  cbURL,
		Scopes:       []string{discord.ScopeIdentify},
		Endpoint:     discord.Endpoint,
	}
	o.Mux.HandleFunc(cbPath, a.discordOAuthCallback)

	return nil
}

func (a *Authn) verify() error {
	realCfg := false
	realCfg = realCfg || a.googleCfg != nil
	realCfg = realCfg || a.discordCfg != nil
	fakeCfg := a.fakeCfg != nil

	if realCfg == fakeCfg {
		return fmt.Errorf("either real OAuth provider(s) or fake OAuth must be configured, but not both")
	}
	return nil
}
