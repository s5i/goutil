package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFakeOAuthInject_defaults(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())

	req := httptest.NewRequest(http.MethodGet, "/app/dashboard", nil)
	rec := httptest.NewRecorder()
	a.fakeOAuthInject(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/app/dashboard" {
		t.Fatalf("Location = %q", loc)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}

	got, ok := a.jwtVerify(cookies[0].Value)
	if !ok {
		t.Fatal("cookie JWT invalid")
	}
	if got.Issuer != "fakeoauth" || got.ID != "fakeuser" || got.DisplayName != "Fake User" {
		t.Fatalf("got %+v", got)
	}
}

func TestFakeOAuthInject_customFuncs(t *testing.T) {
	mux := newTestMux()
	a := newFakeAuthn(t, mux, OptFakeOAuth(&FakeOAuthConfig{
		IssuerFunc: func(ctx context.Context) string {
			return "custom-issuer"
		},
		IDFunc: func(ctx context.Context) string {
			return "custom-id"
		},
		DisplayNameFunc: func(ctx context.Context) string {
			return "Custom Name"
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	rec := httptest.NewRecorder()
	a.fakeOAuthInject(rec, req)

	got, ok := a.jwtVerify(rec.Result().Cookies()[0].Value)
	if !ok {
		t.Fatal("cookie JWT invalid")
	}
	if got.Issuer != "custom-issuer" || got.ID != "custom-id" || got.DisplayName != "Custom Name" {
		t.Fatalf("got %+v", got)
	}
}

func TestOAuthDialog_usesFakeOAuthWhenConfigured(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	rec := httptest.NewRecorder()
	a.oAuthDialog(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want fake OAuth redirect", rec.Code)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("expected fake OAuth to set cookie")
	}
}
