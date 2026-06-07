package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequireToken_acceptsBearerHeader(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())
	jwtStr, _, err := a.jwtBuild(&Token{Issuer: "google", ID: "user@example.com", DisplayName: "User"})
	if err != nil {
		t.Fatalf("jwtBuild: %v", err)
	}

	var got *Token
	handler := a.RequireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		got, ok = a.Token(r)
		if !ok {
			t.Fatal("Token returned false inside middleware")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got == nil || got.Issuer != "google" || got.ID != "user@example.com" {
		t.Fatalf("got token %+v", got)
	}
}

func TestRequireToken_acceptsCookie(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())
	cookie, err := a.SyntheticCookie(&Token{Issuer: "discord", ID: "123"}, time.Hour)
	if err != nil {
		t.Fatalf("SyntheticCookie: %v", err)
	}

	var got *Token
	handler := a.RequireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = a.Token(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got == nil || got.Issuer != "discord" || got.ID != "123" {
		t.Fatalf("got token %+v", got)
	}
}

func TestRequireToken_prefersBearerOverCookie(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())

	bearerJWT, _, err := a.jwtBuild(&Token{Issuer: "bearer", ID: "from-header"})
	if err != nil {
		t.Fatalf("jwtBuild bearer: %v", err)
	}
	cookieJWT, _, err := a.jwtBuild(&Token{Issuer: "cookie", ID: "from-cookie"})
	if err != nil {
		t.Fatalf("jwtBuild cookie: %v", err)
	}

	var got *Token
	handler := a.RequireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = a.Token(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+bearerJWT)
	req.AddCookie(&http.Cookie{Name: a.jwtCookieName, Value: cookieJWT})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if got.Issuer != "bearer" || got.ID != "from-header" {
		t.Fatalf("got %+v, want bearer/from-header", got)
	}
}

func TestRequireToken_unauthenticatedTriggersFakeOAuth(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())
	handler := a.RequireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not run")
	}))

	rec, _ := recordResponse(handler)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != a.jwtCookieName {
		t.Fatalf("expected auth cookie, got %+v", cookies)
	}

	got, ok := a.jwtVerify(cookies[0].Value)
	if !ok {
		t.Fatal("fake OAuth cookie is not a valid JWT")
	}
	if got.Issuer != "fakeoauth" || got.ID != "fakeuser" {
		t.Fatalf("got %+v", got)
	}
}

func TestToken_requiresMiddlewareKey(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(issuerHeader, "google")
	req.Header.Set(idHeader, "user@example.com")

	if _, ok := a.Token(req); ok {
		t.Fatal("Token should fail without middleware key")
	}

	req.Header.Set(keyHeader, a.middlewareKey)
	got, ok := a.Token(req)
	if !ok || got.ID != "user@example.com" {
		t.Fatalf("got %+v, ok=%v", got, ok)
	}
}

func TestUnsafeToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(issuerHeader, "fakeoauth")
	req.Header.Set(idHeader, "fakeuser")
	req.Header.Set(displayNameHeader, "Fake User")
	req.Header.Set(isFakeHeader, "1")

	got, ok := UnsafeToken(req)
	if !ok {
		t.Fatal("UnsafeToken returned false")
	}
	if got.DisplayName != "Fake User" || !got.IsFake {
		t.Fatalf("got %+v", got)
	}

	req.Header.Del(idHeader)
	if _, ok := UnsafeToken(req); ok {
		t.Fatal("expected false when id is missing")
	}
}

func TestSyntheticCookie(t *testing.T) {
	a := newFakeAuthn(t, newTestMux())
	ttl := 30 * time.Minute

	cookie, err := a.SyntheticCookie(&Token{
		Issuer:      "google",
		ID:          "user@example.com",
		DisplayName: "User",
	}, ttl)
	if err != nil {
		t.Fatalf("SyntheticCookie: %v", err)
	}

	if cookie.Name != a.jwtCookieName || cookie.Path != "/" {
		t.Fatalf("unexpected cookie: %+v", cookie)
	}
	if cookie.Expires.Before(time.Now().Add(ttl - time.Minute)) {
		t.Fatalf("expires too soon: %v", cookie.Expires)
	}

	got, ok := a.jwtVerify(cookie.Value)
	if !ok || got.ID != "user@example.com" {
		t.Fatalf("jwtVerify failed: %+v ok=%v", got, ok)
	}
}
