package authn

import (
	"net/http"
)

func (a *Authn) fakeOAuthInject(w http.ResponseWriter, r *http.Request) {
	t := &Token{
		Issuer:      "fakeoauth",
		ID:          "fakeuser",
		DisplayName: "Fake User",
	}

	if a.fakeCfg.IssuerFunc != nil {
		t.Issuer = a.fakeCfg.IssuerFunc(r.Context())
	}
	if a.fakeCfg.IDFunc != nil {
		t.ID = a.fakeCfg.IDFunc(r.Context())
	}
	if a.fakeCfg.DisplayNameFunc != nil {
		t.DisplayName = a.fakeCfg.DisplayNameFunc(r.Context())
	}

	if err := a.jwtSetCookie(w, a.jwtCookieName, t); err != nil {
		http.Error(w, "failed to build JWT", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, r.URL.Path, http.StatusFound)
}
