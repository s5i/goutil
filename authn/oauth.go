package authn

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"time"
)

func (a *Authn) oAuthDialog(w http.ResponseWriter, r *http.Request) {
	if a.fakeCfg != nil {
		a.fakeOAuthInject(w, r)
		return
	}

	state := randomString(32)

	var url string
	switch {
	case a.discordCfg != nil:
		url = a.discordCfg.AuthCodeURL(state)
	case a.googleCfg != nil:
		url = a.googleCfg.AuthCodeURL(state)
	default:
		http.Error(w, "no OAuth provider configured", http.StatusInternalServerError)
		return
	}

	a.oAuthInFlightMu.Lock()
	a.oAuthInFlight[state] = &oauthState{previousPath: r.URL.Path}
	a.oAuthInFlightMu.Unlock()

	// TODO: move this logic to a centralized background loop
	go func() {
		time.Sleep(15 * time.Minute)
		a.oAuthInFlightMu.Lock()
		delete(a.oAuthInFlight, state)
		a.oAuthInFlightMu.Unlock()
	}()

	http.Redirect(w, r, url, http.StatusFound)
}

type oauthState struct {
	previousPath string
}

func randomString(len int) string {
	b := make([]byte, len)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[:len]
}
