package authn

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (a *Authn) jwtVerify(token string) (string, bool) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})
	if err != nil {
		return "", false
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		if !t.Valid {
			return "", false
		}
		email, ok := claims["email"].(string)
		if !ok {
			return "", false
		}
		return email, true
	}
	return "", false

}

func (a *Authn) jwtBuild(email string) (string, time.Time, error) {
	now := time.Now()
	deadline := now.Add(a.jwtTTL)
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"iat":   now.Unix(),
		"exp":   deadline.Unix(),
	})

	token, err := t.SignedString(a.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, deadline, nil
}

func (a *Authn) jwtSetCookie(w http.ResponseWriter, name, email string) error {
	jwt, expires, err := a.jwtBuild(email)
	if err != nil {
		return errors.New("failed to build JWT")
	}

	http.SetCookie(w, &http.Cookie{Name: name, Value: jwt, Path: "/", Expires: expires})
	return nil
}
