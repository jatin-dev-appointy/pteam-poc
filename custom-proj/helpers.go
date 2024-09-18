package main

import (
	"github.com/gorilla/securecookie"
	"net/http"
	"time"
)

func encryptTempToCookie(w http.ResponseWriter, r *http.Request, name, value, path string) error {
	sec := securecookie.New(
		[]byte("development-credentials-hash----"),
		nil,
	)

	encVal, err := sec.Encode(name, value)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    encVal,
		Path:     path,
		HttpOnly: true,
		Expires:  time.Now().UTC().Add(1 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
		Domain:   "127.0.0.1",
	})

	return nil
}

func decryptTempFromCookie(w http.ResponseWriter, r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	var value string

	sec := securecookie.New(
		[]byte("development-credentials-hash----"),
		nil,
	)
	if err = sec.Decode(name, c.Value, &value); err != nil {
		return "", err
	}

	c.MaxAge = -1
	http.SetCookie(w, c)

	return value, nil
}

func SetAuthCookie(w http.ResponseWriter, r *http.Request, token *Token) error {

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc",
		Value:    token.AccessToken,
		HttpOnly: true,
		Expires:  token.Expiry,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sign-out",
		Value:    token.IDToken,
		HttpOnly: true,
		Expires:  token.Expiry,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func GetAuthCookie(r *http.Request) (string, error) {
	c, err := r.Cookie("oidc")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", nil
		}
		return "", err
	}

	return c.Value, nil
}

func AuthCookie(r *http.Request) (*Token, error) {
	c, err := r.Cookie("oidc")
	if err != nil {
		return nil, err
	}

	idc, err := r.Cookie("sign-out")
	if err != nil {
		idc = &http.Cookie{
			Value: "",
		}
	}

	return &Token{
		AccessToken: c.Value,
		IDToken:     idc.Value,
	}, nil
}

func RemoveAuthCookie(r *http.Request, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc",
		HttpOnly: true,
		MaxAge:   -1,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "sign-out",
		HttpOnly: true,
		MaxAge:   -1,
		Path:     "/",
	})
}
