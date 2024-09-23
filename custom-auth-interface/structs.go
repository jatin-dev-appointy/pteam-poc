package main

import (
	"net/http"
	"net/url"
	"time"
)

type WelcomePageData struct {
	Title   string
	AuthURL string
}

type DashboardPageData struct {
	IsLoggedIn bool
}

type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// IDToken is the OpenID addition to the excellent OAuth 2.0
	IDToken string `json:"id_token,omitempty"`
}

// Custom cookie jar to pass cookies to the Kratos client
type CookieJar struct {
	CookiesList []*http.Cookie
}

func (jar *CookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {}

func (jar *CookieJar) Cookies(u *url.URL) []*http.Cookie {
	return jar.CookiesList
}
