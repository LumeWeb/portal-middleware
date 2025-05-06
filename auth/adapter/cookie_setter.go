package adapter

import (
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"net/http"
	"time"
)

var (
	_ APIProvider = (*coreAPIProvider)(nil)
)

// CookieSetter is an interface for setting cookies with JWT tokens
// CookieSetter manages JWT cookies across multiple domains and APIs.
// Handles both setting and clearing authentication cookies.
type CookieSetter interface {
	SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.Purpose,
		expiry time.Duration, opts ...jwt.Option) (string, error)
	ClearJWTCookie(w http.ResponseWriter)
}

// SetJWTCookie sets a JWT token as a cookie
func (s *coreCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string,
	purpose jwt.Purpose, expiry time.Duration, opts ...jwt.Option) (string, error) {

	tokenString, err := jwt.CreateToken(
		s.config.GetPrivateKey(),
		s.config.GetDomain(),
		subject,
		purpose,
		expiry,
		opts...,
	)
	if err != nil {
		return "", err
	}

	// Set cookie with explicit domain
	cookie := &http.Cookie{
		Name:     s.config.GetAuthCookieName(),
		Value:    tokenString,
		Domain:   s.config.GetDomain(),
		Path:     "/",
		Expires:  time.Now().Add(expiry),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)

	return tokenString, nil
}

// ClearJWTCookie clears the JWT cookie
func (s *coreCookieSetter) ClearJWTCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     s.config.GetAuthCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, cookie)
}

// NewCookieSetter creates a new defaultCookieSetter
func NewCookieSetter(config ConfigProvider) CookieSetter {
	return &coreCookieSetter{
		config: config,
	}
}

// multiCookieSetter handles setting cookies across multiple APIs
type multiCookieSetter struct {
	Config ConfigProvider
	APIs   APIProvider
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ CookieSetter = (*coreCookieSetter)(nil)
	_ CookieSetter = (*multiCookieSetter)(nil)
)

// SetJWTCookie sets JWT cookies for all APIs
func (m *multiCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.Purpose,
	expiry time.Duration, opts ...jwt.Option) (string, error) {

	var lastToken string
	var lastErr error

	// Set cookie for main domain
	lastToken, lastErr = jwt.CreateAndSend(
		w,
		m.Config.GetPrivateKey(),
		m.Config.GetDomain(),
		m.Config.GetAuthCookieName(),
		subject,
		purpose,
		expiry,
		opts...,
	)

	// Set cookies for all APIs
	for _, api := range m.APIs.GetAPIs() {
		// Skip errors but keep them for return value
		token, err := jwt.CreateAndSend(
			w,
			m.Config.GetPrivateKey(),
			api,
			m.Config.GetAuthCookieName(),
			subject,
			purpose,
			expiry,
			opts...,
		)

		if err == nil && lastErr != nil {
			lastToken = token
			lastErr = nil
		}
	}

	return lastToken, lastErr
}

// ClearJWTCookie clears JWT cookies for all APIs
func (m *multiCookieSetter) ClearJWTCookie(w http.ResponseWriter) {
	// Clear cookie for main domain
	cookie := &http.Cookie{
		Name:     m.Config.GetAuthCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, cookie)

	// Clear cookies for all APIs
	for _, api := range m.APIs.GetAPIs() {
		// Use the api as domain to properly clear the cookie
		cookie := &http.Cookie{
			Name:     m.Config.GetAuthCookieName(),
			Value:    "",
			Path:     "/",
			Domain:   api,
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}

		http.SetCookie(w, cookie)
	}
}

// NewMultiCookieSetter creates a new multiCookieSetter
func NewMultiCookieSetter(config ConfigProvider, apis APIProvider) CookieSetter {
	return &multiCookieSetter{
		Config: config,
		APIs:   apis,
	}
}
