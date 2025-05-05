package auth

import (
	"crypto/ed25519"
	"errors"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"net/http"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// createJWTToken is an internal function that creates a new JWT token
// This is internal to avoid name conflicts with existing functions
func createJWTToken(privateKey ed25519.PrivateKey, domain string, subject string, purpose jwt.JWTPurpose,
	expireAt *time.Time) (string, error) {

	claims := gjwt.RegisteredClaims{
		Issuer:  domain,
		Subject: subject,
	}

	if purpose != jwt.JWTPurposeNone {
		claims.Audience = gjwt.ClaimStrings{string(purpose)}
	}

	if expireAt != nil {
		claims.ExpiresAt = gjwt.NewNumericDate(*expireAt)
	}

	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	return token.SignedString(privateKey)
}

// SendJWT creates and sets a JWT token in the HTTP response
func SendJWT(w http.ResponseWriter, privateKey ed25519.PrivateKey, domain string,
	cookieName string, subject string, purpose jwt.JWTPurpose, expiry time.Duration, 
	opts ...ClaimModifier) (string, error) {

	token, err := CreateJWTToken(privateKey, domain, subject, purpose, expiry, opts...)
	if err != nil {
		return "", err
	}

	// Set cookie if cookie name is provided
	if cookieName != "" {
		cookie := &http.Cookie{
			Name:     cookieName,
			Value:    token,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}

		if expiry > 0 {
			cookie.Expires = time.Now().Add(expiry)
		}

		http.SetCookie(w, cookie)
	}

	return token, nil
}

// APIProvider defines an interface for getting a list of APIs
type APIProvider interface {
	GetAPIs() []string
}

// CookieSetter is an interface for setting cookies with JWT tokens
// CookieSetter manages JWT cookies across multiple domains and APIs.
// Handles both setting and clearing authentication cookies.
type CookieSetter interface {
	SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.JWTPurpose, 
		expiry time.Duration, opts ...ClaimModifier) (string, error)
	ClearJWTCookie(w http.ResponseWriter)
}

// defaultCookieSetter implements CookieSetter with standard JWT cookie handling
type defaultCookieSetter struct {
	PrivateKey ed25519.PrivateKey
	Domain     string
	CookieName string
}

// SetJWTCookie sets a JWT token as a cookie
func (s *defaultCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string, 
	purpose jwt.JWTPurpose, expiry time.Duration, opts ...ClaimModifier) (string, error) {

	return SendJWT(w, s.PrivateKey, s.Domain, s.CookieName, subject, purpose, expiry, opts...)
}

// ClearJWTCookie clears the JWT cookie
func (s *defaultCookieSetter) ClearJWTCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     s.CookieName,
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
func NewCookieSetter(privateKey ed25519.PrivateKey, domain string, cookieName string) CookieSetter {
	return &defaultCookieSetter{
		PrivateKey: privateKey,
		Domain:     domain,
		CookieName: cookieName,
	}
}

// multiCookieSetter handles setting cookies across multiple APIs
type multiCookieSetter struct {
	Config ConfigProvider
	APIs   APIProvider
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ CookieSetter = (*defaultCookieSetter)(nil)
	_ CookieSetter = (*multiCookieSetter)(nil)
)

// SetJWTCookie sets JWT cookies for all APIs
func (m *multiCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.JWTPurpose,
	expiry time.Duration, opts ...ClaimModifier) (string, error) {

	var lastToken string
	var lastErr error

	// Set cookie for main domain
	lastToken, lastErr = SendJWT(
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
		token, err := SendJWT(
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
// CreateJWTToken generates a new JWT token with specified claims.
// Uses Ed25519 for signing, sets standard claims (iss, sub, aud, exp, iat, nbf).
// Returns the signed token string or error if signing fails.
func CreateJWTToken(privateKey ed25519.PrivateKey, domain string, subject string, purpose jwt.JWTPurpose,
	expiration time.Duration, opts ...ClaimModifier) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key cannot be nil")
	}

	now := time.Now()
	expirationTime := now.Add(expiration)

	var claims gjwt.Claims
	if factory, exists := customClaimTypes[string(purpose)]; exists {
		claims = factory()
		if rc, ok := claims.(interface {
			SetSubject(string)
			SetExpiresAt(*gjwt.NumericDate)
			SetIssuedAt(*gjwt.NumericDate)
			SetNotBefore(*gjwt.NumericDate)
			SetIssuer(string)
			SetAudience([]string)
		}); ok {
			rc.SetSubject(subject)
			rc.SetExpiresAt(gjwt.NewNumericDate(expirationTime))
			rc.SetIssuedAt(gjwt.NewNumericDate(now))
			rc.SetNotBefore(gjwt.NewNumericDate(now))
			rc.SetIssuer(domain)
			if purpose != jwt.JWTPurposeNone {
				rc.SetAudience([]string{string(purpose)})
			}
		}
	} else {
		claims = &gjwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: gjwt.NewNumericDate(expirationTime),
			IssuedAt:  gjwt.NewNumericDate(now),
			NotBefore: gjwt.NewNumericDate(now),
			Issuer:    domain,
		}
		// Type assert to set audience for RegisteredClaims
		if rc, ok := claims.(*gjwt.RegisteredClaims); ok && purpose != jwt.JWTPurposeNone {
			rc.Audience = []string{string(purpose)}
		}
	}

	for _, opt := range opts {
		opt(claims)
	}

	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	return token.SignedString(privateKey)
}

// RefreshJWTToken refreshes an existing JWT token
// RefreshJWTToken creates a new token with extended expiration while preserving claims.
// Verifies the original token is valid before creating refreshed version.
// Returns error if original token is invalid or signing fails.
func RefreshJWTToken(tokenString string, privateKey ed25519.PrivateKey, domain string,
	expiration time.Duration) (string, error) {

	claims, err := JWTVerifyToken(tokenString, domain, privateKey, nil)
	if err != nil {
		return "", err
	}

	// Create new JWT with same claims but new expiration
	now := time.Now()
	expirationTime := now.Add(expiration)

	claims.ExpiresAt = gjwt.NewNumericDate(expirationTime)
	claims.IssuedAt = gjwt.NewNumericDate(now)
	claims.NotBefore = gjwt.NewNumericDate(now)

	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	return token.SignedString(privateKey)
}
