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
	EchoAuthCookie(w http.ResponseWriter, r *http.Request, opts ...jwt.Option)
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

// EchoAuthCookie implements CookieSetter interface for coreCookieSetter
func (s *coreCookieSetter) EchoAuthCookie(w http.ResponseWriter, r *http.Request, opts ...jwt.Option) {
	cookieName := s.config.GetAuthCookieName()
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return // No cookie to echo
	}

	// Use provided options for claim type, or default to RegisteredClaims
	claimsType := jwt.GetClaimsType(opts)
	claims, err := jwt.DecodeToken(cookie.Value, claimsType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	domain := s.config.GetCtx().Config().Config().Core.Domain
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookie.Value,
		MaxAge:   int(time.Until(exp.Time).Seconds()),
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Domain:   domain,
	})
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

// EchoAuthCookie implements CookieSetter interface for multiCookieSetter
func (m *multiCookieSetter) EchoAuthCookie(w http.ResponseWriter, r *http.Request, opts ...jwt.Option) {
	cookieName := m.Config.GetAuthCookieName()
	mainCookie, err := r.Cookie(cookieName)
	if err != nil {
		return // No main cookie to echo
	}

	// Use provided options for claim type, or default to RegisteredClaims
	claimsType := jwt.GetClaimsType(opts)
	claims, err := jwt.DecodeToken(mainCookie.Value, claimsType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract subject and purpose from the original token
	subject, err := claims.GetSubject()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audience, err := claims.GetAudience()
	if err != nil || len(audience) == 0 {
		http.Error(w, "missing audience", http.StatusInternalServerError)
		return
	}
	purpose := jwt.Purpose(audience[0])

	// Echo main domain cookie with correct issuer
	mainDomain := m.Config.GetCtx().Config().Config().Core.Domain
	mainToken, err := jwt.CreateToken(
		m.Config.GetPrivateKey(),
		mainDomain,
		subject,
		purpose,
		time.Until(exp.Time),
		opts...,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    mainToken,
		MaxAge:   int(time.Until(exp.Time).Seconds()),
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Domain:   mainDomain,
	})

	// Echo API subdomain cookies with correct issuer
	for _, api := range m.APIs.GetAPIs() {
		apiToken, err := jwt.CreateToken(
			m.Config.GetPrivateKey(),
			api, // ✅ Use the API domain as the issuer
			subject,
			purpose,
			time.Until(exp.Time),
			opts...,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    apiToken,
			MaxAge:   int(time.Until(exp.Time).Seconds()),
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			Domain:   api,
		})
	}
}

// NewMultiCookieSetter creates a new multiCookieSetter
func NewMultiCookieSetter(config ConfigProvider, apis APIProvider) CookieSetter {
	return &multiCookieSetter{
		Config: config,
		APIs:   apis,
	}
}
