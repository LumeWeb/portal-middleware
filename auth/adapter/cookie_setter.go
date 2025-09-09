package adapter

import (
	"errors"
	"net/http"
	"time"

	"go.lumeweb.com/portal-middleware/auth/jwt"
)

var (
	_ APIProvider = (*coreAPIProvider)(nil)
)

// CookieSetter is an interface for managing authentication cookies across domains.
// CookieSetter handles setting, clearing, and echoing JWT cookies for both main domains
// and API subdomains, ensuring consistent authentication state across all relevant domains.
type CookieSetter interface {
	// SetJWTCookie creates and sets a JWT token as a cookie.
	// Generates a new JWT token with the provided parameters and sets it as an HTTP cookie
	// on the response writer. The token is signed with the configured private key.
	//
	// Parameters:
	// - w: HTTP response writer to set the cookie on
	// - subject: Subject of the token (typically user ID)
	// - purpose: Purpose of the token (e.g., login, refresh)
	// - expiry: Duration until token expiration
	// - opts: Additional JWT options
	//
	// Returns:
	// - string: The generated JWT token string
	// - error: Any error encountered during token creation or cookie setting
	SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.Purpose,
		expiry time.Duration, opts ...jwt.Option) (string, error)

	// ClearJWTCookie removes the JWT authentication cookie.
	// Sets a cookie with the same name but empty value and MaxAge of -1 to delete
	// the authentication cookie from the client.
	//
	// Parameters:
	// - w: HTTP response writer to clear the cookie on
	ClearJWTCookie(w http.ResponseWriter)

	// EchoAuthCookie duplicates an existing authentication cookie.
	// Takes an existing authentication cookie from the request and sets it again
	// on the response, effectively "echoing" it. This is used to maintain
	// authentication state during certain operations.
	//
	// Parameters:
	// - w: HTTP response writer to set the cookie on
	// - r: HTTP request containing the cookie to echo
	// - opts: Additional JWT options for claim type specification
	EchoAuthCookie(w http.ResponseWriter, r *http.Request, opts ...jwt.Option)

	// SetCookie sets a generic cookie with the specified parameters.
	// This method allows setting cookies with custom names, values, domains, paths,
	// expiration times, and security settings.
	//
	// Parameters:
	// - w: The HTTP response writer to set the cookie on
	// - name: The name of the cookie
	// - value: The value to store in the cookie
	// - domain: The domain the cookie is associated with
	// - path: The path the cookie is valid for
	// - expiry: The expiration time of the cookie
	// - secure: Whether the cookie should only be sent over HTTPS
	// - httpOnly: Whether the cookie should be inaccessible to JavaScript
	// - sameSite: The SameSite attribute for the cookie
	SetCookie(w http.ResponseWriter, name, value, domain, path string, expiry time.Time, secure, httpOnly bool, sameSite http.SameSite)

	// Config returns the configuration provider used by this cookie setter.
	// This allows access to configuration values such as domain, secure settings, etc.
	Config() ConfigProvider
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

	// Use SetCookie internally
	s.SetCookie(w, s.config.GetAuthCookieName(), tokenString, s.config.GetDomain(), "/", time.Now().Add(expiry), s.config.Secure(), true, http.SameSiteStrictMode)

	return tokenString, nil
}

// ClearJWTCookie clears the JWT cookie
func (s *coreCookieSetter) ClearJWTCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     s.config.GetAuthCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   s.config.Secure(),
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
	// Add 1 minute leeway for clock skew
	if time.Now().Add(time.Minute).After(exp.Time) {
		return
	}

	domain := s.config.GetCtx().Config().Config().Core.Domain
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookie.Value,
		MaxAge:   int(time.Until(exp.Time).Seconds()),
		Secure:   s.config.Secure(),
		HttpOnly: true,
		Path:     "/",
		Domain:   domain,
		SameSite: http.SameSiteStrictMode,
	})
}

// SetCookie implements CookieSetter interface for setting a generic cookie.
func (s *coreCookieSetter) SetCookie(w http.ResponseWriter, name, value, domain, path string, expiry time.Time, secure, httpOnly bool, sameSite http.SameSite) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		Expires:  expiry,
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: sameSite,
	}
	http.SetCookie(w, cookie)
}

// Config returns the configuration provider
func (s *coreCookieSetter) Config() ConfigProvider {
	return s.config
}

// NewCookieSetter creates a new defaultCookieSetter
func NewCookieSetter(config ConfigProvider) CookieSetter {
	return &coreCookieSetter{
		config: config,
	}
}

// multiCookieSetter handles setting cookies across multiple APIs
type multiCookieSetter struct {
	config ConfigProvider
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

	var errs []error

	// Create token for main domain
	mainToken, err := jwt.CreateToken(
		m.config.GetPrivateKey(),
		m.config.GetDomain(),
		subject,
		purpose,
		expiry,
		opts...,
	)
	if err != nil {
		errs = append(errs, err)
	} else {
		// Set cookie for main domain
		m.setCookieForDomain(w, m.config.GetAuthCookieName(), mainToken, m.config.GetDomain(), "/", time.Now().Add(expiry), m.config.Secure(), true, http.SameSiteStrictMode)
	}

	// Set cookies for all APIs
	for _, api := range m.APIs.GetAPIs() {
		// Skip empty API; main domain already handled
		if api == "" {
			continue
		}
		fullDomain := api + "." + m.config.GetDomain()
		token, err := jwt.CreateToken(
			m.config.GetPrivateKey(),
			fullDomain,
			subject,
			purpose,
			expiry,
			opts...,
		)

		if err != nil {
			errs = append(errs, err)
			continue
		}

		// Set cookie for this API domain only
		m.setCookieForDomain(w, m.config.GetAuthCookieName(), token, fullDomain, "/", time.Now().Add(expiry), m.config.Secure(), true, http.SameSiteStrictMode)
	}

	// Return the main token if we have it, otherwise return error
	if mainToken != "" {
		if len(errs) > 0 {
			return mainToken, errors.Join(errs...)
		}
		return mainToken, nil
	}

	if len(errs) > 0 {
		return "", errors.Join(errs...)
	}

	// This shouldn't happen, but just in case
	return "", errors.New("no tokens were created successfully")
}

// ClearJWTCookie clears JWT cookies for all APIs
func (m *multiCookieSetter) ClearJWTCookie(w http.ResponseWriter) {
	// Clear cookie for main domain
	m.setCookieForDomain(w, m.config.GetAuthCookieName(), "", m.config.GetDomain(), "/", time.Time{}, m.config.Secure(), true, http.SameSiteStrictMode)

	// Clear cookies for all APIs
	for _, api := range m.APIs.GetAPIs() {
		// Skip empty API; main domain already cleared above
		if api == "" {
			continue
		}
		apiDomain := api + "." + m.config.GetDomain()
		// Clear cookie for this API domain only
		m.setCookieForDomain(w, m.config.GetAuthCookieName(), "", apiDomain, "/", time.Time{}, m.config.Secure(), true, http.SameSiteStrictMode)
	}
}

// EchoAuthCookie implements CookieSetter interface for multiCookieSetter
func (m *multiCookieSetter) EchoAuthCookie(w http.ResponseWriter, r *http.Request, opts ...jwt.Option) {
	cookieName := m.config.GetAuthCookieName()
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

	var errs []error

	// Echo main domain cookie with correct issuer
	mainDomain := m.config.GetDomain()
	mainToken, err := jwt.CreateToken(
		m.config.GetPrivateKey(),
		mainDomain,
		subject,
		purpose,
		time.Until(exp.Time),
		opts...,
	)
	if err != nil {
		errs = append(errs, err)
	} else {
		// Set cookie for main domain only
		m.setCookieForDomain(w, cookieName, mainToken, mainDomain, "/", time.Now().Add(time.Until(exp.Time)), m.config.Secure(), true, http.SameSiteStrictMode)
	}

	// Echo API subdomain cookies with correct issuer
	for _, api := range m.APIs.GetAPIs() {
		// Skip empty API; main domain echoed above
		if api == "" {
			continue
		}
		fullDomain := api + "." + m.config.GetDomain()
		apiToken, err := jwt.CreateToken(
			m.config.GetPrivateKey(),
			fullDomain, // Use the combined API domain as the issuer
			subject,
			purpose,
			time.Until(exp.Time),
			opts...,
		)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// Set cookie for this API domain only
		m.setCookieForDomain(w, cookieName, apiToken, fullDomain, "/", time.Now().Add(time.Until(exp.Time)), m.config.Secure(), true, http.SameSiteStrictMode)
	}

	if len(errs) > 0 {
		// Log errors but don't fail the request
		// In a real implementation, you might want to use a proper logger
	}
}

// setCookieForDomain sets a cookie for a specific domain only
func (m *multiCookieSetter) setCookieForDomain(w http.ResponseWriter, name, value, domain, path string, expiry time.Time, secure, httpOnly bool, sameSite http.SameSite) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		Expires:  expiry,
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: sameSite,
	}

	// Handle clearing cookies (empty value and zero expiry)
	if value == "" && expiry.IsZero() {
		cookie.MaxAge = -1
	}

	http.SetCookie(w, cookie)
}

// SetCookie implements CookieSetter for setting a generic cookie.
// It sets exactly one cookie using the provided domain parameter.
// If domain is empty, it falls back to the configured main domain.
func (m *multiCookieSetter) SetCookie(w http.ResponseWriter, name, value, domain, path string, expiry time.Time, secure, httpOnly bool, sameSite http.SameSite) {
	// Use the provided domain, fallback to main domain if empty
	if domain == "" {
		domain = m.config.GetDomain()
	}

	// Set exactly one cookie with the specified domain
	m.setCookieForDomain(w, name, value, domain, path, expiry, secure, httpOnly, sameSite)
}

// Config returns the configuration provider
func (m *multiCookieSetter) Config() ConfigProvider {
	return m.config
}

// NewMultiCookieSetter creates a new multiCookieSetter
func NewMultiCookieSetter(config ConfigProvider, apis APIProvider) CookieSetter {
	return &multiCookieSetter{
		config: config,
		APIs:   apis,
	}
}
