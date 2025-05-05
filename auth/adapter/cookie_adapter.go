package adapter

import (
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"net/http"
	"time"

	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal/core"
)

// coreAPIProvider implements auth.APIProvider
type coreAPIProvider struct {
	apis []string
}

// coreCookieSetter adapts a ConfigProvider to implement auth.CookieSetter
type coreCookieSetter struct {
	config auth.ConfigProvider
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ auth.APIProvider  = (*coreAPIProvider)(nil)
	_ auth.CookieSetter = (*coreCookieSetter)(nil)
)

// GetAPIs returns the stored API domains
func (p *coreAPIProvider) GetAPIs() []string {
	return p.apis
}

// NewAPIProvider creates a new APIProvider using core.GetAPIs
func NewAPIProvider() auth.APIProvider {
	apiList := core.GetAPIList()
	domains := make([]string, 0, len(apiList))

	for _, api := range apiList {
		domains = append(domains, api.Subdomain())
	}

	return &coreAPIProvider{apis: domains}
}

// SetJWTCookie sets a JWT token as a cookie using ConfigProvider
func (s *coreCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.JWTPurpose,
	expiry time.Duration, opts ...auth.JWTOption) (string, error) {

	tokenString, err := auth.CreateJWTToken(
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

// MultiCoreSetterFromCore creates a chained cookie setter that handles both main domain and API subdomains
func MultiCoreSetterFromCore(ctx core.Context) auth.CookieSetter {
	mainSetter := NewCookieSetter(NewFromCore(ctx))

	// Create API setters with explicit domain handling
	var apiSetters []auth.CookieSetter
	for _, domain := range NewAPIProvider().GetAPIs() {
		apiSetters = append(apiSetters, newDomainCookieSetter(mainSetter, domain))
	}

	return NewChainedCookieSetter(append([]auth.CookieSetter{mainSetter}, apiSetters...)...)
}

// domainCookieSetter sets cookies for a specific domain
type domainCookieSetter struct {
	base   auth.CookieSetter
	domain string
}

// newDomainCookieSetter creates a new domainCookieSetter instance
func newDomainCookieSetter(base auth.CookieSetter, domain string) *domainCookieSetter {
	return &domainCookieSetter{
		base:   base,
		domain: domain,
	}
}

func (d *domainCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.JWTPurpose,
	expiry time.Duration, opts ...auth.JWTOption) (string, error) {
	// Get config from base but override domain
	config := d.base.(*coreCookieSetter).config

	tokenString, err := auth.CreateJWTToken(
		config.GetPrivateKey(),
		d.domain, // Use the API domain as issuer
		subject,
		purpose,
		expiry,
		opts...,
	)
	if err != nil {
		return "", err
	}

	// Create domain-specific cookie
	cookie := &http.Cookie{
		Name:     config.GetAuthCookieName(),
		Value:    tokenString,
		Domain:   d.domain,
		Path:     "/",
		Expires:  time.Now().Add(expiry),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)

	return tokenString, nil
}

func (d *domainCookieSetter) ClearJWTCookie(w http.ResponseWriter) {
	config := d.base.(*coreCookieSetter).config

	// Clear domain-specific cookie
	cookie := &http.Cookie{
		Name:     config.GetAuthCookieName(),
		Value:    "",
		Domain:   d.domain,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

// NewChainedCookieSetter creates a CookieSetter that chains multiple setters
func NewChainedCookieSetter(setters ...auth.CookieSetter) auth.CookieSetter {
	return &chainedCookieSetter{setters: setters}
}

type chainedCookieSetter struct {
	setters []auth.CookieSetter
}

func (c *chainedCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.JWTPurpose, expiry time.Duration, opts ...auth.JWTOption) (string, error) {
	var token string
	var err error
	for _, setter := range c.setters {
		token, err = setter.SetJWTCookie(w, subject, purpose, expiry, opts...)
		if err != nil {
			return "", err
		}
	}
	return token, nil
}

func (c *chainedCookieSetter) ClearJWTCookie(w http.ResponseWriter) {
	for _, setter := range c.setters {
		setter.ClearJWTCookie(w)
	}
}

// NewCookieSetter creates a new coreCookieSetter from a ConfigProvider
func NewCookieSetter(config auth.ConfigProvider) auth.CookieSetter {
	return &coreCookieSetter{
		config: config,
	}
}
