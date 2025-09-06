package adapter

import (
	"net/http"
	"time"

	"go.lumeweb.com/portal-middleware/auth/jwt"

	"go.lumeweb.com/portal/core"
)

// coreAPIProvider implements auth.APIProvider
type coreAPIProvider struct {
	apis []string
}

// coreCookieSetter adapts a ConfigProvider to implement auth.CookieSetter
type coreCookieSetter struct {
	config ConfigProvider
}

// APIProvider defines an interface for getting a list of APIs
type APIProvider interface {
	GetAPIs() []string
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ APIProvider = (*coreAPIProvider)(nil)
)

// GetAPIs returns the stored API domains
func (p *coreAPIProvider) GetAPIs() []string {
	return p.apis
}

// NewAPIProvider creates a new APIProvider using core.GetAPIs
func NewAPIProvider() APIProvider {
	apiList := core.GetAPIList()
	domains := make([]string, 0, len(apiList))

	for _, api := range apiList {
		domains = append(domains, api.Subdomain())
	}

	return &coreAPIProvider{apis: domains}
}

// MultiCoreSetterFromCore creates a chained cookie setter that handles both main domain and API subdomains
func MultiCoreSetterFromCore(ctx core.Context) CookieSetter {
	mainSetter := NewCookieSetter(NewFromCore(ctx))

	// Create API setters with explicit domain handling
	var apiSetters []CookieSetter
	for _, domain := range NewAPIProvider().GetAPIs() {
		apiSetters = append(apiSetters, newDomainCookieSetter(mainSetter, domain))
	}

	return NewChainedCookieSetter(append([]CookieSetter{mainSetter}, apiSetters...)...)
}

// domainCookieSetter sets cookies for a specific domain
type domainCookieSetter struct {
	base   CookieSetter
	domain string
}

// newDomainCookieSetter creates a new domainCookieSetter instance
func newDomainCookieSetter(base CookieSetter, domain string) *domainCookieSetter {
	return &domainCookieSetter{
		base:   base,
		domain: domain,
	}
}

func (d *domainCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.Purpose,
	expiry time.Duration, opts ...jwt.Option) (string, error) {
	// Get config from base but override domain
	config := d.base.Config()

	tokenString, err := jwt.CreateToken(
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

	// Use SetCookie internally
	d.SetCookie(w, config.GetAuthCookieName(), tokenString, d.domain, "/", time.Now().Add(expiry), config.Secure(), true, http.SameSiteStrictMode)

	return tokenString, nil
}

func (d *domainCookieSetter) ClearJWTCookie(w http.ResponseWriter) {
	config := d.base.Config()

	// Clear domain-specific cookie
	cookie := &http.Cookie{
		Name:     config.GetAuthCookieName(),
		Value:    "",
		Domain:   d.domain,
		Path:     "/",
		MaxAge:   -1,
		Secure:   config.Secure(),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

func (d *domainCookieSetter) EchoAuthCookie(w http.ResponseWriter, r *http.Request, opts ...jwt.Option) {
	cookieName := d.base.Config().GetAuthCookieName()

	// Get the main cookie from the request
	mainCookie, err := r.Cookie(cookieName)
	if err != nil {
		return // No cookie to echo
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

	// Set cookie for this domain using the main cookie's value
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    mainCookie.Value,
		Expires:  exp.Time,
		MaxAge:   int(time.Until(exp.Time).Seconds()),
		Secure:   d.base.Config().Secure(),
		HttpOnly: true,
		Path:     "/",
		Domain:   d.domain,
		SameSite: http.SameSiteStrictMode,
	})
}

// Config returns the configuration provider from the base cookie setter
func (d *domainCookieSetter) Config() ConfigProvider {
	return d.base.Config()
}

// SetCookie implements CookieSetter interface for setting a generic cookie for a specific domain.
func (d *domainCookieSetter) SetCookie(w http.ResponseWriter, name, value, domain, path string, expiry time.Time, secure, httpOnly bool, sameSite http.SameSite) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   d.domain,
		Path:     path,
		Expires:  expiry,
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: sameSite,
	}
	http.SetCookie(w, cookie)
}

// NewChainedCookieSetter creates a CookieSetter that chains multiple setters
func NewChainedCookieSetter(setters ...CookieSetter) CookieSetter {
	return &chainedCookieSetter{setters: setters}
}

type chainedCookieSetter struct {
	setters []CookieSetter
}

func (c *chainedCookieSetter) SetJWTCookie(w http.ResponseWriter, subject string, purpose jwt.Purpose, expiry time.Duration, opts ...jwt.Option) (string, error) {
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

func (c *chainedCookieSetter) EchoAuthCookie(w http.ResponseWriter, r *http.Request, opts ...jwt.Option) {
	// Call EchoAuthCookie on all setters, not just the first
	for _, setter := range c.setters {
		setter.EchoAuthCookie(w, r, opts...)
	}
}

func (c *chainedCookieSetter) SetCookie(w http.ResponseWriter, name, value, domain, path string, expiry time.Time, secure, httpOnly bool, sameSite http.SameSite) {
	// Call SetCookie on all setters
	for _, setter := range c.setters {
		setter.SetCookie(w, name, value, domain, path, expiry, secure, httpOnly, sameSite)
	}
}

// Config returns the configuration provider from the first setter in the chain
// If no setters exist, returns nil
func (c *chainedCookieSetter) Config() ConfigProvider {
	if len(c.setters) > 0 {
		return c.setters[0].Config()
	}
	return nil
}
