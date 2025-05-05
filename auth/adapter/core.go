package adapter

import (
	"crypto/ed25519"
	"go.lumeweb.com/portal/core"
)

// ConfigProvider defines an interface for accessing configuration needed by auth middleware
// ConfigProvider defines the configuration requirements for authentication services.
// Implementations should provide cryptographic keys and operational settings.
type ConfigProvider interface {
	GetPrivateKey() ed25519.PrivateKey
	GetDomain() string
	GetAuthCookieName() string
	GetAuthTokenName() string
}

// coreConfigProvider bridges the core framework's context with the auth package's ConfigProvider interface.
// This allows the auth middleware to access configuration values from the core system.
type coreConfigProvider struct {
	ctx core.Context
}

// Compile-time interface implementation check
var _ ConfigProvider = (*coreConfigProvider)(nil)

// NewFromCore creates a ConfigProvider that sources configuration from the core framework context.
// This is the primary integration point between the core framework and auth package.
// Example:
//
//	coreCtx := core.GetContext()
//	authConfig := adapter.NewFromCore(coreCtx)
func NewFromCore(ctx core.Context) ConfigProvider {
	return &coreConfigProvider{ctx: ctx}
}

// GetPrivateKey retrieves the Ed25519 private key used for JWT signing from core configuration.
// Implements auth.ConfigProvider interface.
func (c *coreConfigProvider) GetPrivateKey() ed25519.PrivateKey {
	return c.ctx.Config().Config().Core.Identity.PrivateKey()
}

// GetDomain returns the primary domain name from core configuration.
// Used for JWT issuer validation and cookie domain settings.
func (c *coreConfigProvider) GetDomain() string {
	return c.ctx.Config().Config().Core.Domain
}

// GetAuthCookieName returns the auth cookie name
func (c *coreConfigProvider) GetAuthCookieName() string {
	return core.AUTH_COOKIE_NAME
}

// GetAuthTokenName returns the auth token name
func (c *coreConfigProvider) GetAuthTokenName() string {
	return core.AUTH_TOKEN_NAME
}
