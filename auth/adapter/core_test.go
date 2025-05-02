package adapter

import (
	"go.lumeweb.com/portal-middleware/auth"
	"go.sia.tech/coreutils/wallet"
	"testing"

	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoreConfigProvider(t *testing.T) {
	// Create test context with configured values
	ctx := coreTesting.NewTestContext(t)

	testDomain := "test.example.com"

	cfg := ctx.Config().Config()
	cfg.Core.Domain = testDomain
	seedPhrase := wallet.NewSeedPhrase()
	err := cfg.Core.Identity.DecodeMapstructure(seedPhrase)
	if err != nil {
		t.Error(err)
	}

	testPrivKey := cfg.Core.Identity.PrivateKey()

	// Create provider from core context
	provider := NewFromCore(ctx).(*coreConfigProvider)

	t.Run("GetPrivateKey returns configured key", func(t *testing.T) {
		key := provider.GetPrivateKey()
		assert.Equal(t, testPrivKey, key, "Should return configured private key")
	})

	t.Run("GetDomain returns configured domain", func(t *testing.T) {
		domain := provider.GetDomain()
		assert.Equal(t, testDomain, domain, "Should return configured domain")
	})

	t.Run("GetAuthCookieName returns core constant", func(t *testing.T) {
		name := provider.GetAuthCookieName()
		assert.Equal(t, core.AUTH_COOKIE_NAME, name, "Should return core AUTH_COOKIE_NAME")
	})

	t.Run("GetAuthTokenName returns core constant", func(t *testing.T) {
		name := provider.GetAuthTokenName()
		assert.Equal(t, core.AUTH_TOKEN_NAME, name, "Should return core AUTH_TOKEN_NAME")
	})

	t.Run("implements ConfigProvider interface", func(t *testing.T) {
		var provider interface{} = NewFromCore(ctx)
		_, ok := provider.(auth.ConfigProvider)
		require.True(t, ok, "Should implement ConfigProvider interface")
	})
}
