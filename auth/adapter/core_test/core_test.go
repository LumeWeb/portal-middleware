package adapter_test

import (
	"go.sia.tech/coreutils/wallet"
	"testing"

	"go.lumeweb.com/portal/core"
	adapter "go.lumeweb.com/portal-middleware/auth/adapter"
	coreTesting "go.lumeweb.com/portal/core/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoreConfigProvider(t *testing.T) {
	// Create test context
	testCtx, err := coreTesting.NewTestContext(t)
	require.NoError(t, err)

	// Create provider from context
	provider := adapter.NewFromCore(testCtx)

	t.Run("GetPrivateKey returns configured key", func(t *testing.T) {
		// Setup test identity
		seedPhrase := wallet.NewSeedPhrase()
		cfg := testCtx.Config()
		err := cfg.Set(testCtx, "core.identity", seedPhrase)
		require.NoError(t, err)

		testPrivKey := cfg.Config().Core.Identity.PrivateKey()
		key := provider.GetPrivateKey()
		assert.Equal(t, testPrivKey, key, "Should return configured private key")
	})

	t.Run("GetDomain returns configured domain", func(t *testing.T) {
		testDomain := "test.example.com"
		cfg := testCtx.Config()
		err := cfg.Set(testCtx, "core.domain", testDomain)
		require.NoError(t, err)

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

	t.Run("GetCtx returns original context", func(t *testing.T) {
		// Create a new test context
		testCtx, err := coreTesting.NewTestContext(t)
		require.NoError(t, err)

		// Create provider from the test context
		provider := adapter.NewFromCore(testCtx)

		// Ensure GetCtx returns the same context
		assert.Same(t, testCtx, provider.GetCtx(), "GetCtx should return the original context used to create the provider")
	})

	t.Run("implements ConfigProvider interface", func(t *testing.T) {
		testCtx, err := coreTesting.NewTestContext(t)
		require.NoError(t, err)
		var provider interface{} = adapter.NewFromCore(testCtx)
		_, ok := provider.(adapter.ConfigProvider)
		require.True(t, ok, "Should implement ConfigProvider interface")
	})
}
