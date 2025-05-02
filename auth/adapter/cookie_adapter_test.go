package adapter

import (
	"crypto/ed25519"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.sia.tech/coreutils/wallet"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authmocks "go.lumeweb.com/portal-middleware/mocks/auth"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"
)

func TestCoreAPIProvider_GetAPIs(t *testing.T) {

	// Create mock APIs
	mockAPI1 := coreMocks.NewMockAPI(t)
	mockAPI1.On("Name").Return("api1").Maybe()
	mockAPI1.On("Subdomain").Return("api1.example.com").Maybe()
	mockAPI2 := coreMocks.NewMockAPI(t)
	mockAPI2.On("Name").Return("api2").Maybe()
	mockAPI2.On("Subdomain").Return("api2.example.com").Maybe()

	// Register test APIs
	core.RegisterAPI("api1", mockAPI1)
	core.RegisterAPI("api2", mockAPI2)

	// Reset API registry after test
	t.Cleanup(core.ResetState)

	provider := NewAPIProvider()
	apis := provider.GetAPIs()

	assert.ElementsMatch(t, []string{"api1.example.com", "api2.example.com"}, apis, "Should return all API domains")
}

func TestCoreCookieSetter(t *testing.T) {
	mockConfig := &authmocks.MockConfigProvider{}
	_, privKey, _ := ed25519.GenerateKey(nil)

	mockConfig.On("GetPrivateKey").Return(privKey)
	mockConfig.On("GetDomain").Return("example.com")
	mockConfig.On("GetAuthCookieName").Return("auth_token")

	setter := NewCookieSetter(mockConfig)

	t.Run("SetJWTCookie sets main cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		token, err := setter.SetJWTCookie(w, "user123", jwt.JWTPurposeLogin, time.Hour)

		require.NoError(t, err, "Should create token without error")
		assert.NotEmpty(t, token, "Token should not be empty")

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should set one cookie")

		cookie := cookies[0]
		assert.Equal(t, "auth_token", cookie.Name)
		assert.Equal(t, token, cookie.Value)
		assert.WithinDuration(t, time.Now().Add(time.Hour), cookie.Expires, time.Second)
	})

	t.Run("ClearJWTCookie removes cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		setter.ClearJWTCookie(w)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should set one cookie")

		cookie := cookies[0]
		assert.Equal(t, "auth_token", cookie.Name)
		assert.Equal(t, "", cookie.Value)
		assert.Equal(t, -1, cookie.MaxAge)
	})
}

func TestMultiCoreSetterFromCore(t *testing.T) {
	// Setup test context with mock config
	ctx := coreTesting.NewTestContext(t)

	// Configure core context with test values
	cfg := ctx.Config().Config()
	cfg.Core.Domain = "main.example.com"
	seedPhrase := wallet.NewSeedPhrase()
	err := cfg.Core.Identity.DecodeMapstructure(seedPhrase)
	if err != nil {
		t.Error(err)
	}
	// Create test APIs for multi-domain test
	mockAPI1 := coreMocks.NewMockAPI(t)
	mockAPI1.On("Name").Return("api1.example.com").Maybe()
	mockAPI1.On("Subdomain").Return("api1.example.com").Maybe()
	mockAPI2 := coreMocks.NewMockAPI(t)
	mockAPI2.On("Name").Return("api2.example.com").Maybe()
	mockAPI2.On("Subdomain").Return("api2.example.com").Maybe()
	core.RegisterAPI("api1", mockAPI1)
	core.RegisterAPI("api2", mockAPI2)

	setter := MultiCoreSetterFromCore(ctx)

	t.Run("Sets cookies for all domains", func(t *testing.T) {
		w := httptest.NewRecorder()
		token, err := setter.SetJWTCookie(w, "user123", jwt.JWTPurposeLogin, time.Hour)

		require.NoError(t, err, "Should create token without error")
		assert.NotEmpty(t, token, "Token should not be empty")

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 3, "Should set cookies for main domain + 2 APIs")

		// Verify main domain cookie
		mainCookie := cookies[0]
		assert.Equal(t, "main.example.com", mainCookie.Domain)
		assert.Equal(t, "auth_token", mainCookie.Name)

		// Verify API subdomain cookies
		api1Cookie := cookies[1]
		assert.Equal(t, "api1.example.com", api1Cookie.Domain)
		api2Cookie := cookies[2]
		assert.Equal(t, "api2.example.com", api2Cookie.Domain)
	})

	t.Run("Clears all cookies", func(t *testing.T) {
		w := httptest.NewRecorder()
		setter.ClearJWTCookie(w)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 3, "Should clear cookies for all domains")

		for _, cookie := range cookies {
			assert.Equal(t, "", cookie.Value)
			assert.Equal(t, -1, cookie.MaxAge)
		}
	})
}
