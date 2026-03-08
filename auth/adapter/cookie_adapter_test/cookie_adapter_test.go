package adapter_test

import (
	"crypto/ed25519"
	gjwt "github.com/golang-jwt/jwt/v5"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.sia.tech/coreutils/wallet"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	provider := adapter.NewAPIProvider()
	apis := provider.GetAPIs()

	assert.ElementsMatch(t, []string{"api1.example.com", "api2.example.com"}, apis, "Should return all API domains")
}

func TestCoreCookieSetter(t *testing.T) {

	mockConfig := adapter.NewMockConfigProvider(t)
	_, privKey, _ := ed25519.GenerateKey(nil)

	mockConfig.On("GetPrivateKey").Return(privKey)
	mockConfig.On("GetDomain").Return("example.com")
	mockConfig.On("GetAuthCookieName").Return(core.AUTH_COOKIE_NAME)
	mockConfig.On("Secure").Return(true).Maybe()

	setter := adapter.NewCookieSetter(mockConfig)

	t.Run("SetJWTCookie sets main cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		token, err := setter.SetJWTCookie(w, "user123", jwt.PurposeLogin, time.Hour)

		require.NoError(t, err, "Should create token without error")
		assert.NotEmpty(t, token, "Token should not be empty")

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should set one cookie")

		cookie := cookies[0]
		assert.Equal(t, core.AUTH_COOKIE_NAME, cookie.Name)
		assert.Equal(t, token, cookie.Value)
		assert.WithinDuration(t, time.Now().Add(time.Hour), cookie.Expires, time.Second)
	})

	t.Run("ClearJWTCCookie removes cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		setter.ClearJWTCookie(w)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1, "Should set one cookie")

		cookie := cookies[0]
		assert.Equal(t, core.AUTH_COOKIE_NAME, cookie.Name)
		assert.Equal(t, "", cookie.Value)
		assert.Equal(t, -1, cookie.MaxAge)
	})
}

func TestMultiCoreSetterFromCore(t *testing.T) {
	// Setup test context with mock config
	ctx, err := coreTesting.NewTestContext(t)
	require.NoError(t, err)

	// Configure core context with test values
	seedPhrase := wallet.NewSeedPhrase()
	cfg := ctx.Config()
	err = cfg.Set(ctx, "core.domain", "main.example.com")
	if err != nil {
		t.Error(err)
	}
	err = cfg.Set(ctx, "core.identity", seedPhrase)
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

	setter := adapter.MultiCoreSetterFromCore(ctx)

	t.Run("Sets cookies for all domains", func(t *testing.T) {
		w := httptest.NewRecorder()
		token, err := setter.SetJWTCookie(w, "user123", jwt.PurposeLogin, time.Hour)

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

	t.Run("EchoAuthCookie echoes to all domains", func(t *testing.T) {
		// First set a cookie
		setW := httptest.NewRecorder()
		_, err := setter.SetJWTCookie(setW, "user123", jwt.PurposeLogin, time.Hour)
		require.NoError(t, err)

		// Create request with the cookie
		req := httptest.NewRequest("GET", "/", nil)
		for _, cookie := range setW.Result().Cookies() {
			if cookie.Domain == "main.example.com" {
				req.AddCookie(cookie)
				break
			}
		}

		// Echo the cookie
		echoW := httptest.NewRecorder()
		setter.EchoAuthCookie(echoW, req)

		// Verify echoed cookies
		echoCookies := echoW.Result().Cookies()
		require.Len(t, echoCookies, 3, "Should echo to main domain + 2 APIs")

		// Verify main domain cookie
		mainCookie := echoCookies[0]
		assert.Equal(t, "main.example.com", mainCookie.Domain)
		decodedJwt, err := jwt.DecodeToken(mainCookie.Value, &gjwt.RegisteredClaims{})
		require.NoError(t, err, "Failed to decode JWT token")
		issuer, err := decodedJwt.GetIssuer()
		require.NoError(t, err, "Failed to get issuer from JWT")
		assert.Equal(t, "main.example.com", issuer)
		// Verify API subdomain cookies
		api1Cookie := echoCookies[1]
		assert.Equal(t, "api1.example.com", api1Cookie.Domain)
		api2Cookie := echoCookies[2]
		assert.Equal(t, "api2.example.com", api2Cookie.Domain)
	})

	t.Run("EchoAuthCookie ignores invalid cookie", func(t *testing.T) {
		// Create request with invalid cookie
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:   "auth_token",
			Value:  "invalid.token",
			Domain: "main.example.com",
		})

		// Echo the cookie
		echoW := httptest.NewRecorder()
		setter.EchoAuthCookie(echoW, req)

		// Should return error
		assert.Equal(t, http.StatusInternalServerError, echoW.Code)
	})

	t.Run("DomainCookieSetter echoes only matching domain", func(t *testing.T) {
		// Create a mock base setter
		_, privKey, _ := ed25519.GenerateKey(nil)
		mockBaseSetter := adapter.NewMockCookieSetter(t)
		mockConfig := adapter.NewMockConfigProvider(t)
		mockConfig.On("GetPrivateKey").Return(privKey).Maybe()
		mockConfig.On("GetAuthCookieName").Return("auth_token").Maybe()
		mockConfig.On("Secure").Return(true).Maybe()
		mockBaseSetter.On("Config").Return(mockConfig).Maybe()

		// Create domain-specific setter using public API
		domainSetter := adapter.NewDomainCookieSetter(mockBaseSetter, "api1.example.com")

		// First set a cookie
		setW := httptest.NewRecorder()
		token, err := domainSetter.SetJWTCookie(setW, "user123", jwt.PurposeLogin, time.Hour)
		require.NoError(t, err)

		// Create request with the cookie
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:   "auth_token",
			Value:  token,
			Domain: "api1.example.com",
		})

		// Echo the cookie
		echoW := httptest.NewRecorder()
		domainSetter.EchoAuthCookie(echoW, req)

		// Verify only one cookie was echoed
		echoCookies := echoW.Result().Cookies()
		require.Len(t, echoCookies, 1)
		assert.Equal(t, "auth_token", echoCookies[0].Name)
		assert.Equal(t, "api1.example.com", echoCookies[0].Domain)
	})

	t.Run("DomainCookieSetter ignores non-matching domain", func(t *testing.T) {
		// Create a mock base setter
		_, privKey, _ := ed25519.GenerateKey(nil)
		mockBaseSetter := adapter.NewMockCookieSetter(t)
		mockConfig := adapter.NewMockConfigProvider(t)
		mockConfig.On("GetPrivateKey").Return(privKey).Maybe()
		mockConfig.On("GetAuthCookieName").Return("auth_token").Maybe()
		mockConfig.On("Secure").Return(true).Maybe()
		mockBaseSetter.On("Config").Return(mockConfig).Maybe()

		// Create domain-specific setter using public API
		domainSetter := adapter.NewDomainCookieSetter(mockBaseSetter, "api1.example.com")

		// Create request with cookie for different domain
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:   "auth_token",
			Value:  "some.token",
			Domain: "other.example.com",
		})

		// Echo the cookie
		echoW := httptest.NewRecorder()
		domainSetter.EchoAuthCookie(echoW, req)

		// Should not set any cookies
		assert.Len(t, echoW.Result().Cookies(), 0)
	})
}

