package adapter

import (
	"crypto/ed25519"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCookieSetter(t *testing.T) {
	mockConfig := NewMockConfigProvider(t)
	_, privKey, _ := ed25519.GenerateKey(nil)

	// Setup mock expectations
	mockConfig.On("GetPrivateKey").Return(privKey)
	mockConfig.On("GetDomain").Return("test.com")
	mockConfig.On("GetAuthCookieName").Return("auth_token")

	setter := NewCookieSetter(mockConfig)

	t.Run("SetJWTCookie sets main cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		token, err := setter.SetJWTCookie(w, "user123", jwt.PurposeLogin, time.Hour)

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

func TestMultiCookieSetter(t *testing.T) {
	mockConfig := NewMockConfigProvider(t)
	mockAPIProvider := NewMockAPIProvider(t)

	_, privKey, _ := ed25519.GenerateKey(nil)

	// Setup mock expectations
	mockConfig.On("GetPrivateKey").Return(privKey)
	mockConfig.On("GetDomain").Return("test.com")
	mockConfig.On("GetAuthCookieName").Return("auth_token")
	mockAPIProvider.On("GetAPIs").Return([]string{"api1.test.com", "api2.test.com"})

	setter := NewMultiCookieSetter(mockConfig, mockAPIProvider)

	t.Run("Sets cookies for all domains", func(t *testing.T) {
		w := httptest.NewRecorder()
		token, err := setter.SetJWTCookie(w, "user123", jwt.PurposeLogin, time.Hour)

		require.NoError(t, err, "Should create token without error")
		assert.NotEmpty(t, token, "Token should not be empty")

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 3, "Should set cookies for main domain + 2 APIs")

		// Verify main domain cookie
		mainCookie := cookies[0]
		assert.Equal(t, "test.com", mainCookie.Domain)
		assert.Equal(t, "auth_token", mainCookie.Name)

		// Verify API subdomain cookies
		api1Cookie := cookies[1]
		assert.Equal(t, "api1.test.com", api1Cookie.Domain)
		api2Cookie := cookies[2]
		assert.Equal(t, "api2.test.com", api2Cookie.Domain)
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
