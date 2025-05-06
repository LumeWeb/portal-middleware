package adapter

import (
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.sia.tech/coreutils/wallet"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestCookieSetter(t *testing.T) {
	ctx := coreTesting.NewTestContext(t)
	mockConfig := NewMockConfigProvider(t)
	seedPhrase := wallet.NewSeedPhrase()

	// Setup mock expectations
	mockConfig.On("GetDomain").Return("test.com")
	mockConfig.On("GetAuthCookieName").Return("auth_token")
	mockConfig.On("GetCtx").Return(ctx)

	cfg := ctx.Config()
	err := cfg.Update("core.domain", "main.example.com")
	if err != nil {
		t.Error(err)
	}
	err = cfg.Update("core.identity", seedPhrase)
	if err != nil {
		t.Error(err)
	}

	mockConfig.On("GetPrivateKey").Return(ctx.Config().Config().Core.Identity.PrivateKey())
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

	t.Run("EchoAuthCookie echoes valid cookie", func(t *testing.T) {
		// First set a cookie
		setW := httptest.NewRecorder()
		token, err := setter.SetJWTCookie(setW, "user123", jwt.PurposeLogin, time.Hour)
		require.NoError(t, err)

		// Create request with the cookie
		req := httptest.NewRequest("GET", "/", nil)
		for _, cookie := range setW.Result().Cookies() {
			req.AddCookie(cookie)
		}

		// Echo the cookie
		echoW := httptest.NewRecorder()
		setter.EchoAuthCookie(echoW, req)

		// Verify echoed cookie
		echoCookies := echoW.Result().Cookies()
		require.Len(t, echoCookies, 1)
		echoCookie := echoCookies[0]
		assert.Equal(t, "auth_token", echoCookie.Name)
		assert.Equal(t, token, echoCookie.Value)
		assert.Equal(t, "main.example.com", echoCookie.Domain)
	})

	t.Run("EchoAuthCookie ignores invalid cookie", func(t *testing.T) {
		// Create request with invalid cookie
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "auth_token",
			Value: "invalid.token",
		})

		// Echo the cookie
		echoW := httptest.NewRecorder()
		setter.EchoAuthCookie(echoW, req)

		// Should return error
		assert.Equal(t, http.StatusInternalServerError, echoW.Code)
	})

	t.Run("EchoAuthCookie ignores missing cookie", func(t *testing.T) {
		// Create request without cookie
		req := httptest.NewRequest("GET", "/", nil)

		// Echo the cookie
		echoW := httptest.NewRecorder()
		setter.EchoAuthCookie(echoW, req)

		// Should not set any cookies
		assert.Len(t, echoW.Result().Cookies(), 0)
	})
}
