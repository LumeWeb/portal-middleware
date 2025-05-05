package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"net/http/httptest"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateJWTToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	domain := "test.com"
	subject := "user123"
	purpose := jwt.JWTPurposeLogin
	expiration := time.Hour

	t.Run("valid token creation", func(t *testing.T) {
		token, err := CreateJWTToken(priv, domain, subject, purpose, expiration)
		require.NoError(t, err)

		parsed, err := gjwt.ParseWithClaims(token, &gjwt.RegisteredClaims{}, func(t *gjwt.Token) (interface{}, error) {
			return pub, nil
		})
		require.NoError(t, err)

		claims := parsed.Claims.(*gjwt.RegisteredClaims)
		assert.Equal(t, subject, claims.Subject)
		assert.Equal(t, domain, claims.Issuer)
		assert.Contains(t, claims.Audience, string(purpose))
		assert.WithinDuration(t, time.Now().Add(expiration), claims.ExpiresAt.Time, time.Second)
	})

	t.Run("invalid private key", func(t *testing.T) {
		_, err := CreateJWTToken(nil, domain, subject, purpose, expiration)
		assert.Error(t, err)
	})
}

func TestRefreshJWTToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	domain := "test.com"
	subject := "user123"
	expiration := time.Hour

	t.Run("valid token refresh", func(t *testing.T) {
		original, _ := CreateJWTToken(priv, domain, subject, jwt.JWTPurposeLogin, time.Minute)
		refreshed, err := RefreshJWTToken(original, priv, domain, expiration)
		require.NoError(t, err)

		parsed, _ := gjwt.ParseWithClaims(refreshed, &gjwt.RegisteredClaims{}, func(t *gjwt.Token) (interface{}, error) {
			return pub, nil
		})
		claims := parsed.Claims.(*gjwt.RegisteredClaims)
		assert.WithinDuration(t, time.Now().Add(expiration), claims.ExpiresAt.Time, time.Second)
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := RefreshJWTToken("invalid", priv, domain, expiration)
		assert.Error(t, err)
	})
}

func TestSendJWT(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	domain := "test.com"
	cookieName := "auth"
	subject := "user123"
	purpose := jwt.JWTPurposeLogin
	expiration := time.Hour

	t.Run("sets cookie correctly", func(t *testing.T) {
		w := httptest.NewRecorder()
		token, err := SendJWT(w, priv, domain, cookieName, subject, purpose, expiration)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		cookie := cookies[0]
		assert.Equal(t, cookieName, cookie.Name)
		assert.Equal(t, token, cookie.Value)
		assert.WithinDuration(t, time.Now().Add(expiration), cookie.Expires, time.Second)
	})

	t.Run("no cookie when name empty", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, err := SendJWT(w, priv, domain, "", subject, purpose, expiration)
		assert.NoError(t, err)
		assert.Empty(t, w.Result().Cookies())
	})
}

func TestCookieSetter(t *testing.T) {
	config := NewMockConfigProvider(t)
	apis := NewMockAPIProvider(t)
	config.On("GetPrivateKey").Return(ed25519.NewKeyFromSeed(make([]byte, 32)))
	config.On("GetDomain").Return("test.com")
	config.On("GetAuthCookieName").Return("auth")
	apis.On("GetAPIs").Return([]string{"api1.test.com", "api2.test.com"})

	t.Run("multi cookie setter", func(t *testing.T) {
		setter := NewMultiCookieSetter(config, apis)
		w := httptest.NewRecorder()

		_, err := setter.SetJWTCookie(w, "user123", jwt.JWTPurposeLogin, time.Hour)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		assert.Len(t, cookies, 3) // main domain + 2 APIs
	})

	t.Run("clear cookies", func(t *testing.T) {
		setter := NewMultiCookieSetter(config, apis)
		w := httptest.NewRecorder()
		setter.ClearJWTCookie(w)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 3)
		for _, c := range cookies {
			assert.Equal(t, -1, c.MaxAge)
		}
	})
}
