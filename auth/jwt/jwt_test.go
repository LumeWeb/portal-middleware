package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
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
	purpose := PurposeLogin
	expiration := time.Hour

	t.Run("valid token creation", func(t *testing.T) {
		token, err := CreateToken(priv, domain, subject, purpose, expiration)
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
		_, err := CreateToken(nil, domain, subject, purpose, expiration)
		assert.Error(t, err)
	})
}

func TestRefreshJWTToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	domain := "test.com"
	subject := "user123"
	expiration := time.Hour

	t.Run("valid token refresh", func(t *testing.T) {
		original, _ := CreateToken(priv, domain, subject, PurposeLogin, time.Minute)
		refreshed, err := RefreshToken(original, priv, domain, expiration)
		require.NoError(t, err)

		parsed, _ := gjwt.ParseWithClaims(refreshed, &gjwt.RegisteredClaims{}, func(t *gjwt.Token) (interface{}, error) {
			return pub, nil
		})
		claims := parsed.Claims.(*gjwt.RegisteredClaims)
		assert.WithinDuration(t, time.Now().Add(expiration), claims.ExpiresAt.Time, time.Second)
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := RefreshToken("invalid", priv, domain, expiration)
		assert.Error(t, err)
	})
}

func TestSendJWT(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	domain := "test.com"
	cookieName := "auth"
	subject := "user123"
	purpose := PurposeLogin
	expiration := time.Hour

	t.Run("sets cookie correctly", func(t *testing.T) {
		w := httptest.NewRecorder()
		token, err := Send(w, priv, domain, cookieName, subject, purpose, expiration)
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
		_, err := Send(w, priv, domain, "", subject, purpose, expiration)
		assert.NoError(t, err)
		assert.Empty(t, w.Result().Cookies())
	})
}

func TestCreateJWTTokenWithCustomClaims(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	domain := "test.com"
	subject := "user123"
	purpose := PurposeLogin
	expiration := time.Hour

	type CustomClaims struct {
		*gjwt.RegisteredClaims
		CustomField string `json:"custom_field"`
	}

	t.Run("custom claims are preserved", func(t *testing.T) {
		// Initialize the RegisteredClaims field properly
		claims := &CustomClaims{
			RegisteredClaims: &gjwt.RegisteredClaims{
				Subject:   subject,
				Issuer:    domain,
				ExpiresAt: gjwt.NewNumericDate(time.Now().Add(expiration)),
				Audience:  []string{string(purpose)},
			},
			CustomField: "test_value",
		}

		token, err := CreateToken(priv, domain, subject, purpose, expiration,
			WithClaims(claims),
		)
		require.NoError(t, err)

		// Parse with custom claims
		parsed, err := gjwt.ParseWithClaims(token, &CustomClaims{}, func(t *gjwt.Token) (interface{}, error) {
			return pub, nil
		})
		require.NoError(t, err)

		claims, ok := parsed.Claims.(*CustomClaims)
		require.True(t, ok)
		assert.Equal(t, "test_value", claims.CustomField)
		assert.Equal(t, subject, claims.Subject)
		assert.Equal(t, domain, claims.Issuer)
		assert.Contains(t, claims.Audience, string(purpose))
	})
}
