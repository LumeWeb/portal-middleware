package auth

import (
	"crypto/ed25519"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authmocks "go.lumeweb.com/portal-middleware/mocks/auth"
)

func TestParseAuthTokenHeader(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		expected    string
	}{
		{"Bearer prefix", "Bearer token123", "token123"},
		{"lowercase bearer", "bearer token456", "token456"},
		{"no prefix", "token789", "token789"},
		{"empty header", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", tt.headerValue)
			result := ParseAuthTokenHeader(req.Header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidJWT(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	validToken, _ := CreateJWTToken(priv, "test.com", "user1", jwt.JWTPurposeLogin, time.Hour)

	t.Run("valid token", func(t *testing.T) {
		assert.True(t, IsValidJWT(validToken, priv))
	})

	t.Run("invalid token", func(t *testing.T) {
		assert.False(t, IsValidJWT("invalid.token", priv))
	})

	t.Run("wrong key", func(t *testing.T) {
		_, wrongPriv, _ := ed25519.GenerateKey(nil)
		assert.False(t, IsValidJWT(validToken, wrongPriv))
	})
}

func TestAuthMiddleware(t *testing.T) {
	mockConfig := authmocks.NewMockConfigProvider(t)
	mockValidator := authmocks.NewMockTokenValidator(t)
	
	// Setup mock config to return a valid private key
	_, privKey, _ := ed25519.GenerateKey(nil)
	mockConfig.On("GetPrivateKey").Return(privKey)
	mockConfig.On("GetAuthCookieName").Return("auth_cookie")
	mockConfig.On("GetAuthTokenName").Return("auth_token")

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer valid.token")

		mockValidator.On("Validate", "valid.token", "login").
			Return(&gjwt.RegisteredClaims{Subject: "123"}, nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:       mockConfig,
			Validator:    mockValidator,
			Purpose:      "login",
			EmptyAllowed: false,
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("expired but allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer expired.token")

		mockValidator.On("Validate", "expired.token", "login").
			Return(&gjwt.RegisteredClaims{Subject: "123"}, gjwt.ErrTokenExpired)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        "login",
			ExpiredAllowed: true,
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("invalid purpose", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer wrong.purpose.token")

		mockValidator.On("Validate", "wrong.purpose.token", "login").
			Return(nil, jwt.ErrJWTInvalid)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   "login",
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestFindAuthToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	validToken, _ := CreateJWTToken(priv, "test.com", "user1", jwt.JWTPurposeLogin, time.Hour)

	t.Run("header first", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		result := FindAuthToken(req, priv, "auth_cookie", "auth_token")
		assert.Equal(t, validToken, result)
	})

	t.Run("cookie fallback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "auth_cookie", Value: validToken})
		result := FindAuthToken(req, priv, "auth_cookie", "auth_token")
		assert.Equal(t, validToken, result)
	})

	t.Run("query param last", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/?auth_token="+validToken, nil)
		result := FindAuthToken(req, priv, "auth_cookie", "auth_token")
		assert.Equal(t, validToken, result)
	})
}

func TestJWTVerifyToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	validToken, _ := CreateJWTToken(priv, "test.com", "user1", jwt.JWTPurposeLogin, time.Hour)

	t.Run("valid token", func(t *testing.T) {
		claims, err := JWTVerifyToken(validToken, "test.com", priv, func(c *gjwt.RegisteredClaims) error {
			if c.Subject != "user1" {
				return jwt.ErrJWTInvalid
			}
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, "user1", claims.Subject)
	})

	t.Run("invalid issuer", func(t *testing.T) {
		_, err := JWTVerifyToken(validToken, "wrong.com", priv, nil)
		assert.ErrorIs(t, err, jwt.ErrJWTUnexpectedIssuer)
	})

	t.Run("expired token", func(t *testing.T) {
		expiredToken, _ := CreateJWTToken(priv, "test.com", "user1", jwt.JWTPurposeLogin, -time.Hour)
		_, err := JWTVerifyToken(expiredToken, "test.com", priv, nil)
		assert.ErrorIs(t, err, gjwt.ErrTokenExpired)
	})
}
