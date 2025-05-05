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
)

func TestAuthMiddleware(t *testing.T) {
	mockConfig := NewMockConfigProvider(t)
	mockValidator := NewMockTokenValidator(t)

	// Setup mock config to return a valid private key
	_, privKey, _ := ed25519.GenerateKey(nil)
	mockConfig.On("GetPrivateKey").Return(privKey)
	mockConfig.On("GetDomain").Return("test.com")
	mockConfig.On("GetAuthCookieName").Return("auth_cookie")
	mockConfig.On("GetAuthTokenName").Return("auth_token")

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer valid.token")

		mockValidator.On("ValidateWithClaims", "valid.token", jwt.JWTPurposeLogin).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, (*gjwt.RegisteredClaims)(nil), nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:       mockConfig,
			Validator:    mockValidator,
			Purpose:      jwt.JWTPurposeLogin,
			EmptyAllowed: false,
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid.token")

		mockValidator.On("ValidateWithClaims", "invalid.token", jwt.JWTPurposeLogin).
			Return(nil, nil, jwt.ErrJWTInvalid)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   jwt.JWTPurposeLogin,
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("expired but allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer expired.token")

		mockValidator.On("ValidateWithClaims", "expired.token", jwt.JWTPurposeLogin).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, (*gjwt.RegisteredClaims)(nil), gjwt.ErrTokenExpired)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.JWTPurposeLogin,
			EmptyAllowed:   false,
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

		mockValidator.On("ValidateWithClaims", "wrong.purpose.token", jwt.JWTPurposeLogin).
			Return(nil, nil, jwt.ErrJWTInvalid)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   jwt.JWTPurposeLogin,
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("custom claims registration", func(t *testing.T) {
		type customClaims struct {
			*gjwt.RegisteredClaims
			CustomField string `json:"custom_field"`
		}

		tokenString, err := CreateJWTToken(privKey, "test.com", "user123",
			jwt.JWTPurpose("test_purpose"), time.Hour,
			WithClaims(&customClaims{}),
			WithModifiers(func(claims gjwt.Claims) {
				if cc, ok := claims.(*customClaims); ok {
					cc.CustomField = "test_value"
				}
			}))
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		mockValidator.On("ValidateWithClaims", tokenString, jwt.JWTPurpose("test_purpose")).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, &customClaims{
				RegisteredClaims: &gjwt.RegisteredClaims{Subject: "123"},
				CustomField:      "test_value",
			}, nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:       mockConfig,
			Validator:    mockValidator,
			Purpose:      jwt.JWTPurpose("test_purpose"),
			EmptyAllowed: false,
		})

		rr := httptest.NewRecorder()
		customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims[*customClaims](r.Context())
			assert.True(t, ok, "should retrieve custom claims")
			assert.Equal(t, "test_value", claims.CustomField)
			w.WriteHeader(http.StatusOK)
		})
		handler := middleware(customHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("missing config panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic for missing config")
			} else {
				assert.Contains(t, r.(string), "ConfigProvider", "panic message should mention ConfigProvider")
			}
		}()

		AuthMiddleware(AuthMiddlewareOptions{
			Purpose: "login",
		})
	})

	t.Run("missing purpose panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic for missing purpose")
			} else {
				assert.Contains(t, r.(string), "Purpose", "panic message should mention Purpose")
			}
		}()

		AuthMiddleware(AuthMiddlewareOptions{
			Config: mockConfig,
		})
	})
}
