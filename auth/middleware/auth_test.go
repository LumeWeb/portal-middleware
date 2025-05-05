package middleware

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/auth/validation"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware(t *testing.T) {
	mockConfig := adapter.NewMockConfigProvider(t)
	mockValidator := validation.NewMockTokenValidator(t)

	// Setup mock config to return a valid private key
	_, privKey, _ := ed25519.GenerateKey(nil)
	mockConfig.On("GetPrivateKey").Return(privKey)
	mockConfig.On("GetDomain").Return("example.com")
	mockConfig.On("GetAuthCookieName").Return("auth_cookie")

	t.Run("valid token", func(t *testing.T) {

		rr := httptest.NewRecorder()
		cookieSetter := adapter.NewCookieSetter(mockConfig)

		cookie, err := cookieSetter.SetJWTCookie(rr, "0", jwt.PurposeLogin, time.Hour)
		if err != nil {
			t.Error(err)
		}

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cookie))

		// Setup validator mock to return expected claims
		mockValidator.On("ValidateWithClaims", cookie, jwt.PurposeLogin).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, (*gjwt.RegisteredClaims)(nil), nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:       mockConfig,
			Validator:    mockValidator,
			Purpose:      jwt.PurposeLogin,
			EmptyAllowed: false,
		})

		// Custom handler to verify context values
		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			// Verify user ID was set in context
			userID, err := mcontext.GetUserID(r.Context())
			assert.NoError(t, err)
			assert.Equal(t, uint(123), userID)

			// Verify auth token was set in context
			authToken, err := mcontext.GetAuthToken(r.Context())
			assert.NoError(t, err)
			assert.Equal(t, cookie, authToken)

			w.WriteHeader(http.StatusOK)
		})

		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
		mockConfig.AssertExpectations(t)
		mockValidator.AssertExpectations(t)
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid.token")

		mockValidator.On("ValidateWithClaims", "invalid.token", jwt.PurposeLogin).
			Return(nil, nil, jwt.ErrJWTInvalid)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   jwt.PurposeLogin,
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("expired but allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer expired.token")

		mockValidator.On("ValidateWithClaims", "expired.token", jwt.PurposeLogin).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, (*gjwt.RegisteredClaims)(nil), gjwt.ErrTokenExpired)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.PurposeLogin,
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

		mockValidator.On("ValidateWithClaims", "wrong.purpose.token", jwt.PurposeLogin).
			Return(nil, nil, jwt.ErrJWTInvalid)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   jwt.PurposeLogin,
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("custom claims registration", func(t *testing.T) {
		type CustomClaims struct {
			*gjwt.RegisteredClaims
			CustomField string `json:"custom_field"`
		}

		tokenString, err := jwt.CreateToken(privKey, "test.com", "user123",
			jwt.Purpose("test_purpose"), time.Hour,
			jwt.WithClaims(&CustomClaims{}),
			jwt.WithModifiers(func(claims gjwt.Claims) {
				if cc, ok := claims.(*CustomClaims); ok {
					cc.CustomField = "test_value"
				}
			}))
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		mockValidator.On("ValidateWithClaims", tokenString, jwt.Purpose("test_purpose")).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, &CustomClaims{
				RegisteredClaims: &gjwt.RegisteredClaims{Subject: "123"},
				CustomField:      "test_value",
			}, nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:       mockConfig,
			Validator:    mockValidator,
			Purpose:      jwt.Purpose("test_purpose"),
			EmptyAllowed: false,
			Options:      jwt.Options(jwt.WithClaims(&CustomClaims{})),
		})

		rr := httptest.NewRecorder()
		customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := auth.GetClaims[*CustomClaims](r.Context())
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

func TestAuthMiddleware_CustomClaims(t *testing.T) {
	// Setup common test dependencies
	mockConfig := adapter.NewMockConfigProvider(t)
	_, privKey, _ := ed25519.GenerateKey(nil)
	mockConfig.On("GetPrivateKey").Return(privKey).Maybe()
	mockConfig.On("GetDomain").Return("test.com").Maybe()
	mockConfig.On("GetAuthCookieName").Return("auth_cookie").Maybe()

	type CustomClaims struct {
		*gjwt.RegisteredClaims
		Role string `json:"role"`
	}

	t.Run("custom claims are accessible", func(t *testing.T) {
		// Create fresh mock for this test
		mockValidator := validation.NewMockTokenValidator(t)

		validToken, err := jwt.CreateToken(privKey, "test.com", "123", jwt.PurposeLogin, time.Hour,
			jwt.WithClaims(&CustomClaims{
				RegisteredClaims: &gjwt.RegisteredClaims{},
				Role:             "admin",
			}),
		)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)

		// Setup fresh expectations
		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		customClaims := &CustomClaims{Role: "admin"}
		mockValidator.On("ValidateWithClaims", validToken, jwt.PurposeLogin).
			Return(baseClaims, customClaims, nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   jwt.PurposeLogin,
			Options:   jwt.Options(jwt.WithClaims(&CustomClaims{})),
		})

		rr := httptest.NewRecorder()
		customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := auth.GetClaims[*CustomClaims](r.Context())
			assert.True(t, ok)
			assert.Equal(t, "admin", claims.Role)
			w.WriteHeader(http.StatusOK)
		})
		handler := middleware(customHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockValidator.AssertExpectations(t)
	})

	t.Run("invalid custom claims type", func(t *testing.T) {
		// Create fresh mock for this test
		mockValidator := validation.NewMockTokenValidator(t)

		validToken, err := jwt.CreateToken(privKey, "test.com", "123", jwt.PurposeLogin, time.Hour,
			jwt.WithClaims(&CustomClaims{
				RegisteredClaims: &gjwt.RegisteredClaims{},
				Role:             "admin",
			}),
		)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)

		// Setup fresh expectations with different return type
		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", validToken, jwt.PurposeLogin).
			Return(baseClaims, &gjwt.RegisteredClaims{}, nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   jwt.PurposeLogin,
			Options:   jwt.Options(jwt.WithClaims(&CustomClaims{})),
		})

		rr := httptest.NewRecorder()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called for invalid claim types")
		}))

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		mockValidator.AssertExpectations(t)
	})
}

func TestAuthMiddleware_ValidationErrors(t *testing.T) {
	mockConfig := adapter.NewMockConfigProvider(t)
	mockValidator := validation.NewMockTokenValidator(t)

	type CustomClaims struct {
		*gjwt.RegisteredClaims
		Role string `json:"role"`
	}

	t.Run("token with missing claims", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid.token")

		mockValidator.On("ValidateWithClaims", "invalid.token", jwt.PurposeLogin).
			Return(nil, nil, jwt.ErrJWTInvalid)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   jwt.PurposeLogin,
			Options:   jwt.Options(jwt.WithClaims(&CustomClaims{})),
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("token with malformed claims", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer malformed.token")

		mockValidator.On("ValidateWithClaims", "malformed.token", jwt.PurposeLogin).
			Return(&gjwt.RegisteredClaims{}, nil, errors.New("malformed claims"))

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:    mockConfig,
			Validator: mockValidator,
			Purpose:   jwt.PurposeLogin,
			Options:   jwt.Options(jwt.WithClaims(&CustomClaims{})),
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestClaimsContext(t *testing.T) {
	type CustomClaims struct {
		*gjwt.RegisteredClaims
		FeatureFlag bool `json:"feature_flag"`
	}

	ctx := context.Background()
	baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
	customClaims := &CustomClaims{FeatureFlag: true}

	// Store claims
	ctx = context.WithValue(ctx, auth.ClaimsContextKey{}, auth.NewClaimsWrapper(baseClaims, customClaims))

	t.Run("get custom claims", func(t *testing.T) {
		claims, ok := auth.GetClaims[*CustomClaims](ctx)
		assert.True(t, ok)
		assert.Equal(t, true, claims.FeatureFlag)
	})

	t.Run("get base claims", func(t *testing.T) {
		claims, ok := auth.GetClaims[*gjwt.RegisteredClaims](ctx)
		assert.True(t, ok)
		assert.Equal(t, "123", claims.Subject)
	})

	t.Run("invalid claim type", func(t *testing.T) {
		type OtherClaims struct{ gjwt.RegisteredClaims }
		claims, ok := auth.GetClaims[*OtherClaims](ctx)
		assert.False(t, ok)
		assert.Nil(t, claims)
	})
}
