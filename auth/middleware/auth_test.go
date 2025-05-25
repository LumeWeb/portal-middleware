package middleware

import (
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/stretchr/testify/mock"
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

type CustomClaims struct {
	*gjwt.RegisteredClaims
	Role string `json:"role"`
}

func setupAuthTest(t *testing.T) (*adapter.MockConfigProvider, *validation.MockTokenValidator) {
	mockConfig := adapter.NewMockConfigProvider(t)
	mockValidator := validation.NewMockTokenValidator(t)

	_, privKey, _ := ed25519.GenerateKey(nil)
	mockConfig.On("GetPrivateKey").Return(privKey).Maybe()
	mockConfig.On("GetDomain").Return("example.com").Maybe()
	mockConfig.On("GetAuthCookieName").Return("auth_cookie").Maybe()
	mockConfig.On("GetAuthTokenName").Return("auth_token").Maybe()

	return mockConfig, mockValidator
}

func TestAuthMiddleware(t *testing.T) {

	t.Run("valid token", func(t *testing.T) {
		mockConfig, mockValidator := setupAuthTest(t)

		// Setup validator mock first
		mockValidator.On("ValidateWithClaims", mock.Anything, jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, (*gjwt.RegisteredClaims)(nil), nil).Once()

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:       mockConfig,
			Validator:    mockValidator,
			Purpose:      jwt.PurposeLogin,
			EmptyAllowed: false,
		})

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer valid.token")

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
			assert.Equal(t, "valid.token", authToken)

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
		mockConfig, mockValidator := setupAuthTest(t)
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid.token")

		mockValidator.On("ValidateWithClaims", "invalid.token", jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
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
		mockConfig, mockValidator := setupAuthTest(t)
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer expired.token")

		mockValidator.On("ValidateWithClaims", "expired.token", jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, &gjwt.RegisteredClaims{}, gjwt.ErrTokenExpired)

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
		mockConfig, mockValidator := setupAuthTest(t)
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer wrong.purpose.token")

		mockValidator.On("ValidateWithClaims", "wrong.purpose.token", jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
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
		mockConfig, mockValidator := setupAuthTest(t)
		type CustomClaims struct {
			*gjwt.RegisteredClaims
			CustomField string `json:"custom_field"`
		}

		// Setup mock config expectations
		_, privKey, _ := ed25519.GenerateKey(nil)
		mockConfig.On("GetPrivateKey").Return(privKey).Maybe()
		mockConfig.On("GetAuthCookieName").Return("auth_cookie").Maybe()
		mockConfig.On("GetAuthTokenName").Return("auth_token").Maybe()

		// Setup validator mock with correct claims type
		expectedClaims := &CustomClaims{
			RegisteredClaims: &gjwt.RegisteredClaims{Subject: "123"},
			CustomField:      "test_value",
		}
		mockValidator.On("ValidateWithClaims", "valid.token", jwt.Purpose("test_purpose"), &CustomClaims{}).
			Return(expectedClaims.RegisteredClaims, expectedClaims, nil).Once()

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.Purpose("test_purpose"),
			EmptyAllowed:   false,
			Options:        jwt.Options(jwt.WithClaims(&CustomClaims{})),
			ExpectedClaims: &CustomClaims{},
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer valid.token")

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
		mockValidator.AssertExpectations(t)
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

		mockConfig := adapter.NewMockConfigProvider(t)
		_, privKey, _ := ed25519.GenerateKey(nil)
		mockConfig.On("GetPrivateKey").Return(privKey).Maybe()

		AuthMiddleware(AuthMiddlewareOptions{
			Config: mockConfig,
		})
	})
}

func TestAuthMiddleware_DefaultRegisteredClaims(t *testing.T) {
	mockConfig := adapter.NewMockConfigProvider(t)
	_, privKey, _ := ed25519.GenerateKey(nil)
	mockConfig.On("GetPrivateKey").Return(privKey).Maybe()
	mockConfig.On("GetDomain").Return("test.com").Maybe()
	mockConfig.On("GetAuthCookieName").Return("auth_cookie").Maybe()
	mockConfig.On("GetAuthTokenName").Return("auth_token").Maybe()
	mockConfig.On("GetAuthTokenName").Return("auth_token").Maybe()

	t.Run("valid token with only standard claims", func(t *testing.T) {
		mockValidator := validation.NewMockTokenValidator(t)

		validToken, err := jwt.CreateToken(privKey, "test.com", "123", jwt.PurposeLogin, time.Hour)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)

		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", validToken, jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(baseClaims, nil, nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.PurposeLogin,
			ExpectedClaims: nil, // No expected claims specified
		})

		rr := httptest.NewRecorder()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Should be able to get base claims
			claims, ok := auth.GetClaims[*gjwt.RegisteredClaims](r.Context())
			assert.True(t, ok)
			assert.Equal(t, "123", claims.Subject)
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockValidator.AssertExpectations(t)
	})

	t.Run("token with custom claims when only standard claims expected", func(t *testing.T) {
		mockValidator := validation.NewMockTokenValidator(t)

		// Create token with custom claims
		validToken, err := jwt.CreateToken(privKey, "test.com", "123", jwt.PurposeLogin, time.Hour,
			jwt.WithClaims(&CustomClaims{
				RegisteredClaims: &gjwt.RegisteredClaims{},
				Role:             "admin",
			}),
		)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)

		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", validToken, jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(baseClaims, nil, nil) // Validator should ignore custom claims

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.PurposeLogin,
			ExpectedClaims: nil, // No expected claims specified
		})

		rr := httptest.NewRecorder()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Should only get base claims
			claims, ok := auth.GetClaims[*gjwt.RegisteredClaims](r.Context())
			assert.True(t, ok)
			assert.Equal(t, "123", claims.Subject)

			// Should not get custom claims
			_, ok = auth.GetClaims[*CustomClaims](r.Context())
			assert.False(t, ok)
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockValidator.AssertExpectations(t)
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
		// Setup mock config expectations
		mockConfig.On("GetPrivateKey").Return(privKey).Maybe()
		mockConfig.On("GetAuthTokenName").Return("auth_token").Maybe()

		// Setup mock config expectations
		mockConfig.On("GetPrivateKey").Return(privKey).Maybe()
		mockConfig.On("GetAuthCookieName").Return("auth_cookie").Maybe()
		mockConfig.On("GetAuthTokenName").Return("auth_token").Maybe()

		// Setup validator mock with correct claims type
		mockValidator.On("ValidateWithClaims", validToken, jwt.PurposeLogin, &CustomClaims{}).
			Return(baseClaims, customClaims, nil).Once()

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.PurposeLogin,
			Options:        jwt.Options(jwt.WithClaims(&CustomClaims{})),
			ExpectedClaims: &CustomClaims{},
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

		// Setup fresh expectations with correct claims type
		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", validToken, jwt.PurposeLogin, &CustomClaims{}).
			Return(baseClaims, &gjwt.RegisteredClaims{}, nil)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.PurposeLogin,
			Options:        jwt.Options(jwt.WithClaims(&CustomClaims{})),
			ExpectedClaims: &CustomClaims{},
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

		// Setup mock config expectations
		mockConfig.On("GetPrivateKey").Return(ed25519.PrivateKey{}).Maybe()
		mockConfig.On("GetAuthTokenName").Return("auth_token").Maybe()

		// Setup validator mock
		// Setup mock config expectations
		mockConfig.On("GetPrivateKey").Return(ed25519.PrivateKey{}).Maybe()
		mockConfig.On("GetAuthCookieName").Return("auth_cookie").Maybe()
		mockConfig.On("GetAuthTokenName").Return("auth_token").Maybe()

		// Setup validator mock
		// Setup mock to expect CustomClaims type
		mockValidator.On("ValidateWithClaims", "invalid.token", jwt.PurposeLogin, &CustomClaims{}).
			Return(nil, nil, jwt.ErrJWTInvalid)

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.PurposeLogin,
			Options:        jwt.Options(jwt.WithClaims(&CustomClaims{})),
			ExpectedClaims: &CustomClaims{},
		})

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("token with malformed claims", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer malformed.token")

		// Setup mock to expect CustomClaims type
		mockValidator.On("ValidateWithClaims", "malformed.token", jwt.PurposeLogin, &CustomClaims{}).
			Return(nil, nil, errors.New("malformed claims")).Once()

		middleware := AuthMiddleware(AuthMiddlewareOptions{
			Config:         mockConfig,
			Validator:      mockValidator,
			Purpose:        jwt.PurposeLogin,
			Options:        jwt.Options(jwt.WithClaims(&CustomClaims{})),
			ExpectedClaims: &CustomClaims{},
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
