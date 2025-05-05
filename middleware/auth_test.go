package middleware

import (
	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/auth/validation"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.sia.tech/coreutils/wallet"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mo "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestAuthMiddleware(t *testing.T) {
	// Setup test context with mock config
	ctx := coreTesting.NewTestContext(t)

	// Configure core context with test values

	cfg := ctx.Config()
	err := cfg.Update("core.domain", "test.example.com")
	if err != nil {
		t.Error(t)
	}
	err = cfg.Update("core.identity", wallet.NewSeedPhrase())
	if err != nil {
		t.Error(t)
	}

	t.Run("valid token", func(t *testing.T) {
		middleware := AuthMiddleware(ctx, "test-purpose")

		// Create test handler to verify context values
		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			// Verify user ID was set in context
			userID, err := mo.GetUserID(r.Context())
			assert.NoError(t, err)
			assert.Equal(t, uint(123), userID)

			w.WriteHeader(http.StatusOK)
		})

		// Create test request with valid token
		req := httptest.NewRequest("GET", "/", nil)
		token := createTestToken(t, ctx, "123", "test-purpose")
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("empty allowed", func(t *testing.T) {
		middleware := AuthMiddleware(ctx, "test-purpose", WithAuthEmptyAllowed(true))

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil) // No token
		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("expired allowed", func(t *testing.T) {
		// Create a mock validator that returns base claims for expired tokens
		mockValidator := validation.NewMockTokenValidator(t)
		mockValidator.On("ValidateWithClaims", mock.Anything, jwt.Purpose("test-purpose")).
			Return(&gjwt.RegisteredClaims{Subject: "123"}, nil, gjwt.ErrTokenExpired)

		middleware := AuthMiddleware(ctx, "test-purpose",
			WithAuthExpiredAllowed(true),
			WithAuthValidator(mockValidator), // Use our mock validator
		)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true

			// Verify user ID was set from the expired token
			userID, err := mcontext.GetUserID(r.Context())
			assert.NoError(t, err)
			assert.Equal(t, uint(123), userID)

			w.WriteHeader(http.StatusOK)
		})

		// Create expired token
		req := httptest.NewRequest("GET", "/", nil)
		token := createTestToken(t, ctx, "123", "test-purpose", -time.Hour) // Expired 1 hour ago
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		handler := middleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
		mockValidator.AssertExpectations(t)
	})
}

// Helper to create test tokens
func createTestToken(t *testing.T, ctx core.Context, subject string, purpose string, expiresIn ...time.Duration) string {
	config := adapter.NewFromCore(ctx)
	expiry := time.Hour
	if len(expiresIn) > 0 {
		expiry = expiresIn[0]
	}

	token, err := jwt.CreateToken(
		config.GetPrivateKey(),
		config.GetDomain(),
		subject,
		jwt.Purpose(purpose),
		expiry,
	)
	require.NoError(t, err)
	return token
}
