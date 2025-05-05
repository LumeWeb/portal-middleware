package middleware

import (
	"context"
	"crypto/ed25519"
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
	cfg := ctx.Config().Config()
	cfg.Core.Domain = "test.example.com"
	_, privKey, _ := ed25519.GenerateKey(nil)
	cfg.Core.Identity.PrivateKey = privKey

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
		middleware := AuthMiddleware(ctx, "test-purpose", WithEmptyAllowed(true))
		
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
		middleware := AuthMiddleware(ctx, "test-purpose", WithExpiredAllowed(true))
		
		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
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
	})
}

// Helper to create test tokens
func createTestToken(t *testing.T, ctx core.Context, subject string, purpose string, expiresIn ...time.Duration) string {
	config := adapter.NewFromCore(ctx)
	expiry := time.Hour
	if len(expiresIn) > 0 {
		expiry = expiresIn[0]
	}

	token, err := middleware.CreateToken(
		config.GetPrivateKey(),
		config.GetDomain(),
		subject,
		middleware.Purpose(purpose),
		expiry,
	)
	require.NoError(t, err)
	return token
}
