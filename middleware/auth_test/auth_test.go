package middleware_test

import (
	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
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

	middleware "go.lumeweb.com/portal-middleware/middleware"
	mo "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestAuthMiddleware(t *testing.T) {
	// Setup test context with mock config
	ctx, err := coreTesting.NewTestContext(t)
	require.NoError(t, err)

	// Configure core context with test values

	cfg := ctx.Config()
	err = cfg.Set(ctx, "core.domain", "test.example.com")
	require.NoError(t, err, "Failed to set test domain")
	err = cfg.Set(ctx, "core.identity", wallet.NewSeedPhrase())
	require.NoError(t, err, "Failed to set test identity")

	t.Run("valid token", func(t *testing.T) {
		mw := middleware.AuthMiddleware(ctx, middleware.WithAuthPurpose(jwt.Purpose("test-purpose")))

		// Create test handler to verify context values
		handlerCalled := false
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		token := createTestToken(t, ctx, "123", "test-purpose")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handlerCalled = false
		testHandler := func(c echo.Context) error {
			handlerCalled = true

			// Verify user ID was set in context
			userID, err := mo.GetUserID(c)
			assert.NoError(t, err)
			assert.Equal(t, uint(123), userID)

			return c.NoContent(http.StatusOK)
		}

		// Apply middleware and call handler
		err = mw(testHandler)(c)
		assert.NoError(t, err)
		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("empty allowed", func(t *testing.T) {
		mw := middleware.AuthMiddleware(ctx, middleware.WithAuthPurpose(jwt.Purpose("test-purpose")), middleware.WithAuthEmptyAllowed(true))

		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil) // No token
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handlerCalled := false
		testHandler := func(c echo.Context) error {
			handlerCalled = true
			return c.NoContent(http.StatusOK)
		}

		err = mw(testHandler)(c)
		assert.NoError(t, err)
		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("expired allowed", func(t *testing.T) {
		// Create a mock validator that returns base claims for expired tokens
		mockValidator := validation.NewMockTokenValidator(t)

		mw := middleware.AuthMiddleware(ctx, 
			middleware.WithAuthPurpose(jwt.Purpose("test-purpose")),
			middleware.WithAuthExpiredAllowed(true),
			middleware.WithAuthValidator(mockValidator), // Use our mock validator
		)

		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		token := createTestToken(t, ctx, "123", "test-purpose", -time.Hour) // Expired 1 hour ago
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		claim := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", token, jwt.Purpose("test-purpose"), mock.Anything).
			Return(claim, claim, nil)

		handlerCalled := false
		testHandler := func(c echo.Context) error {
			handlerCalled = true

			// Verify user ID was set from the expired token
			userID, err := mcontext.GetUserID(c)
			assert.NoError(t, err)
			assert.Equal(t, uint(123), userID)

			return c.NoContent(http.StatusOK)
		}

		err = mw(testHandler)(c)
		assert.NoError(t, err)
		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rec.Code)
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
