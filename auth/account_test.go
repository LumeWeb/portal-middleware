package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.lumeweb.com/portal-middleware/context"
	authmocks "go.lumeweb.com/portal-middleware/mocks/auth"
)

func TestAccountVerifiedMiddleware(t *testing.T) {
	mockChecker := authmocks.NewMockUserChecker(t)
	middleware := AccountVerified(mockChecker)

	t.Run("verified user", func(t *testing.T) {
		mockChecker.On("IsAccountVerified", uint(1)).Return(true, nil)

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(1)))
		w := httptest.NewRecorder()

		middleware(testHandler).ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("unverified user", func(t *testing.T) {
		mockChecker.On("IsAccountVerified", uint(2)).Return(false, nil)

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(2)))
		w := httptest.NewRecorder()

		middleware(testHandler).ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("no user in context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		middleware(testHandler).ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("service error", func(t *testing.T) {
		mockChecker.On("IsAccountVerified", uint(3)).Return(false, assert.AnError)

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(3)))
		w := httptest.NewRecorder()

		middleware(testHandler).ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
