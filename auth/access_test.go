package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.lumeweb.com/portal-middleware/context"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"
)

func TestAccessMiddleware(t *testing.T) {
	mockUserChecker := NewMockUserChecker(t)
	mockAccessChecker := coreMocks.NewMockAccessService(t)
	middleware := AccessMiddleware(mockUserChecker, mockAccessChecker)

	t.Run("access granted", func(t *testing.T) {
		mockUserChecker.On("AccountExists", uint(1)).Return(true, nil)
		mockAccessChecker.On("CheckAccess", uint(1), "example.com", "/", "GET").Return(true, nil)

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(1)))
		w := httptest.NewRecorder()

		middleware(testHandler).ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("access denied", func(t *testing.T) {
		mockUserChecker.On("AccountExists", uint(2)).Return(true, nil)
		mockAccessChecker.On("CheckAccess", uint(2), "example.com", "/admin", "GET").Return(false, nil)

		req := httptest.NewRequest("GET", "http://example.com/admin", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(2)))
		w := httptest.NewRecorder()

		middleware(testHandler).ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("user not found", func(t *testing.T) {
		mockUserChecker.On("AccountExists", uint(3)).Return(false, nil)

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(3)))
		w := httptest.NewRecorder()

		middleware(testHandler).ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("access check error", func(t *testing.T) {
		mockUserChecker.On("AccountExists", uint(4)).Return(true, nil)
		mockAccessChecker.On("CheckAccess", uint(4), "example.com", "/api", "GET").Return(false, assert.AnError)

		req := httptest.NewRequest("GET", "http://example.com/api", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(4)))
		w := httptest.NewRecorder()

		middleware(testHandler).ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
