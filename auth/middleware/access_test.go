package middleware

import (
	"context"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.lumeweb.com/portal-middleware/context"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"
)

func setupAccessTest(t *testing.T) (*auth.MockUserChecker, *coreMocks.MockAccessService, echo.MiddlewareFunc) {
	mockUserChecker := auth.NewMockUserChecker(t)
	mockAccessChecker := coreMocks.NewMockAccessService(t)
	middleware := AccessMiddleware(mockUserChecker, mockAccessChecker)
	return mockUserChecker, mockAccessChecker, middleware
}

func TestAccessMiddleware(t *testing.T) {

	t.Run("access granted", func(t *testing.T) {
		mockUserChecker, mockAccessChecker, middleware := setupAccessTest(t)

		mockUserChecker.On("AccountExists", mock.Anything, uint(1)).Return(true, nil)
		mockAccessChecker.On("CheckAccess", mock.Anything, uint(1), "example.com", "/", "GET").Return(true, nil)

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(1)))
		w := httptest.NewRecorder()

		e := echo.New()
		e.GET("/", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
		c := e.NewContext(req, w)
		c.Set(string(mcontext.UserIDKey), uint(1))

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("access denied", func(t *testing.T) {
		mockUserChecker, mockAccessChecker, middleware := setupAccessTest(t)

		mockUserChecker.On("AccountExists", mock.Anything, uint(2)).Return(true, nil)
		mockAccessChecker.On("CheckAccess", mock.Anything, uint(2), "example.com", "/admin", "GET").Return(false, nil)

		req := httptest.NewRequest("GET", "http://example.com/admin", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(2)))
		w := httptest.NewRecorder()

		e := echo.New()
		e.GET("/admin", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
		c := e.NewContext(req, w)
		c.Set(string(mcontext.UserIDKey), uint(2))

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("user not found", func(t *testing.T) {
		mockUserChecker, _, middleware := setupAccessTest(t)

		mockUserChecker.On("AccountExists", mock.Anything, uint(3)).Return(false, nil)

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(3)))
		w := httptest.NewRecorder()

		e := echo.New()
		e.GET("/", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
		c := e.NewContext(req, w)
		c.Set(string(mcontext.UserIDKey), uint(3))

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("access check error", func(t *testing.T) {
		mockUserChecker, mockAccessChecker, middleware := setupAccessTest(t)

		mockUserChecker.On("AccountExists", mock.Anything, uint(4)).Return(true, nil)
		mockAccessChecker.On("CheckAccess", mock.Anything, uint(4), "example.com", "/api", "GET").Return(false, assert.AnError)

		req := httptest.NewRequest("GET", "http://example.com/api", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(4)))
		w := httptest.NewRecorder()

		e := echo.New()
		e.GET("/api", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
		c := e.NewContext(req, w)
		c.Set(string(mcontext.UserIDKey), uint(4))

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		assert.Equal(t, echo.ErrInternalServerError, err)
	})

	t.Run("strips port from host", func(t *testing.T) {
		mockUserChecker, mockAccessChecker, middleware := setupAccessTest(t)

		mockUserChecker.On("AccountExists", mock.Anything, uint(5)).Return(true, nil)
		// The host check should receive "example.com" without port, even though request has port
		mockAccessChecker.On("CheckAccess", mock.Anything, uint(5), "example.com", "/test", "GET").Return(true, nil)

		req := httptest.NewRequest("GET", "http://example.com:8080/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(5)))
		w := httptest.NewRecorder()

		e := echo.New()
		e.GET("/test", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
		c := e.NewContext(req, w)
		c.Set(string(mcontext.UserIDKey), uint(5))

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
