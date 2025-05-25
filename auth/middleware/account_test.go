package middleware

import (
	"context"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.lumeweb.com/portal-middleware/context"
)

func TestAccountVerifiedMiddleware(t *testing.T) {
	mockChecker := auth.NewMockUserChecker(t)
	middleware := AccountVerified(mockChecker)

	t.Run("verified user", func(t *testing.T) {
		mockChecker.On("IsAccountVerified", uint(1)).Return(true, nil)

		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.UserIDKey, uint(1)))
		w := httptest.NewRecorder()

		e := echo.New()
		c := e.NewContext(req, w)
		c.Set(string(mcontext.UserIDKey), uint(1))

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("unverified user", func(t *testing.T) {
		mockChecker.On("IsAccountVerified", uint(2)).Return(false, nil)

		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set(string(mcontext.UserIDKey), uint(2))

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		assert.Equal(t, echo.ErrForbidden, err)
	})

	t.Run("no user in context", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("service error", func(t *testing.T) {
		mockChecker.On("IsAccountVerified", uint(3)).Return(false, assert.AnError)

		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set(string(mcontext.UserIDKey), uint(3))

		err := middleware(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)
		assert.Equal(t, echo.ErrInternalServerError, err)
	})
}
