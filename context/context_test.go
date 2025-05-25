package mcontext

import (
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUserID(t *testing.T) {
	t.Run("valid user ID in echo context", func(t *testing.T) {
		e := echo.New()
		c := e.NewContext(nil, nil)
		c.Set(string(UserIDKey), uint(123))

		userID, err := GetUserID(c)
		require.NoError(t, err)
		assert.Equal(t, uint(123), userID)
	})

	t.Run("invalid user ID type", func(t *testing.T) {
		e := echo.New()
		c := e.NewContext(nil, nil)
		c.Set(string(UserIDKey), "invalid")

		_, err := GetUserID(c)
		assert.ErrorIs(t, err, ErrUserContextInvalid)
	})

	t.Run("no user ID in context", func(t *testing.T) {
		e := echo.New()
		c := e.NewContext(nil, nil)

		_, err := GetUserID(c)
		assert.ErrorIs(t, err, ErrUserContextInvalid)
	})
}

func TestGetAuthToken(t *testing.T) {
	t.Run("valid auth token in echo context", func(t *testing.T) {
		e := echo.New()
		c := e.NewContext(nil, nil)
		c.Set(string(AuthTokenKey), "test-token")

		token, err := GetAuthToken(c)
		require.NoError(t, err)
		assert.Equal(t, "test-token", token)
	})

	t.Run("invalid auth token type", func(t *testing.T) {
		e := echo.New()
		c := e.NewContext(nil, nil)
		c.Set(string(AuthTokenKey), 123)

		_, err := GetAuthToken(c)
		assert.ErrorIs(t, err, ErrAuthTokenContextInvalid)
	})

	t.Run("no auth token in context", func(t *testing.T) {
		e := echo.New()
		c := e.NewContext(nil, nil)

		_, err := GetAuthToken(c)
		assert.ErrorIs(t, err, ErrAuthTokenContextInvalid)
	})
}
