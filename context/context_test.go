package mcontext

import (
	"context"
	"testing"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUserID(t *testing.T) {
	t.Run("valid user ID in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserIDKey, uint(123))
		userID, err := GetUserID(ctx)
		require.NoError(t, err)
		assert.Equal(t, uint(123), userID)
	})

	t.Run("invalid user ID type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserIDKey, "invalid")
		_, err := GetUserID(ctx)
		assert.ErrorIs(t, err, ErrUserContextInvalid)
	})

	t.Run("no user ID in context", func(t *testing.T) {
		_, err := GetUserID(context.Background())
		assert.ErrorIs(t, err, ErrUserContextInvalid)
	})
}

func TestGetAuthToken(t *testing.T) {
	t.Run("valid auth token in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), AuthTokenKey, "test-token")
		token, err := GetAuthToken(ctx)
		require.NoError(t, err)
		assert.Equal(t, "test-token", token)
	})

	t.Run("invalid auth token type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), AuthTokenKey, 123)
		_, err := GetAuthToken(ctx)
		assert.ErrorIs(t, err, ErrAuthTokenContextInvalid)
	})

	t.Run("no auth token in context", func(t *testing.T) {
		_, err := GetAuthToken(context.Background())
		assert.ErrorIs(t, err, ErrAuthTokenContextInvalid)
	})
}
