package middleware

import (
	"context"
	"testing"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mo "go.lumeweb.com/portal-middleware/context"
)

func TestGetUserFromContext(t *testing.T) {
	t.Run("valid user ID in context", func(t *testing.T) {
		// Create context with valid user ID
		ctx := context.WithValue(context.Background(), mo.UserIDKey, uint(123))
		
		userID, err := GetUserFromContext(ctx)
		
		require.NoError(t, err, "Should not return error for valid context")
		assert.Equal(t, uint(123), userID, "Should return correct user ID")
	})

	t.Run("no user ID in context", func(t *testing.T) {
		// Create empty context
		ctx := context.Background()
		
		_, err := GetUserFromContext(ctx)
		
		assert.Error(t, err, "Should return error when no user ID in context")
		assert.Contains(t, err.Error(), "user not found in context", "Error message should indicate missing user")
	})

	t.Run("invalid user ID type in context", func(t *testing.T) {
		// Create context with invalid user ID type
		ctx := context.WithValue(context.Background(), mo.UserIDKey, "invalid-type")
		
		_, err := GetUserFromContext(ctx)
		
		assert.Error(t, err, "Should return error for invalid user ID type")
		assert.Contains(t, err.Error(), "user context invalid", "Error message should indicate invalid context")
	})
}
