package middleware

import (
	"context"
	"errors"
	"go.lumeweb.com/portal-middleware/context"
)

// GetUserFromContext extracts user ID from the context
func GetUserFromContext(ctx context.Context) (uint, error) {
	val := ctx.Value(mcontext.UserIDKey)
	if val == nil {
		return 0, errors.New("user not found in context")
	}

	userID, ok := val.(uint)
	if !ok {
		return 0, errors.New("user context invalid")
	}

	return userID, nil
}
