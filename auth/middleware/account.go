package middleware

import (
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/context"
)

// AccountVerified creates Echo middleware that requires verified user accounts.
// Checks the verification status of the user in the request context.
// Must be used after AuthMiddleware to ensure user context exists.
func AccountVerified(checker auth.UserChecker) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID, err := mcontext.GetUserID(c)
			if err != nil {
				return echo.ErrUnauthorized
			}

			verified, err := checker.IsAccountVerified(c.Request().Context(), userID)
			if err != nil {
				return echo.ErrInternalServerError
			}

			if !verified {
				return echo.ErrForbidden
			}

			return next(c)
		}
	}
}
