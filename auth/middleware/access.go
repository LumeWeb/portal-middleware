package middleware

import (
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/context"
)

// AccessMiddleware creates Echo middleware for role-based access control.
// Verifies both user existence and access permissions before allowing request progression.
// Chain with AuthMiddleware to ensure user context is available.
func AccessMiddleware(checker auth.UserChecker, accessChecker auth.AccessChecker) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			userID, err := mcontext.GetUserID(c)
			if err != nil {
				return echo.ErrUnauthorized
			}

			exists, err := checker.AccountExists(r.Context(), userID)
			if err != nil || !exists {
				return echo.ErrUnauthorized
			}

			host := r.Host
			if host == "" {
				host = "localhost" // default if no host header
			}
			ok, err := accessChecker.CheckAccess(r.Context(), userID, host, c.Path(), r.Method)
			if err != nil {
				return echo.ErrInternalServerError
			}
			if !ok {
				return echo.ErrUnauthorized
			}

			return next(c)
		}
	}
}
