package auth

import (
	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth/jwt"
)

// JWTKeyLogger receives notifications whenever authentication middleware
// processes a JWT token, allowing plugins to record or audit token access.
// Implementations must not block or fail the request; the middleware
// recovers from panics raised inside RecordAccess and ignores them.
type JWTKeyLogger interface {
	// RecordAccess is invoked with the raw token, the purpose that was
	// attempted, the validated claims (nil when validation failed), and the
	// validation error (nil on success).
	RecordAccess(c echo.Context, token string, purpose jwt.Purpose, claims gjwt.Claims, err error)
}
