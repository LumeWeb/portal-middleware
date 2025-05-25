package middleware

import (
	"go.lumeweb.com/portal-middleware/auth"
	"net/http"

	"go.lumeweb.com/portal-middleware/context"
)

// AccessMiddleware creates HTTP middleware for role-based access control.
// Verifies both user existence and access permissions before allowing request progression.
// Chain with AuthMiddleware to ensure user context is available.
// Returns 401 Unauthorized for invalid users, 403 Forbidden for access denials.
func AccessMiddleware(checker auth.UserChecker, accessChecker auth.AccessChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			deny := func() {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}

			userID, err := mcontext.GetUserID(r.Context())
			if err != nil {
				deny()
				return
			}

			exists, err := checker.AccountExists(userID)
			if err != nil || !exists {
				deny()
				return
			}

			host := r.Host
			if host == "" {
				host = "localhost" // default if no host header
			}
			ok, err := accessChecker.CheckAccess(userID, host, r.URL.Path, r.Method)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if !ok {
				deny()
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
