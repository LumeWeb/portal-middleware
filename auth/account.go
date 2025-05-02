package auth

import (
	"net/http"

	"go.lumeweb.com/portal-middleware/context"
)

// AccountVerified creates HTTP middleware that requires verified user accounts.
// Checks the verification status of the user in the request context.
// Returns 403 Forbidden if account is not verified, 500 for verification errors.
// Must be used after AuthMiddleware to ensure user context exists.
func AccountVerified(checker UserChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, err := mcontext.GetUserID(r.Context())
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			verified, err := checker.IsAccountVerified(userID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if !verified {
				http.Error(w, "Account not verified", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
