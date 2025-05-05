// Package middleware provides comprehensive authentication, authorization, and HTTP utilities
// for building secure web applications. Key features include:
//
// - JWT-based authentication with Ed25519 signatures
// - Role-Based Access Control (RBAC) and resource permissions
// - CORS configuration with fine-grained controls
// - Swagger/OpenAPI 3.0 documentation support
// - Account verification workflows
// - Tus protocol v1.0.0 extensions for resumable uploads
// - Context-aware request processing
//
// The package integrates with the portal ecosystem while remaining framework-agnostic
// for standalone use.
//
// # Core Components
//
// 1. Authentication Middleware:
//   - Token creation/validation with purpose-specific claims
//   - Cookie-based session management with automatic refresh
//   - Multiple authentication sources (header, cookie, query param)
//   - Token revocation and expiration handling
//   - Example:
//     authMiddleware := auth.AuthMiddleware(auth.AuthMiddlewareOptions{
//         Config: config,       // Required
//         Purpose: "api-access",// Required
//         ExpiredAllowed: false,
//     })
//
// 2. Authorization Middleware:
//   - Hierarchical role-based access control
//   - Resource path pattern matching
//   - Integration with user directory services
//   - Example:
//     accessMiddleware := auth.AccessMiddleware(
//     userChecker,
//     accessChecker,
//     )
//
// 3. Security Utilities:
//   - CORS with safe defaults and custom rules
//   - CSRF protection via same-site cookies
//   - Secure context propagation for user IDs and tokens
//   - Example CORS config:
//     cors.New(cors.Config{
//     AllowedOrigins: []string{"https://trusted.com"},
//     AllowedMethods: []string{"GET", "POST"},
//     MaxAge: 3600,
//     })
//
// 4. Account Management:
//   - Email verification workflows
//   - Account status checks
//   - Example:
//     verifiedMiddleware := middleware.AccountVerifiedMiddleware(ctx)
//
// # Custom Claims Example
//
// Define custom claims type:
//
//	type CustomClaims struct {
//		*gjwt.RegisteredClaims
//		Role string `json:"role"`
//	}
//
// Register claims type during initialization:
//
//	auth.RegisterClaimsType("api-access", func() gjwt.Claims { return &CustomClaims{} })
//
// Create token with custom claims:
//
//	token, err := auth.CreateJWTToken(privateKey, "domain.com", "user123", 
//		auth.JWTPurposeLogin, time.Hour,
//		func(claims gjwt.Claims) {
//			if cc, ok := claims.(*CustomClaims); ok {
//				cc.Role = "admin"
//			}
//		})
//
// Retrieve in handler:
//
//	claims, ok := auth.GetClaims[CustomClaims](ctx, "api-access")
//	if ok {
//		log.Printf("User role: %s", claims.Role)
//	}
//
// # GetClaims Function
//
// GetClaims retrieves custom claims from context by purpose and type.
// Example handler usage:
//
//	func protectedHandler(w http.ResponseWriter, r *http.Request) {
//		claims, ok := auth.GetClaims[CustomClaims](r.Context(), "api-access")
//		if !ok {
//			http.Error(w, "Invalid claims", http.StatusUnauthorized)
//			return
//		}
//		// Use claims.CustomField values...
//	}
//
// # Example Application Setup
//
// Typical middleware chain configuration:
//
//	router := http.NewServeMux()
//	config := auth.NewConfigProvider()
//
//	// Build processing chain
//	chain := util.New(router).
//	  WithAuth(auth.AuthMiddlewareOptions{
//	    Config: config,
//	    Purpose: "session",
//	  }).
//	  WithCORS(cors.Config{
//	    AllowedOrigins: []string{"https://app.domain.com"},
//	    AllowedHeaders: []string{"Authorization"},
//	  }).
//	  WithAccessControl(accessRules)
//
//	// Add Swagger documentation
//	swaggerHandler := swagger.NewHandler(specJSON, "/docs")
//	router.Handle("/docs/", swaggerHandler)
//
//	http.ListenAndServe(":8080", chain)
//
// # Configuration Management
//
// Implement ConfigProvider to supply:
// - ed25519.PrivateKey for JWT signing
// - Domain names for token issuer validation
// - Cookie security settings (SameSite, HttpOnly flags)
// - API endpoint configurations for multi-domain deployments
//
// # Security Architecture
//
// - JWT tokens signed with Ed25519 for performance and security
// - Strict same-site cookie policies by default
// - Audience claims validation for token purpose isolation
// - Contextual user ID injection with type safety
// - Automatic token revocation detection
// - HSTS-ready security headers
//
// # Error Handling
//
// Standard HTTP status codes with structured error responses:
// - 401 Unauthorized: Authentication failures
// - 403 Forbidden: Authorization/verification failures
// - 500 Internal Server Error: Configuration/validation errors
//
// # Testing & Validation
//
// Package includes:
//   - Mock implementations for all interfaces
//   - Integration test helpers
//   - 100% coverage of security-critical paths
//   - Example:
//     go test -v -cover ./...
//
// # Maintenance & Extensibility
//
// - Semantic versioning with Go module support
// - Generated documentation via godoc
// - Plugin architecture for custom validators
// - Audit logging integration points
package middleware
