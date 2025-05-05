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
//   - Integration with ConfigProvider for security settings
//   - Example:
//     authMiddleware := middleware.AuthMiddleware(middleware.AuthMiddlewareOptions{
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
//     accessMiddleware := middleware.AccessMiddleware(userChecker, accessChecker)
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
//     verifiedMiddleware := middleware.AccountVerifiedMiddleware(userChecker)
//
// # Package Structure
//
// - /auth: Core authentication types and interfaces
// - /auth/adapter: Adapters for core services
// - /auth/jwt: JWT token handling utilities
// - /auth/middleware: HTTP middleware implementations
// - /auth/validation: Token validation logic
// - /cors: CORS middleware
// - /swagger: OpenAPI documentation support
// - /tus: File upload protocol support
// - /util: Helper utilities
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
// Create token with custom claims:
//
//	token, err := jwt.CreateToken(privateKey, "domain.com", "user123", 
//		jwt.PurposeLogin, time.Hour,
//		jwt.WithClaims(&CustomClaims{}),
//		jwt.WithModifiers(func(claims gjwt.Claims) {
//			if cc, ok := claims.(*CustomClaims); ok {
//				cc.Role = "admin"
//			}
//		}))
//
// Retrieve in handler:
//
//	claims, ok := auth.GetClaims[*CustomClaims](r.Context())
//	if ok {
//		log.Printf("User role: %s", claims.Role)
//	}
//
// # Example Application Setup
//
// Typical middleware chain configuration:
//
//	router := http.NewServeMux()
//	config := adapter.NewFromCore(coreCtx) 
//
//	// Build processing chain
//	chain := util.New(router).
//		WithAuth(middleware.AuthMiddlewareOptions{
//			Config: config,
//			Purpose: "session",
//		}).
//		WithCORS(cors.Config{
//			AllowedOrigins: []string{"https://app.domain.com"},
//			AllowedHeaders: []string{"Authorization"},
//		})
//
//	// Add Swagger documentation
//	spec := loadOpenAPISpec() // Implement your spec loader
//	swaggerHandler := swagger.NewHandler(spec, "/docs")
//	router.Handle("/docs/", swaggerHandler)
//
//	http.ListenAndServe(":8080", chain.Then())
//
// # Security Architecture
//
// - JWT tokens signed with Ed25519 for performance and security
// - Strict same-site cookie policies
// - Type-safe custom claims handling
// - Audience claim validation for token purpose isolation
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
