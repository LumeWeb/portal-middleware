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
// # JWT Token API
//
// The package provides a complete JWT implementation with these core operations:
//
// 1. Token Creation:
//    - CreateToken(): Generates new tokens with custom claims
//    - CreateAndSend(): Combines creation and HTTP transmission
//    - RefreshToken(): Creates new token with same claims but fresh expiration
//
// 2. Token Transmission:
//    - Send(): Sets token in response cookies and headers
//
// 3. Token Validation:
//    - DecodeToken(): Parses token without validation, returning raw claims
//    - VerifyClaims(): Validates standard claims (issuer, audience, expiration)
//    - DecodeAndVerify(): Combines decoding and validation in one operation
//    - ValidateClaimsStructure(): Ensures custom claims match expected structure
//    - MapClaims(): Converts raw claims to typed structs
//
// Example usage:
//
//	// Decode and verify in separate steps
//	claims, err := jwt.DecodeToken(tokenString, &CustomClaims{})
//	if err != nil {
//		// handle error
//	}
//	err = jwt.VerifyClaims(claims, "example.com", jwt.PurposeLogin)
//
//	// Or combined
//	claims, err := jwt.DecodeAndVerify(tokenString, &CustomClaims{}, "example.com", jwt.PurposeLogin)
//
// # Adapter Layer
//
// The adapter package provides integration between core services and middleware:
//
// - ConfigProvider: Bridges core configuration to auth requirements
// - APIProvider: Manages API domain information  
// - CookieSetter: Handles JWT cookie operations across domains
// - ServiceAdapters:
//   - coreUserChecker: Adapts core.UserService to auth.UserChecker
//   - coreAccessChecker: Adapts core.AccessService to auth.AccessChecker
//
// Adapters enable the middleware to work with core services while maintaining
// separation of concerns. Key adapter functions:
//
// - NewFromCore(): Creates ConfigProvider from core context
// - NewUserCheckerFromCore(): Creates UserChecker from core services
// - NewAccessCheckerFromCore(): Creates AccessChecker from core services
// - MultiCoreSetterFromCore(): Creates multi-domain CookieSetter
//
// # Middleware API
//
// The package provides these middleware components:
//
// - AuthMiddleware: JWT authentication with purpose validation
// - AccessMiddleware: Role-based access control  
// - AccountVerified: Requires verified user accounts
// - CORS: Cross-Origin Resource Sharing configuration
//
// Example middleware chain:
//
//	chain := util.New(router).
//		WithAuth(AuthMiddlewareOptions{
//			Config: config,
//			Purpose: "api-access",
//		}).
//		WithAccess(userChecker, accessChecker).
//		WithCORS(cors.Config{...})
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
// # Security Architecture
//
// - JWT tokens signed with Ed25519 for performance and security
// - Strict same-site cookie policies
// - Type-safe custom claims handling
// - Audience claim validation for token purpose isolation  
// - Contextual user ID injection with type safety
// - Automatic token revocation detection
// - HSTS-ready security headers
// - Separate token creation and transmission concerns
package middleware
