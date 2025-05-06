# Portal Middleware

[![Go Reference](https://pkg.go.dev/badge/go.lumeweb.com/portal-middleware.svg)](https://pkg.go.dev/go.lumeweb.com/portal-middleware)

Secure middleware package for Go web applications providing authentication, authorization, and API management features.

## Features

- JWT-based authentication with Ed25519 signatures
- Role-Based Access Control (RBAC) with path pattern matching  
- CORS configuration with security best practices
- Swagger/OpenAPI 3.0 documentation support
- TUS protocol v1.0.0 extensions for resumable uploads
- Account verification workflows
- Context-aware request processing
- Type-safe custom claims handling

## Package Structure

```
/auth
  /adapter      # Core service adapters
  /jwt          # JWT token utilities  
  /middleware   # HTTP middleware implementations
  /validation   # Token validation logic
/cors           # CORS middleware  
/swagger        # OpenAPI documentation
/tus            # File upload protocol
/util           # Helper utilities
```

## Installation

```bash
go get go.lumeweb.com/portal-middleware
```

## Quick Start

```go
package main

import (
	"net/http"
	
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/middleware"
	"go.lumeweb.com/portal-middleware/cors"
	"go.lumeweb.com/portal-middleware/swagger"
	"go.lumeweb.com/portal-middleware/util"
	"go.lumeweb.com/portal/core"
)

func main() {
	router := http.NewServeMux()
	coreCtx := core.GetContext()
	
	// Initialize configuration
	config := adapter.NewFromCore(coreCtx)
	
	// Create middleware chain
	chain := util.New(router).
		WithAuth(middleware.AuthMiddlewareOptions{
			Config:  config,
			Purpose: "api-access",
		}).
		WithCORS(cors.Config{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET", "POST"},
			MaxAge:         3600,
		})
	
	// Add Swagger documentation
	spec := loadOpenAPISpec() // Implement your spec loader
	swaggerHandler := swagger.NewHandler(spec, "/docs")
	router.Handle("/docs/", swaggerHandler)
	
	http.ListenAndServe(":8080", chain.Then())
}
```

## JWT Token Handling

### Token Validation API

```go
// Decode token without validation
claims, err := jwt.DecodeToken(tokenString, &CustomClaims{})
if err != nil {
    // handle error
}

// Verify standard claims
err = jwt.VerifyClaims(claims, "example.com", jwt.PurposeLogin)
if err != nil {
    // handle validation error
}

// Combined decode and verify
claims, err := jwt.DecodeAndVerify(
    tokenString,
    &CustomClaims{},
    "example.com", 
    jwt.PurposeLogin,
)

// Validate custom claims structure
err = jwt.ValidateClaimsStructure(rawClaims, &CustomClaims{})

// Map raw claims to struct
err = jwt.MapClaims(rawClaims, &CustomClaims{})
```

### Adapter Layer

The adapter package provides integration between core services and middleware:

```go
// Get config from core context
config := adapter.NewFromCore(coreCtx)

// Create service adapters 
userChecker := adapter.NewUserCheckerFromCore(coreCtx)
accessChecker := adapter.NewAccessCheckerFromCore(coreCtx)

// Multi-domain cookie handling  
cookieSetter := adapter.MultiCoreSetterFromCore(coreCtx)
```

Key adapter interfaces:

- `ConfigProvider`: Provides JWT signing keys and domain config
- `APIProvider`: Manages API domain information
- `CookieSetter`: Handles JWT cookie operations
- `UserChecker`: Verifies user account status
- `AccessChecker`: Checks resource permissions

## Security Features

- Token expiration enforcement with optional refresh
- SameSite cookie policies to prevent CSRF  
- Type-safe custom claims handling
- Purpose-specific claim validation
- Contextual user ID injection
- Automatic token revocation detection
- Separate token creation and transmission concerns

## Testing

Run the test suite with:

```bash
go test -v -cover ./...
```

## Documentation

Full package documentation available on [pkg.go.dev](https://pkg.go.dev/go.lumeweb.com/portal-middleware)

## Contributing

Contributions welcome! Please follow:
1. Fork the repository  
2. Create a feature branch
3. Submit a pull request

## License

MIT
