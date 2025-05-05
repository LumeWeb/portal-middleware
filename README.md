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

## Custom Claims Example

```go
type CustomClaims struct {
	*gjwt.RegisteredClaims
	Role string `json:"role"`
}

// Create token
token, err := jwt.CreateToken(
	privateKey,
	"example.com", 
	"user123",
	jwt.PurposeLogin,
	time.Hour,
	jwt.WithClaims(&CustomClaims{Role: "admin"}),
)

// Retrieve in handler  
claims, ok := auth.GetClaims[*CustomClaims](r.Context())
if ok {
	log.Printf("User role: %s", claims.Role)
}
```

## Security Features

- Token expiration enforcement with optional refresh
- SameSite cookie policies to prevent CSRF  
- Type-safe custom claims handling
- Purpose-specific claim validation
- Contextual user ID injection
- Automatic token revocation detection

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
