# Portal Middleware

[![Go Reference](https://pkg.go.dev/badge/go.lumeweb.com/portal-middleware.svg)](https://pkg.go.dev/go.lumeweb.com/portal-middleware)

Secure middleware package for Go web applications providing authentication, authorization, and API management features.

## Features

- JWT-based authentication with Ed25519 signatures
- Role-Based Access Control (RBAC)
- CORS configuration with security best practices
- Swagger/OpenAPI 3.0 documentation support
- TUS protocol v1.0.0 extensions for resumable uploads
- Account verification workflows
- Context-aware request processing

## Installation

```bash
go get go.lumeweb.com/portal-middleware
```

## Quick Start

```go
package main

import (
	"net/http"
	
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/cors"
	"go.lumeweb.com/portal-middleware/swagger"
	"go.lumeweb.com/portal-middleware/util"
)

func main() {
	router := http.NewServeMux()
	
	// Initialize core configuration
	config := auth.NewConfigProvider() 
	
	// Create middleware chain
	chain := util.New(router).
		WithAuth(auth.AuthMiddlewareOptions{
			Config:  config,
			Purpose: "api-access",  // Required for claims validation
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

## Configuration

Implement the `ConfigProvider` interface to provide:
- Ed25519 private key for JWT signing
- Domain names for token validation
- Cookie security settings
- API endpoint configurations

```go
type MyConfig struct {
	privateKey ed25519.PrivateKey
	domain     string
}

func (c *MyConfig) GetPrivateKey() ed25519.PrivateKey {
	return c.privateKey
}

func (c *MyConfig) GetDomain() string {
	return c.domain
}

// Implement remaining interface methods...
```

## Security Features

- Token expiration enforcement
- SameSite cookie policies
- Type-safe custom claims handling
- Purpose-specific claim validation
- Audience claim validation
- CSRF protection headers
- Automatic token revocation
- Mandatory configuration checks

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
