// Package swagger provides OpenAPI/Swagger documentation support for HTTP APIs.
package swagger

import (
	"embed"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-router"
	"io/fs"
	"net/http"
)

//go:embed embed
var swagfs embed.FS

// WireRouter wires swagger UI endpoints to an existing router.Router.
// It configures the UI to fetch the OpenAPI spec from the specified specPath.
//
// Parameters:
// - router: The router.Router to wire the Swagger UI handlers to
// - specPath: The URL path where the OpenAPI JSON spec is served (e.g., "/swagger.json")
// - uiPathPrefix: The URL path prefix where the Swagger UI will be served (e.g., "/swagger")
func WireRouter(_router router.Router, specPath string, uiPathPrefix string) error {
	if specPath == "" {
		return fmt.Errorf("specPath cannot be empty")
	}
	if uiPathPrefix == "" || uiPathPrefix[0] != '/' {
		return fmt.Errorf("uiPathPrefix must start with '/' and cannot be empty")
	}

	swaggerFiles, err := fs.Sub(swagfs, "embed")
	if err != nil {
		return fmt.Errorf("failed to get embedded swagger files: %w", err)
	}

	// Create file server handler
	fileServer := http.FileServer(http.FS(swaggerFiles))

	// Register routes with router
	router.GetRouter(_router).GET(uiPathPrefix, func(c echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, uiPathPrefix+"/")
	})

	// Serve static files under the prefix
	router.GetRouter(_router).GET(uiPathPrefix+"/*", echo.WrapHandler(http.StripPrefix(uiPathPrefix, fileServer)))

	// Note: This package no longer serves the spec itself.
	// The spec is expected to be served by another handler,
	// typically generated dynamically by gswagger.
	// The swagger-initializer.js file (embedded) is modified
	// by the generate.go script to point to "/swagger.json" by default.
	// If a different specPath is needed, the generate.go script
	// or the swagger-initializer.js file might need adjustment,
	// or a custom initializer could be served.
	// For this integration, we assume the gswagger spec is at "/swagger.json".

	return nil
}

// NewStandaloneHandler creates an HTTP handler that serves the Swagger UI.
func NewStandaloneHandler(specPath string, uiPathPrefix string) (router.Router, error) {
	_router, err := router.NewRouter(router.APIInfo().Title("Swagger").Version("0.1.0"))
	if err != nil {
		return nil, err
	}
	if err = WireRouter(_router, specPath, uiPathPrefix); err != nil {
		return nil, err
	}
	return _router, nil
}

// LoadAndValidateSpec is deprecated. Spec loading and validation
// should be handled by the spec generation mechanism (e.g., gswagger).
//
// Deprecated: Use spec generation libraries like gswagger instead.
func LoadAndValidateSpec(spec []byte) ([]byte, error) {
	// This function is no longer needed for the primary integration path
	// where gswagger generates the spec. Keeping it for potential
	// backward compatibility or alternative use cases, but marked deprecated.
	// Original implementation remains the same.
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		return nil, err
	}

	if err := doc.Validate(loader.Context); err != nil {
		return nil, err
	}

	return doc.MarshalJSON()
}

// NewHandler is deprecated.
func NewHandler(spec []byte, router router.Router) error {
	_, err := LoadAndValidateSpec(spec)
	if err != nil {
		return err
	}
	return WireRouter(router, "/swagger.json", "/swagger")
}
