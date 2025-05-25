// Package swagger provides OpenAPI/Swagger documentation support for HTTP APIs.
package swagger

import (
	"embed"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"io/fs"
	"net/http"

	"github.com/gorilla/mux"
)

//go:embed embed
var swagfs embed.FS

// WireRouter wires swagger UI endpoints to an existing mux.Router.
// It configures the UI to fetch the OpenAPI spec from the specified specPath.
// This function is intended to be used in conjunction with a mechanism
// that serves the OpenAPI spec itself (e.g., gswagger integrated via httputil).
//
// Parameters:
// - router: The mux.Router to wire the Swagger UI handlers to.
// - specPath: The URL path where the OpenAPI JSON spec is served (e.g., "/swagger.json").
// - uiPathPrefix: The URL path prefix where the Swagger UI will be served (e.g., "/swagger").
func WireRouter(router *mux.Router, specPath string, uiPathPrefix string) error {
	// Ensure the specPath is valid
	if specPath == "" {
		return fmt.Errorf("specPath cannot be empty")
	}
	// Ensure the uiPathPrefix is valid
	if uiPathPrefix == "" || uiPathPrefix[0] != '/' {
		return fmt.Errorf("uiPathPrefix must start with '/' and cannot be empty")
	}

	// Serve the static Swagger UI files
	swaggerFiles, err := fs.Sub(swagfs, "embed")
	if err != nil {
		return fmt.Errorf("failed to get embedded swagger files: %w", err)
	}
	swaggerHandler := http.StripPrefix(uiPathPrefix, http.FileServer(http.FS(swaggerFiles)))

	// Redirect from the base UI path to the index.html
	router.HandleFunc(uiPathPrefix, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, uiPathPrefix+"/", http.StatusMovedPermanently)
	}).Methods("GET")

	// Serve the static files under the path prefix
	router.PathPrefix(uiPathPrefix + "/").Handler(swaggerHandler)

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
// It configures the UI to fetch the OpenAPI spec from the specified specPath.
// This is useful for serving the UI from a single handler, assuming the spec
// is available at the given specPath.
//
// Parameters:
// - specPath: The URL path where the OpenAPI JSON spec is served (e.g., "/swagger.json").
// - uiPathPrefix: The URL path prefix where the Swagger UI will be served (e.g., "/swagger").
//
// Returns:
// - http.Handler: The configured handler serving the Swagger UI.
// - error: Any error encountered during setup.
func NewStandaloneHandler(specPath string, uiPathPrefix string) (http.Handler, error) {
	router := mux.NewRouter()
	if err := WireRouter(router, specPath, uiPathPrefix); err != nil {
		return nil, err
	}
	return router, nil
}

// --- Deprecated Functions ---

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

// NewHandler is deprecated. Use WireRouter in conjunction with a spec
// generation mechanism (like gswagger) instead.
//
// Deprecated: Use WireRouter instead.
func NewHandler(spec []byte, router *mux.Router) error {
	// This function combined spec loading/validation with wiring.
	// In the new model, spec generation is separate.
	// Keeping for backward compatibility, but marked deprecated.
	// It now calls the deprecated LoadAndValidateSpec and the new WireRouter.
	_, err := LoadAndValidateSpec(spec)
	if err != nil {
		return err
	}

	// Assuming the spec will be served at "/swagger.json" by the gswagger integration
	// This might need adjustment if gswagger serves it elsewhere.
	// A better approach might be to remove this deprecated function entirely
	// or require the specPath as a parameter. For now, assuming default.
	WireRouter(router, "/swagger.json", "/swagger") // Assuming default paths
	return nil
}
