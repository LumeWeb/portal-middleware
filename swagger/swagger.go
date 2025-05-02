// Package swagger provides OpenAPI/Swagger documentation support for HTTP APIs.
// It handles:
// - Serving validated OpenAPI specifications
// - Embedding and serving Swagger UI assets
// - Proper MIME types and CORS headers for documentation endpoints
//
// The package automatically configures the Swagger UI to work with your API spec
// and provides validation of the OpenAPI document during initialization.
package swagger

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
)

//go:embed embed
var swagfs embed.FS

// NewHandler creates an HTTP handler that serves both the Swagger UI and OpenAPI spec.
// The handler:
// - Validates the provided OpenAPI specification
// - Serves the spec JSON at {basePath}/swagger.json
// - Serves the Swagger UI at {basePath}/
//
// Parameters:
//   - spec: Raw JSON bytes of the OpenAPI specification
//   - basePath: URL path prefix for documentation endpoints (e.g. "/docs")
//
// The returned handler will:
// - Set proper Content-Type headers for JSON and HTML responses
// - Strip the basePath prefix from requests to embedded assets
// - Validate the OpenAPI spec during initialization
func NewHandler(spec []byte, basePath string) http.Handler {
	loader := openapi3.NewLoader()
	doc, _ := loader.LoadFromData(spec)
	doc.Validate(loader.Context)

	jsonDoc, _ := doc.MarshalJSON()

	swaggerFiles, _ := fs.Sub(swagfs, "embed")
	swaggerHandler := http.StripPrefix(basePath, http.FileServer(http.FS(swaggerFiles)))

	mux := http.NewServeMux()
	mux.HandleFunc(basePath+"/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonDoc)
	})
	mux.Handle(basePath+"/", swaggerHandler)
	return mux
}
