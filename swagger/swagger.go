// Package swagger provides OpenAPI/Swagger documentation support for HTTP APIs.
package swagger

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"
)

//go:embed embed
var swagfs embed.FS

// LoadAndValidateSpec loads and validates an OpenAPI spec
func LoadAndValidateSpec(spec []byte) ([]byte, error) {
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

// WireRouter wires swagger endpoints to an existing mux.Router.
// It expects a pre-validated JSON spec.
func WireRouter(jsonSpec []byte, router *mux.Router) {
	swaggerFiles, _ := fs.Sub(swagfs, "embed")
	swaggerHandler := http.StripPrefix("/swagger", http.FileServer(http.FS(swaggerFiles)))

	router.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonSpec)
	}).Methods("GET")

	router.HandleFunc("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)
	}).Methods("GET")

	router.PathPrefix("/swagger/").Handler(swaggerHandler)
}

// NewHandler creates and wires swagger endpoints to an existing mux.Router.
// It validates the OpenAPI spec and returns any validation errors.
func NewHandler(spec []byte, router *mux.Router) error {
	jsonDoc, err := LoadAndValidateSpec(spec)
	if err != nil {
		return err
	}

	WireRouter(jsonDoc, router)
	return nil
}

// NewStandaloneHandler creates an HTTP handler that serves both the Swagger UI and OpenAPI spec.
// It validates the OpenAPI spec and returns a configured http.Handler.
func NewStandaloneHandler(spec []byte) (http.Handler, error) {
	jsonDoc, err := LoadAndValidateSpec(spec)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()
	WireRouter(jsonDoc, router)
	return router, nil
}
