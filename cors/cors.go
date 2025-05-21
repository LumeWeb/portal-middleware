package cors

import (
	"net/http"

	"github.com/rs/cors"
)

type Config struct {
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowOrigins     []string
	AllowOriginFunc  func(string) bool
	ExposedHeaders   []string
	MaxAge           int
	AllowCredentials bool
}

// NewWithTUSDefaults creates a CORS handler with defaults optimized for TUS protocol.
// It allows TUS-specific headers and methods needed for resumable uploads.
func NewWithTUSDefaults() func(http.Handler) http.Handler {
	return New(Config{
		AllowOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPatch,
			http.MethodHead,
			http.MethodOptions,
			http.MethodDelete,
		},
		AllowedHeaders: []string{
			"content-type",
			"authorization",
			"tus-resumable",
			"upload-length",
			"upload-metadata",
			"upload-offset",
			"x-http-method-override",
			"x-requested-with",
		},
		ExposedHeaders: []string{
			"Tus-Resumable",
			"Upload-Length",
			"Upload-Metadata",
			"Upload-Offset",
			"Location",
		},
		AllowCredentials: true,
	})
}

// NewWithDefaults creates a CORS handler with sensible defaults that can be overridden.
// Defaults include:
// - AllowOrigins: ["*"]
// - AllowedMethods: GET, POST, PUT, PATCH, DELETE, OPTIONS
// - AllowedHeaders: Content-Type, Authorization
// - MaxAge: 300 (5 minutes)
func NewWithDefaults(config Config) func(http.Handler) http.Handler {
	// Apply defaults
	if config.AllowOrigins == nil {
		config.AllowOrigins = []string{"*"}
	}
	if config.AllowedMethods == nil {
		config.AllowedMethods = []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		}
	}
	if config.AllowedHeaders == nil {
		config.AllowedHeaders = []string{"Content-Type", "Authorization"}
	}
	if config.MaxAge == 0 {
		config.MaxAge = 300
	}

	return New(config)
}

func New(config Config) func(http.Handler) http.Handler {
	// When using wildcard origin, use AllowOriginFunc to echo requesting origin
	if len(config.AllowOrigins) == 1 && config.AllowOrigins[0] == "*" {
		config.AllowOriginFunc = func(origin string) bool { return true }
		config.AllowOrigins = nil
	}

	c := cors.New(cors.Options{
		AllowedMethods:       config.AllowedMethods,
		AllowedHeaders:       config.AllowedHeaders,
		AllowedOrigins:       config.AllowOrigins,
		AllowOriginFunc:      config.AllowOriginFunc,
		ExposedHeaders:       config.ExposedHeaders,
		MaxAge:               config.MaxAge,
		OptionsPassthrough:   false,
		OptionsSuccessStatus: 204,
		AllowCredentials:     config.AllowCredentials,
	})
	return c.Handler
}
