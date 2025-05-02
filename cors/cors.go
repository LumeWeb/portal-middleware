package cors

import (
	"net/http"

	"github.com/rs/cors"
)

type Config struct {
	AllowedMethods  []string
	AllowedHeaders  []string
	AllowOrigins    []string
	AllowOriginFunc func(string) bool
	ExposedHeaders  []string
	MaxAge          int
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
		AllowCredentials:     true,
	})
	return c.Handler
}
