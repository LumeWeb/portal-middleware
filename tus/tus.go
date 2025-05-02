// Package tus provides TUS protocol v1.0.0 extensions for resumable file uploads.
// It implements:
// - Location header modification for JWT token injection
// - Response writer wrappers for protocol compliance
// - Custom middleware integration with authentication system
package tus

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.lumeweb.com/portal-middleware/context"
)

// LocationModifier defines an interface for modifying upload location URLs.
// Used to inject authentication tokens into TUS protocol responses.
type LocationModifier interface {
	ModifyLocation(loc string, r *http.Request) string
}

// jwtLocModifier implements LocationModifier to add JWT tokens to URLs
type jwtLocModifier struct {
	ParamName string // Query parameter name to inject
}

type tusResponseWriter struct {
	http.ResponseWriter
	req             *http.Request
	locationModifer LocationModifier
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ LocationModifier    = (*jwtLocModifier)(nil)
	_ http.ResponseWriter = (*tusResponseWriter)(nil)
)

func NewJWTLocModifier(paramName string) LocationModifier {
	return &jwtLocModifier{ParamName: paramName}
}

// ModifyLocation adds JWT token to location URL query parameters.
// Implements LocationModifier interface.
func (m *jwtLocModifier) ModifyLocation(loc string, r *http.Request) string {
	authToken, _ := mcontext.GetAuthToken(r.Context())
	if authToken != "" && loc != "" {
		parsedURL, _ := url.Parse(loc)
		query := parsedURL.Query()
		query.Set(m.ParamName, authToken)
		parsedURL.RawQuery = query.Encode()
		return parsedURL.String()
	}
	return loc
}

type locationModifierResponseWriter struct {
	http.ResponseWriter
	req             *http.Request
	locationModifer LocationModifier
}

func (w *locationModifierResponseWriter) WriteHeader(statusCode int) {
	if statusCode == http.StatusCreated {
		location := w.Header().Get("Location")
		if location != "" {
			w.Header().Set("Location", w.locationModifer.ModifyLocation(location, w.req))
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func PathMiddleware(basePath string, modifier LocationModifier) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, basePath) {
				trimmedPath := strings.TrimPrefix(r.URL.Path, basePath)
				wasEmpty := trimmedPath == ""
				if wasEmpty {
				    trimmedPath = "/"
				}
				r.URL.Path = trimmedPath

				res := w
				if r.Method == http.MethodPost && wasEmpty && modifier != nil {
					res = &locationModifierResponseWriter{
						ResponseWriter:  w,
						req:             r,
						locationModifer: modifier,
					}
				}

				next.ServeHTTP(res, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func CorsMiddleware() func(h http.Handler) http.Handler {
	return cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool { return true },
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions},
		AllowedHeaders: []string{
			"authorization", "expires", "upload-concat",
			"upload-length", "upload-metadata", "upload-offset",
			"x-requested-with", "tus-version", "tus-resumable", 
			"tus-extension", "tus-max-size", "x-http-method-override",
			"content-type",
		},
		AllowCredentials: true,
		OptionsPassthrough: false,
		ExposedHeaders: []string{
			"Upload-Offset",
			"Location",
			"Upload-Length",
			"Tus-Version",
			"Tus-Resumable",
			"Tus-Extension",
			"Tus-Max-Size",
		},
	}).Handler
}
