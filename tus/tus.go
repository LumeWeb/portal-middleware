// Package tus provides TUS protocol v1.0.0 extensions for resumable file uploads.
// It implements:
// - Location header modification for JWT token injection
// - Response writer wrappers for protocol compliance
// - Custom middleware integration with authentication system
package tus

import (
	"go.lumeweb.com/gswagger"
	gs "go.lumeweb.com/gswagger/support/gorilla"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal/core"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.lumeweb.com/portal-middleware/context"
)

// TUSProtocolHandler defines the interface for the underlying TUS protocol handler.
type TUSProtocolHandler interface {
	http.Handler
}

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

func (w *tusResponseWriter) WriteHeader(statusCode int) {
	if statusCode == http.StatusCreated {
		if location := w.Header().Get("Location"); location != "" {
			w.Header().Set("Location", w.locationModifer.ModifyLocation(location, w.req))
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
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
	// Modify the Location header before writing headers
	if statusCode == http.StatusCreated {
		if location := w.Header().Get("Location"); location != "" {
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
		AllowedMethods:  []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions},
		AllowedHeaders: []string{
			"authorization", "expires", "upload-concat",
			"upload-length", "upload-metadata", "upload-offset",
			"x-requested-with", "tus-version", "tus-resumable",
			"tus-extension", "tus-max-size", "x-http-method-override",
			"content-type",
		},
		AllowCredentials:   true,
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

// RegisterTusRoutes defines and registers the standard TUS upload routes.
// It uses httputil Swagger helpers and applies TUS-specific middleware.
func RegisterTusRoutes(
	ctx core.Context,
	gRouter *swagger.Router[gs.HandlerFunc, gs.Route],
	accessSvc core.AccessService,
	subdomain string,
	basePath string,
	tusHandler TUSProtocolHandler,
	authRequired bool,
	verifiedRequired bool,
	commonMiddleware ...mux.MiddlewareFunc,
) error {
	muxRouter := swagger.GetRouter[*mux.Router, gs.HandlerFunc, gs.Route](gRouter.Router())
	// 1. Create a subrouter for the base path
	subrouter := muxRouter.PathPrefix(basePath).Subrouter()
	gsubrouter, err := gRouter.SubRouter(gs.NewRouter(subrouter), swagger.SubRouterOptions{})
	if err != nil {
		return err
	}

	// 2. Apply TUS-specific middleware to the subrouter
	// Use the PathMiddleware from the tus middleware package
	subrouter.Use(PathMiddleware(basePath, NewJWTLocModifier("token")))
	// Use the CorsMiddleware from the tus middleware package
	subrouter.Use(CorsMiddleware())
	// Apply any additional common middleware passed in
	subrouter.Use(commonMiddleware...)

	// Determine access role based on authRequired
	access := ""
	if authRequired {
		access = core.ACCESS_USER_ROLE // Or another appropriate role
	}

	// 3. Define the individual operation Swagger using httputil helpers
	// Define error responses common to all TUS operations if any
	// For now, using nil as in the original TusPostSwagger call
	commonErrResp := map[int]any{} // Define common error responses here if needed

	postSwagger := httputil.TusPostSwagger("Create TUS Upload", "Creates a new TUS upload resource.", commonErrResp)
	headSwagger := httputil.TusHeadSwagger("Get TUS Upload Status", "Retrieves the current offset and size of a TUS upload.", commonErrResp)
	patchSwagger := httputil.TusPatchSwagger("Resume TUS Upload", "Appends data to an existing TUS upload resource.", commonErrResp)
	deleteSwagger := httputil.TusDeleteSwagger("Terminate TUS Upload", "Terminates and removes a TUS upload resource.", commonErrResp)
	optionsSwagger := httputil.TusOptionsSwagger("Get TUS Server Capabilities", "Retrieves information about the TUS server's supported versions, extensions, and limits.", commonErrResp)

	// 4. Define the RouteDefinitions slice
	routes := httputil.DefineRoutes(
		httputil.RouteDefinition{
			Path:      "", // Path relative to the subrouter's base path
			Method:    http.MethodPost,
			Handler:   tusHandler.ServeHTTP,
			Access:    access,
			UseVerify: verifiedRequired,
			Use2FA:    false, // TUS typically doesn't require 2FA on these endpoints
			Swagger:   postSwagger,
		},
		httputil.RouteDefinition{
			Path:      "/{id}", // Path relative to the subrouter's base path
			Method:    http.MethodHead,
			Handler:   tusHandler.ServeHTTP,
			Access:    access,
			UseVerify: verifiedRequired,
			Use2FA:    false,
			Swagger:   headSwagger,
		},
		httputil.RouteDefinition{
			Path:      "/{id}", // Path relative to the subrouter's base path
			Method:    http.MethodPatch,
			Handler:   tusHandler.ServeHTTP,
			Access:    access,
			UseVerify: verifiedRequired,
			Use2FA:    false,
			Swagger:   patchSwagger,
		},
		httputil.RouteDefinition{
			Path:      "/{id}", // Path relative to the subrouter's base path
			Method:    http.MethodDelete,
			Handler:   tusHandler.ServeHTTP,
			Access:    access, // Apply access control to DELETE as well
			UseVerify: verifiedRequired,
			Use2FA:    false,
			Swagger:   deleteSwagger,
		},
		httputil.RouteDefinition{
			Path:      "", // Path relative to the subrouter's base path
			Method:    http.MethodOptions,
			Handler:   tusHandler.ServeHTTP,
			Access:    "", // OPTIONS is typically public
			UseVerify: false,
			Use2FA:    false,
			Swagger:   optionsSwagger,
		},
		// Note: The OPTIONS method for /{id} is handled by the router automatically
		// when OPTIONS is included in the Methods list for the /{id} routes.
		// We don't need a separate RouteDefinition for it unless it requires
		// different middleware or Swagger definitions (which it doesn't for TUS).
	)

	// 5. Call httputil.RegisterRoutes to register the routes and Swagger
	// Pass the subrouter, gRouter, accessSvc, subdomain, and the defined routes.
	// No commonMiddleware is passed here as it was applied to the subrouter.
	return httputil.RegisterRoutes(
		ctx,
		gsubrouter,
		accessSvc,
		subdomain,
		routes,
	)
}
