package tus

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	swagger "go.lumeweb.com/gswagger"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal-middleware/middleware/option"
	"go.lumeweb.com/portal-middleware/util/convert"
	"go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"

	"github.com/rs/cors"
)

// TUSProtocolHandler defines the interface for the underlying TUS protocol handler.
type TUSProtocolHandler = echo.HandlerFunc

// LocationModifier defines an interface for modifying upload location URLs.
// Used to inject authentication tokens into TUS protocol responses.
type LocationModifier interface {
	ModifyLocation(loc string, c echo.Context) string
}

// jwtLocModifier implements LocationModifier to add JWT tokens to URLs
type jwtLocModifier struct {
	ParamName string // Query parameter name to inject
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ LocationModifier = (*jwtLocModifier)(nil)
)

func NewJWTLocModifier(paramName string) LocationModifier {
	return &jwtLocModifier{ParamName: paramName}
}

// ModifyLocation adds JWT token to location URL query parameters.
// Implements LocationModifier interface.
func (m *jwtLocModifier) ModifyLocation(loc string, c echo.Context) string {
	authToken := c.Get(string(mcontext.AuthTokenKey))
	if authToken == nil {
		return loc
	}
	if authTokenStr, ok := authToken.(string); ok && authTokenStr != "" && loc != "" {
		parsedURL, _ := url.Parse(loc)
		query := parsedURL.Query()
		query.Set(m.ParamName, authTokenStr)
		parsedURL.RawQuery = query.Encode()
		return parsedURL.String()
	}
	return loc
}

type locationModifierResponseWriter struct {
	http.ResponseWriter
	c               echo.Context
	locationModifer LocationModifier
}

func (w *locationModifierResponseWriter) WriteHeader(statusCode int) {
	// Modify the Location header before writing headers
	if statusCode == http.StatusCreated {
		if location := w.Header().Get("Location"); location != "" {
			w.Header().Set("Location", w.locationModifer.ModifyLocation(location, w.c))
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// PathMiddleware is an echo.MiddlewareFunc that handles TUS path trimming and Location header modification.
func PathMiddleware(basePath string, modifier LocationModifier) echo.MiddlewareFunc {
	// Ensure basePath is clean with no trailing slashes
	basePath = strings.TrimSuffix(basePath, "/")
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			w := c.Response()

			if !strings.HasPrefix(r.URL.Path, basePath) {
				return next(c) // Not the TUS base path, pass to next middleware/handler
			}

			trimmedPath := strings.TrimPrefix(r.URL.Path, basePath)
			wasEmpty := trimmedPath == ""
			if wasEmpty {
				trimmedPath = "/"
			}
			r.URL.Path = trimmedPath // Modify the request path for the downstream handler

			// Wrap the response writer if it's a POST request to the base path and a modifier exists
			if r.Method == http.MethodPost && wasEmpty && modifier != nil {
				// Create a new response writer that wraps the original one
				wrappedWriter := &locationModifierResponseWriter{
					ResponseWriter:  w,
					c:               c, // Pass the echo.Context directly
					locationModifer: modifier,
				}
				// Replace the response writer in the context
				c.SetResponse(echo.NewResponse(wrappedWriter, c.Echo()))
			}

			// Call the next handler in the chain
			return next(c)
		}
	}
}

func CorsMiddleware() func(h http.Handler) http.Handler {
	return cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool { return true },
		AllowedMethods: []string{
			http.MethodPost,
			http.MethodHead,
			http.MethodPatch,
			http.MethodOptions,
			http.MethodGet,
			http.MethodDelete,
		},
		AllowedHeaders: []string{
			"authorization",
			"origin",
			"x-requested-with",
			"x-request-id",
			"x-http-method-override",
			"content-type",
			"upload-length",
			"upload-offset",
			"tus-resumable",
			"upload-metadata",
			"upload-defer-length",
			"upload-concat",
			"upload-incomplete",
			"upload-complete",
			"upload-draft-interop-version",
		},
		AllowCredentials: true,
		ExposedHeaders: []string{
			"Upload-Offset",
			"Location",
			"Upload-Length",
			"Tus-Version",
			"Tus-Resumable",
			"Tus-Max-Size",
			"Tus-Extension",
			"Upload-Metadata",
			"Upload-Defer-Length",
			"Upload-Concat",
			"Upload-Incomplete",
			"Upload-Complete",
			"Upload-Draft-Interop-Version",
		},
		MaxAge: 86400,
	}).Handler
}

// dummyOptionsHandler is a placeholder handler for OPTIONS requests at the basePath.
// The CORS middleware is expected to handle the response before this handler is reached.
func dummyOptionsHandler(c echo.Context) error {
	// This handler should ideally not be reached for CORS preflight requests
	// because the CorsMiddleware should handle them and write the response.
	// If it is reached, it means the CORS middleware didn't handle the request,
	// or it's a non-preflight OPTIONS request.
	// Returning 204 No Content is standard for OPTIONS if not handled by CORS.
	return c.NoContent(http.StatusNoContent)
}

// RegisterTusRoutes registers TUS protocol routes using the router builder API.
// It handles middleware chaining, access control registration and swagger documentation.
// RegisterTusRoutes defines and registers the standard TUS upload routes.
// It uses httputil Swagger helpers and applies TUS-specific middleware.
func RegisterTusRoutes(
	ctx core.Context,
	grouter router.Router,
	accessSvc core.AccessService,
	subdomain string,
	basePath string,
	tusHandler TUSProtocolHandler,
	authRequired bool,
	twoFARequired bool,
	commonMiddleware ...echo.MiddlewareFunc,
) error {

	// Create middleware chain
	mw := router.Middlewares(
		PathMiddleware(basePath, NewJWTLocModifier(core.AUTH_TOKEN_NAME)),
		convert.Wrap(CorsMiddleware()),
	)
	mw = append(mw, commonMiddleware...)

	// Determine access role based on authRequired
	access := ""
	if authRequired {
		access = core.ACCESS_USER_ROLE
	}

	// Define error responses common to all TUS operations
	commonErrResp := map[int]any{
		http.StatusUnauthorized: "Authentication required",
		http.StatusForbidden:    "Insufficient permissions",
	}

	// Helper to build route options based on auth requirements
	buildRouteOptions := func(method string, path string, swaggerFn func(string, string, map[int]any) swagger.Definitions) router.RouteDefinition {
		opts := router.DefineOptions(
			router.WithSwaggerOptions(func(d *swagger.Definitions, _ string) {
				*d = swaggerFn(
					"TUS "+method+" "+path,
					"TUS protocol "+method+" handler for "+path,
					commonErrResp,
				)
			}),
			router.WithMiddlewares(mw...),
		)

		if authRequired {
			if twoFARequired {
				// Only require 2FA, not basic auth
				opts = append(opts, option.With2FA(ctx), router.WithAccess(access))
			} else {
				// Require basic auth + verification
				opts = append(opts, option.WithAuth(ctx), router.WithAccess(access))
			}
		}

		return router.NewRoute(method, path, tusHandler, opts...)
	}

	// Define route configurations
	idPathSuffix := "/:id"
	
	routeConfigs := []struct {
		method       string
		swaggerFunc  func(string, string, map[int]any) swagger.Definitions
		hasIDPath    bool
	}{
		{http.MethodPost, router.TusPostSwagger, false},
		{http.MethodHead, router.TusHeadSwagger, true},
		{http.MethodPatch, router.TusPatchSwagger, true},
		{http.MethodDelete, router.TusDeleteSwagger, true},
		{http.MethodOptions, router.TusOptionsSwagger, true}, // OPTIONS route also needs ID path
	}

	// Build main routes
	var routes []router.RouteDefinition
	for _, cfg := range routeConfigs {
		path := basePath
		if cfg.hasIDPath {
			path += idPathSuffix
		}
		
		route := buildRouteOptions(cfg.method, path, cfg.swaggerFunc)
		routes = append(routes, route)
	}

	// Add base path OPTIONS route (no ID)
	optionsBaseRoute := router.NewRoute(
		http.MethodOptions,
		basePath,
		dummyOptionsHandler,
		router.WithSwaggerOptions(func(d *swagger.Definitions, _ string) {
			*d = router.TusOptionsSwagger(
				"Get TUS Server Capabilities",
				"Retrieves information about the TUS server's supported versions, extensions, and limits.",
				commonErrResp,
			)
		}),
		router.WithMiddlewares(mw...),
	)
	routes = append(routes, optionsBaseRoute)

	routes = router.DefineRoutes(routes...)

	return router.RegisterRoutes(
		grouter,
		accessSvc,
		subdomain,
		routes,
	)
}
