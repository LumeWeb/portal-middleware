package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSHandler(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		requestHeaders map[string]string
		method         string
		wantHeaders    map[string]string
	}{
		{
			name: "default configuration",
			config: Config{
				AllowedMethods: []string{"GET", "POST"},
				AllowedHeaders: []string{"content-type"},
				AllowOrigins:   []string{"*"},
				ExposedHeaders: []string{"x-custom-header"},
				MaxAge:         3600,
			},
			requestHeaders: map[string]string{
				"Origin":                         "https://example.com",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "content-type",
			},
			method: "OPTIONS",
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "https://example.com",
				"Access-Control-Allow-Methods": "GET",
				"Access-Control-Allow-Headers": "content-type",
				"Access-Control-Max-Age":       "3600",
			},
		},
		{
			name: "allowed origins",
			config: Config{
				AllowOrigins: []string{"https://trusted.com", "https://api.trusted.com"},
			},
			requestHeaders: map[string]string{
				"Origin": "https://trusted.com",
			},
			method: "GET",
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://trusted.com",
			},
		},
		{
			name: "disallowed origin",
			config: Config{
				AllowOrigins: []string{"https://trusted.com"},
			},
			requestHeaders: map[string]string{
				"Origin": "https://untrusted.com",
			},
			method: "GET",
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "",
			},
		},
		{
			name: "allowed methods",
			config: Config{
				AllowedMethods: []string{"PUT", "DELETE"},
			},
			method: "OPTIONS",
			requestHeaders: map[string]string{
				"Origin":                        "https://example.com",
				"Access-Control-Request-Method": "PUT",
			},
			wantHeaders: map[string]string{
				"Access-Control-Allow-Methods": "PUT",
			},
		},
		{
			name: "allowed headers",
			config: Config{
				AllowedHeaders: []string{"x-custom-header", "authorization", "content-type"},
				AllowedMethods: []string{"GET"},
				AllowOrigins:   []string{"https://example.com"},
			},
			method: "OPTIONS",
			requestHeaders: map[string]string{
				"Origin":                         "https://example.com",
				"Host":                           "example.com",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "x-custom-header",
			},
			wantHeaders: map[string]string{
				"Access-Control-Allow-Headers": "x-custom-header",
				"Access-Control-Allow-Origin":  "https://example.com",
			},
		},
		{
			name: "exposed headers",
			config: Config{
				ExposedHeaders: []string{"X-Exposed-Header"},
			},
			method: "GET",
			requestHeaders: map[string]string{
				"Origin": "https://example.com",
			},
			wantHeaders: map[string]string{
				"Access-Control-Expose-Headers": "X-Exposed-Header",
			},
		},
		{
			name: "max age",
			config: Config{
				MaxAge: 7200,
			},
			method: "OPTIONS",
			requestHeaders: map[string]string{
				"Origin":                        "https://example.com",
				"Access-Control-Request-Method": "GET",
			},
			wantHeaders: map[string]string{
				"Access-Control-Max-Age": "7200",
			},
		},
		{
			name: "custom allow origin function",
			config: Config{
				AllowOriginFunc: func(origin string) bool {
					return origin == "https://allowed.com"
				},
			},
			requestHeaders: map[string]string{
				"Origin": "https://allowed.com",
			},
			method: "GET",
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://allowed.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create CORS handler with test config
			corsHandler := New(tt.config)

			// Create test handler that the CORS middleware will wrap
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Create request with test headers
			req := httptest.NewRequest(tt.method, "/", nil)
			for k, v := range tt.requestHeaders {
				req.Header.Set(k, v)
			}

			// Record the response
			rr := httptest.NewRecorder()

			// Apply CORS middleware and serve request
			handler := corsHandler(testHandler)
			handler.ServeHTTP(rr, req)

			// Check expected headers
			for header, wantValue := range tt.wantHeaders {
				gotValue := rr.Header().Get(header)
				if gotValue != wantValue {
					t.Errorf("Header %s: got %q, want %q", header, gotValue, wantValue)
				}
			}
		})
	}
}
