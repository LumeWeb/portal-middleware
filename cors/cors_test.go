package cors

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// sortCommaSeparated sorts a comma-separated string lexicographically
func sortCommaSeparated(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func TestNewWithDefaults(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   Config
	}{
		{
			name:   "empty config gets defaults",
			config: Config{},
			want: Config{
				AllowOrigins:   []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"Content-Type", "Authorization"},
				MaxAge:          300,
				AllowCredentials: true,
			},
		},
		{
			name: "partial config merges with defaults",
			config: Config{
				AllowedHeaders: []string{"X-Custom"},
			},
			want: Config{
				AllowOrigins:   []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"X-Custom"},
				MaxAge:          300,
				AllowCredentials: true,
			},
		},
		{
			name: "full config overrides defaults",
			config: Config{
				AllowOrigins:   []string{"https://example.com"},
				AllowedMethods: []string{"GET"},
				AllowedHeaders: []string{"X-Custom"},
				MaxAge:         100,
			},
			want: Config{
				AllowOrigins:     []string{"https://example.com"},
				AllowedMethods:   []string{"GET"},
				AllowedHeaders:   []string{"X-Custom"},
				MaxAge:          100,
				AllowCredentials: false, // Explicit false in config should override defaults
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't directly inspect the cors handler, so we'll test it by making requests
			handler := NewWithDefaults(tt.config)

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			wrapped := handler(testHandler)

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Origin", "https://test.com")
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			// Check CORS headers
			gotOrigin := rr.Header().Get("Access-Control-Allow-Origin")
			gotCredentials := rr.Header().Get("Access-Control-Allow-Credentials")
			
			// Verify credentials header matches expected config
			if tt.want.AllowCredentials {
				if gotCredentials != "true" {
					t.Errorf("Expected Access-Control-Allow-Credentials to be 'true', got %q", gotCredentials)
				}
			} else {
				if gotCredentials != "" {
					t.Errorf("Expected no Access-Control-Allow-Credentials header, got %q", gotCredentials)
				}
			}
			if len(tt.want.AllowOrigins) > 0 && tt.want.AllowOrigins[0] == "*" {
				// Wildcard origin should echo the request origin
				if gotOrigin != "https://test.com" {
					t.Errorf("Expected wildcard origin to echo request origin, got %q", gotOrigin)
				}
			} else if len(tt.want.AllowOrigins) > 0 {
				// For specific allowed origins, check if request origin is allowed
				requestOrigin := req.Header.Get("Origin")
				originAllowed := false
				for _, allowedOrigin := range tt.want.AllowOrigins {
					if requestOrigin == allowedOrigin {
						originAllowed = true
						break
					}
				}

				if originAllowed {
					// Request origin is allowed - should be in response
					if gotOrigin != requestOrigin {
						t.Errorf("Expected origin %q, got %q", requestOrigin, gotOrigin)
					}
				} else {
					// Request origin not allowed - should be empty
					if gotOrigin != "" {
						t.Errorf("Expected empty origin header for disallowed origin %q, got %q", requestOrigin, gotOrigin)
					}
				}
			}
		})
	}
}

func TestNewWithTUSDefaults(t *testing.T) {
	handler := NewWithTUSDefaults()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	wrapped := handler(testHandler)

	tests := []struct {
		name           string
		requestHeaders map[string]string
		method         string
		wantHeaders    map[string]string
	}{
		{
			name: "TUS headers allowed",
			requestHeaders: map[string]string{
				"Origin":                         "https://example.com",
				"Access-Control-Request-Method":  "PATCH",
				"Access-Control-Request-Headers": "upload-offset,tus-resumable",
			},
			method: "OPTIONS",
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "https://example.com",
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Allow-Methods":     "PATCH", // Only echoes requested method
				"Access-Control-Allow-Headers":     "tus-resumable, upload-offset", // Only echoes requested headers
			},
		},
		{
			name: "TUS headers exposed",
			requestHeaders: map[string]string{
				"Origin": "https://example.com",
			},
			method: "GET",
			wantHeaders: map[string]string{
				"Access-Control-Expose-Headers": "Tus-Resumable, Upload-Length, Upload-Metadata, Upload-Offset, Location",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			for k, v := range tt.requestHeaders {
				if k == "Access-Control-Request-Headers" {
					// Sort the headers lexicographically before setting them
					v = sortCommaSeparated(v)
				}
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			// Sort and compare headers to avoid order sensitivity
			for header, wantValue := range tt.wantHeaders {
				gotValue := rr.Header().Get(header)
				if gotValue == "" && wantValue == "" {
					continue
				}
				
				// Split and sort both values for comparison
				gotSorted := sortCommaSeparated(gotValue)
				wantSorted := sortCommaSeparated(wantValue)
				
				if gotSorted != wantSorted {
					t.Errorf("Header %s: got %q (sorted: %q), want %q (sorted: %q)", 
						header, gotValue, gotSorted, wantValue, wantSorted)
				}
			}
		})
	}
}

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
