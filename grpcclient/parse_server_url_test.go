package grpcclient

import (
	"strings"
	"testing"
)

func TestParseServerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantAddr    string
		wantUseTLS  bool
		wantErrPart string
	}{
		{
			name:       "grpc default port",
			input:      "grpc://localhost",
			wantAddr:   "localhost:50051",
			wantUseTLS: false,
		},
		{
			name:       "grpc explicit port",
			input:      "grpc://localhost:9000",
			wantAddr:   "localhost:9000",
			wantUseTLS: false,
		},
		{
			name:       "https default port",
			input:      "https://api.example.com",
			wantAddr:   "api.example.com:443",
			wantUseTLS: true,
		},
		{
			name:       "https explicit port",
			input:      "https://api.example.com:8443",
			wantAddr:   "api.example.com:8443",
			wantUseTLS: true,
		},
		{
			name:        "unsupported scheme",
			input:       "http://localhost",
			wantErrPart: "unsupported scheme",
		},
		{
			name:        "invalid url",
			input:       "://bad",
			wantErrPart: "invalid URL",
		},
		{
			name:        "missing scheme",
			input:       "localhost:50051",
			wantErrPart: "unsupported scheme",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotAddr, gotUseTLS, err := parseServerURL(tc.input)
			if tc.wantErrPart != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrPart)
				}
				if !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrPart, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotAddr != tc.wantAddr {
				t.Fatalf("unexpected addr: got %q want %q", gotAddr, tc.wantAddr)
			}
			if gotUseTLS != tc.wantUseTLS {
				t.Fatalf("unexpected useTLS: got %v want %v", gotUseTLS, tc.wantUseTLS)
			}
		})
	}
}
