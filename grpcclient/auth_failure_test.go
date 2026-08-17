package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsAuthFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "unauthenticated",
			err:  status.Error(codes.Unauthenticated, "invalid API key"),
			want: true,
		},
		{
			name: "permission denied",
			err:  status.Error(codes.PermissionDenied, "access denied"),
			want: true,
		},
		{
			name: "wrapped unauthenticated",
			err:  fmt.Errorf("open stream: %w: %w", errOpenStream, status.Error(codes.Unauthenticated, "invalid API key")),
			want: true,
		},
		{
			name: "errAuthFailure sentinel",
			err:  errAuthFailure,
			want: true,
		},
		{
			name: "wrapped errAuthFailure",
			err:  fmt.Errorf("%w: %w", errAuthFailure, status.Error(codes.Unauthenticated, "invalid API key")),
			want: true,
		},
		{
			name: "unavailable is retryable",
			err:  status.Error(codes.Unavailable, "service unavailable"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "non-status",
			err:  errors.New("plain error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isAuthFailure(tt.err); got != tt.want {
				t.Fatalf("isAuthFailure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConsumeEvents_authFailureStopsReconnect(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcClient := &scriptedStreamClient{
		openFailures: 5,
		openErr:      status.Error(codes.Unauthenticated, "invalid API key"),
	}
	client := &DefaultClient{grpcClient: grpcClient}
	streams := newTestStreams()

	fatalCh := client.ConsumeEvents(ctx, testLogger(), streams, 1, 1, 50*time.Millisecond)

	select {
	case err := <-fatalCh:
		if !errors.Is(err, errAuthFailure) {
			t.Fatalf("fatal error is not errAuthFailure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for auth failure")
	}

	// Give the loop a moment; auth failure must not keep opening streams.
	time.Sleep(200 * time.Millisecond)
	grpcClient.mu.Lock()
	remaining := grpcClient.openFailures
	grpcClient.mu.Unlock()
	if remaining != 4 {
		t.Fatalf("openFailures remaining = %d, want 4 (only one attempt)", remaining)
	}
}
