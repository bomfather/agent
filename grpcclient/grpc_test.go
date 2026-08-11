package grpcclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/bomfather/bomfather/agent/proto"
	"github.com/bomfather/bomfather/agent/reader"
)

// closeAndWaitStream mocks EventIngestion_StreamEventsClient for closeAndWait.
// closeSend is closed when CloseSend is called so the test can wait without sleeping.
type closeAndWaitStream struct {
	closeSend chan struct{}
}

func (s *closeAndWaitStream) Send(*proto.EventBatch) error { return nil }
func (s *closeAndWaitStream) Recv() (*proto.BatchAck, error) {
	return nil, io.EOF
}
func (s *closeAndWaitStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (s *closeAndWaitStream) Trailer() metadata.MD         { return metadata.MD{} }
func (s *closeAndWaitStream) CloseSend() error {
	close(s.closeSend)
	return nil
}
func (s *closeAndWaitStream) Context() context.Context { return context.Background() }
func (s *closeAndWaitStream) SendMsg(any) error        { return nil }
func (s *closeAndWaitStream) RecvMsg(any) error        { return io.EOF }

type openStreamClient struct {
	stream proto.EventIngestion_StreamEventsClient
	err    error
	called chan struct{}
}

func (f *openStreamClient) StreamEvents(ctx context.Context, _ ...grpc.CallOption) (proto.EventIngestion_StreamEventsClient, error) {
	if f.called != nil {
		select {
		case f.called <- struct{}{}:
		default:
		}
	}
	return f.stream, f.err
}

func (f *openStreamClient) GetOrCreateNode(context.Context, *proto.GetOrCreateNodeRequest, ...grpc.CallOption) (*proto.GetOrCreateNodeResponse, error) {
	return nil, errors.New("not used")
}

func TestJitteredBackoff(t *testing.T) {
	for _, attempt := range []int{0, 1, 2} {
		backoff := jitteredBackoff(attempt)
		max := reconnectBaseDelay * (1 << attempt) * 2
		if backoff < reconnectBaseDelay || backoff > max {
			t.Errorf("attempt %d: backoff %v want [%v, %v]", attempt, backoff, reconnectBaseDelay, max)
		}
	}

	// Huge attempt counts must not panic; backoff caps at reconnectMaxDelay.
	backoff := jitteredBackoff(1000)
	if backoff < reconnectMaxDelay || backoff > 2*reconnectMaxDelay {
		t.Errorf("capped backoff %v want [%v, %v]", backoff, reconnectMaxDelay, 2*reconnectMaxDelay)
	}

	const samples = 64
	seen := make(map[time.Duration]struct{}, samples)
	for i := 0; i < samples; i++ {
		backoff := jitteredBackoff(0)
		max := reconnectBaseDelay * 2
		if backoff < reconnectBaseDelay || backoff > max {
			t.Fatalf("sample %d: backoff %v want [%v, %v]", i, backoff, reconnectBaseDelay, max)
		}
		seen[backoff] = struct{}{}
	}
	if len(seen) == 1 {
		t.Fatalf("expected jitter spread across %d samples, all identical: %v", samples, backoff)
	}
}

func TestConsumeEventsRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		bufferSize    int
		batchSize     int
		batchInterval time.Duration
	}{
		{name: "buffer size", bufferSize: 0, batchSize: 1, batchInterval: time.Second},
		{name: "batch size", bufferSize: 1, batchSize: 0, batchInterval: time.Second},
		{name: "batch interval", bufferSize: 1, batchSize: 1, batchInterval: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := make(chan struct{}, 1)
			client := &DefaultClient{grpcClient: &openStreamClient{called: called}}

			client.ConsumeEvents(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), newTestStreams(), tt.bufferSize, tt.batchSize, tt.batchInterval)

			select {
			case <-called:
				t.Fatal("StreamEvents called for invalid configuration")
			case <-time.After(10 * time.Millisecond):
			}
		})
	}
}

func TestOpenStream(t *testing.T) {
	wantStream := &closeAndWaitStream{}
	openErr := errors.New("dial failed")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name    string
		client  *openStreamClient
		want    proto.EventIngestion_StreamEventsClient
		wantErr error
	}{
		{
			name:   "success",
			client: &openStreamClient{stream: wantStream},
			want:   wantStream,
		},
		{
			name:    "failure wraps errOpenStream",
			client:  &openStreamClient{err: openErr},
			wantErr: errOpenStream,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &DefaultClient{grpcClient: tt.client}

			got, err := c.openStream(context.Background(), logger)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("errors.Is(err, %v) = false, got %v", tt.wantErr, err)
				}
				if !errors.Is(err, openErr) {
					t.Fatalf("expected wrapped %v, got %v", openErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("stream = %p, want %p", got, tt.want)
			}
		})
	}
}

func TestCloseAndWait(t *testing.T) {
	stream := &closeAndWaitStream{closeSend: make(chan struct{})}
	recvDone := make(chan error)

	done := make(chan struct{})
	go func() {
		closeAndWait(stream, recvDone)
		close(done)
	}()

	select {
	case <-stream.closeSend:
	case <-time.After(time.Second):
		t.Fatal("CloseSend was not called")
	}

	select {
	case <-done:
		t.Fatal("closeAndWait returned before recvDone")
	default:
	}

	close(recvDone)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closeAndWait did not return after recvDone")
	}
}

func TestAcceptDuringBackoff(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		d    time.Duration
		want error
	}{
		{name: "timer", ctx: context.Background(), d: 10 * time.Millisecond},
		{name: "cancel", ctx: canceledContext(), d: time.Hour, want: context.Canceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := sessionConfig{streams: newTestStreams()}
			err := acceptDuringBackoff(tt.ctx, cfg, newBatcher(8, 4), tt.d)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("got %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAcceptDuringBackoff_drainsEvents(t *testing.T) {
	streams := newTestStreams()
	want := &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/x"}}
	streams.OpenatStream <- want

	cfg := sessionConfig{streams: streams}
	b := newBatcher(8, 4)

	if err := acceptDuringBackoff(context.Background(), cfg, b, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	batch, ok := b.drain()
	if !ok || len(batch.OpenatEvents) != 1 || batch.OpenatEvents[0] != want {
		t.Fatalf("got %+v, want one openat event", batch)
	}
}

func TestAcceptDuringBackoff_timerNotStarved(t *testing.T) {
	streams := newTestStreams()
	cfg := sessionConfig{streams: streams}
	flood := &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/flood"}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go floodOpenat(ctx, streams.OpenatStream, flood)

	start := time.Now()
	if err := acceptDuringBackoff(ctx, cfg, newBatcher(64, 32), 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("backoff took %v; timer was starved by events", elapsed)
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func floodOpenat(ctx context.Context, ch chan<- *proto.OpenatEventWrapper, event *proto.OpenatEventWrapper) {
	for {
		select {
		case <-ctx.Done():
			return
		case ch <- event:
		}
	}
}

type slowOpenClient struct {
	stream  proto.EventIngestion_StreamEventsClient
	started chan struct{}
	unblock chan struct{}
}

func (c *slowOpenClient) StreamEvents(context.Context, ...grpc.CallOption) (proto.EventIngestion_StreamEventsClient, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-c.unblock
	return c.stream, nil
}

func (c *slowOpenClient) GetOrCreateNode(context.Context, *proto.GetOrCreateNodeRequest, ...grpc.CallOption) (*proto.GetOrCreateNodeResponse, error) {
	return nil, errors.New("not used")
}

func TestStreamOnce_drainsWhileOpening(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streams := reader.EventStreams{
		OpenatStream:    make(chan *proto.OpenatEventWrapper),
		ExecveStream:    make(chan *proto.ExecveEventWrapper),
		ViolationStream: make(chan *proto.ViolationEventWrapper),
	}
	want := &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/x"}}

	stream := newFakeBidiStream(ctx)
	slowClient := &slowOpenClient{
		stream:  stream,
		started: make(chan struct{}, 1),
		unblock: make(chan struct{}),
	}
	client := &DefaultClient{grpcClient: slowClient}
	cfg := sessionConfig{
		streams:       streams,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		batchInterval: time.Hour,
	}
	b := newBatcher(8, 4)

	done := make(chan struct{})
	go func() {
		_, _ = client.streamOnce(ctx, cfg, b, nil)
		close(done)
	}()

	<-slowClient.started

	sent := make(chan struct{})
	go func() {
		streams.OpenatStream <- want
		close(sent)
	}()

	select {
	case <-sent:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("producer blocked during stream open")
	}

	close(slowClient.unblock)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("streamOnce did not return after cancel")
	}

	batch, ok := b.drain()
	if !ok || len(batch.OpenatEvents) != 1 || batch.OpenatEvents[0] != want {
		t.Fatalf("got %+v, want one openat event", batch)
	}
}
