package grpcclient

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bomfather/bomfather/agent/proto"
	"github.com/bomfather/bomfather/agent/reader"
)

// streamHandler scripts one StreamEvents session. n is 1-based global open count.
type streamHandler func(n int, stream grpc.BidiStreamingServer[proto.EventBatch, proto.BatchAck]) error

type testIngestionServer struct {
	proto.UnimplementedEventIngestionServer

	opened   chan int
	handlers []streamHandler
	handler  streamHandler
	count    atomic.Int32
}

func (s *testIngestionServer) StreamEvents(stream grpc.BidiStreamingServer[proto.EventBatch, proto.BatchAck]) error {
	n := int(s.count.Add(1))
	select {
	case s.opened <- n:
	default:
	}

	if s.handler != nil {
		return s.handler(n, stream)
	}
	if n-1 >= len(s.handlers) {
		return status.Error(codes.Unavailable, "no more scripted handlers")
	}
	return s.handlers[n-1](n, stream)
}

func (s *testIngestionServer) GetOrCreateNode(context.Context, *proto.GetOrCreateNodeRequest) (*proto.GetOrCreateNodeResponse, error) {
	return &proto.GetOrCreateNodeResponse{NodeId: 1}, nil
}

type integrationHarness struct {
	t             *testing.T
	server        *grpc.Server
	listener      net.Listener
	client        *DefaultClient
	streams       reader.EventStreams
	opened        chan int
	batches       chan *proto.EventBatch
	cancel        context.CancelFunc
	batchInterval time.Duration
	batchSize     int
	bufferSize    int
}

type harnessOptions struct {
	batches       chan *proto.EventBatch
	bufferSize    int
	batchSize     int
	batchInterval time.Duration
	handlers      []streamHandler
	handler       streamHandler
}

func startIntegrationHarness(t *testing.T, opts harnessOptions) *integrationHarness {
	t.Helper()

	if opts.bufferSize == 0 {
		opts.bufferSize = 8
	}
	if opts.batchSize == 0 {
		opts.batchSize = 4
	}
	if opts.batchInterval == 0 {
		opts.batchInterval = 10 * time.Millisecond
	}

	RegisterZstdCompressor()

	opened := make(chan int, 16)
	ingestion := &testIngestionServer{
		opened:   opened,
		handlers: opts.handlers,
		handler:  opts.handler,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := grpc.NewServer()
	proto.RegisterEventIngestionServer(server, ingestion)
	go func() {
		_ = server.Serve(listener)
	}()

	client, err := NewDefaultClient("grpc://"+listener.Addr().String(), "test-api-key", nil)
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("NewDefaultClient: %v", err)
	}

	streams := reader.EventStreams{
		OpenatStream:    make(chan *proto.OpenatEventWrapper),
		ExecveStream:    make(chan *proto.ExecveEventWrapper),
		ViolationStream: make(chan *proto.ViolationEventWrapper),
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &integrationHarness{
		t:             t,
		server:        server,
		listener:      listener,
		client:        client,
		streams:       streams,
		opened:        opened,
		batches:       opts.batches,
		cancel:        cancel,
		batchInterval: opts.batchInterval,
		batchSize:     opts.batchSize,
		bufferSize:    opts.bufferSize,
	}
	t.Cleanup(h.close)

	h.client.ConsumeEvents(
		ctx,
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
		streams,
		h.bufferSize,
		h.batchSize,
		h.batchInterval,
	)
	return h
}

func (h *integrationHarness) close() {
	h.cancel()
	if h.client != nil && h.client.conn != nil {
		_ = h.client.conn.Close()
	}
	if h.server != nil {
		h.server.Stop()
	}
	if h.listener != nil {
		_ = h.listener.Close()
	}
}

func (h *integrationHarness) waitOpened(want int) {
	h.t.Helper()
	select {
	case n := <-h.opened:
		if n != want {
			h.t.Fatalf("opened stream = %d, want %d", n, want)
		}
	case <-time.After(5 * time.Second):
		h.t.Fatalf("timed out waiting for stream %d", want)
	}
}

func (h *integrationHarness) assertNoOpen(want int, within time.Duration) {
	h.t.Helper()
	select {
	case n := <-h.opened:
		h.t.Fatalf("unexpected stream open %d, want none (expected < %d)", n, want)
	case <-time.After(within):
	}
}

func (h *integrationHarness) sendOpenat(filename string) {
	h.t.Helper()
	select {
	case h.streams.OpenatStream <- &proto.OpenatEventWrapper{
		Event: &proto.OpenatEvent{Filename: filename},
	}:
	case <-time.After(time.Second):
		h.t.Fatalf("timed out sending openat %q", filename)
	}
}

func waitExactBatches(t *testing.T, ch <-chan *proto.EventBatch, want int) []*proto.EventBatch {
	t.Helper()
	got := make([]*proto.EventBatch, 0, want)
	deadline := time.After(5 * time.Second)
	for len(got) < want {
		select {
		case batch := <-ch:
			got = append(got, batch)
		case <-deadline:
			t.Fatalf("got %d batches, want %d", len(got), want)
		}
	}
	select {
	case extra := <-ch:
		t.Fatalf("unexpected extra batch: sequence=%d openat=%d", extra.GetSequence(), len(extra.GetOpenatEvents()))
	case <-time.After(50 * time.Millisecond):
	}
	return got
}

func assertBatchOpenatCounts(t *testing.T, batches []*proto.EventBatch, counts ...int) {
	t.Helper()
	if len(batches) != len(counts) {
		t.Fatalf("batch count = %d, want %d", len(batches), len(counts))
	}
	for i, want := range counts {
		got := len(batches[i].GetOpenatEvents())
		if got != want {
			t.Fatalf("batch[%d] openat count = %d, want %d", i, got, want)
		}
	}
}

func assertBatchFilenames(t *testing.T, batches []*proto.EventBatch, want ...string) {
	t.Helper()
	if len(batches) != len(want) {
		t.Fatalf("batch count = %d, want %d filenames", len(batches), len(want))
	}
	for i, name := range want {
		events := batches[i].GetOpenatEvents()
		if len(events) != 1 {
			t.Fatalf("batch[%d] openat count = %d, want 1", i, len(events))
		}
		if got := events[0].GetEvent().GetFilename(); got != name {
			t.Fatalf("batch[%d] filename = %q, want %q", i, got, name)
		}
	}
}

func assertNoBatches(t *testing.T, ch <-chan *proto.EventBatch, within time.Duration) {
	t.Helper()
	select {
	case batch := <-ch:
		t.Fatalf("unexpected batch: sequence=%d openat=%d", batch.GetSequence(), len(batch.GetOpenatEvents()))
	case <-time.After(within):
	}
}

func assertBatchSequencesIncreasing(t *testing.T, batches []*proto.EventBatch) {
	t.Helper()
	for i := 1; i < len(batches); i++ {
		prev := batches[i-1].GetSequence()
		next := batches[i].GetSequence()
		if next <= prev {
			t.Fatalf("batch[%d] sequence = %d, want > %d", i, next, prev)
		}
	}
}

func disconnectStream(_ int, _ grpc.BidiStreamingServer[proto.EventBatch, proto.BatchAck]) error {
	return status.Error(codes.Unavailable, "test disconnect")
}

func collectBatchesTo(ch chan<- *proto.EventBatch) streamHandler {
	return func(_ int, stream grpc.BidiStreamingServer[proto.EventBatch, proto.BatchAck]) error {
		for {
			batch, err := stream.Recv()
			if err != nil {
				return err
			}
			ch <- batch
			if err := stream.Send(&proto.BatchAck{AckedThrough: batch.GetSequence()}); err != nil {
				return err
			}
		}
	}
}

func recvNBatchesThenDisconnect(ch chan<- *proto.EventBatch, n int) streamHandler {
	return func(_ int, stream grpc.BidiStreamingServer[proto.EventBatch, proto.BatchAck]) error {
		for i := 0; i < n; i++ {
			batch, err := stream.Recv()
			if err != nil {
				return err
			}
			ch <- batch
		}
		return status.Error(codes.Unavailable, "test disconnect")
	}
}

func TestConsumeEvents_reconnectKeepsBufferedEvents(t *testing.T) {
	batches := make(chan *proto.EventBatch, 32)
	h := startIntegrationHarness(t, harnessOptions{
		batches: batches,
		handlers: []streamHandler{
			disconnectStream,
			collectBatchesTo(batches),
		},
	})

	h.waitOpened(1)
	h.sendOpenat("/tmp/during-backoff-1")
	h.sendOpenat("/tmp/during-backoff-2")
	h.waitOpened(2)

	got := waitExactBatches(t, batches, 1)
	assertBatchOpenatCounts(t, got, 2)
}

func TestConsumeEvents_disconnectThenRecover(t *testing.T) {
	batches := make(chan *proto.EventBatch, 8)
	h := startIntegrationHarness(t, harnessOptions{
		batches:   batches,
		batchSize: 1,
		handlers: []streamHandler{
			disconnectStream,
			collectBatchesTo(batches),
		},
	})

	h.waitOpened(1)
	h.waitOpened(2)
	h.sendOpenat("/tmp/after-recover")

	got := waitExactBatches(t, batches, 1)
	assertBatchOpenatCounts(t, got, 1)
	assertBatchFilenames(t, got, "/tmp/after-recover")
}

func TestConsumeEvents_midStreamDisconnectBehavior(t *testing.T) {
	t.Run("successful_delivery_not_redelivered", func(t *testing.T) {
		stream1 := make(chan *proto.EventBatch, 8)
		stream2 := make(chan *proto.EventBatch, 8)
		h := startIntegrationHarness(t, harnessOptions{
			batchSize: 1,
			handlers: []streamHandler{
				recvNBatchesThenDisconnect(stream1, 1),
				collectBatchesTo(stream2),
			},
		})

		h.waitOpened(1)
		h.sendOpenat("/tmp/pending-a")

		first := waitExactBatches(t, stream1, 1)
		assertBatchOpenatCounts(t, first, 1)
		assertBatchFilenames(t, first, "/tmp/pending-a")

		h.waitOpened(2)
		assertNoBatches(t, stream2, 200*time.Millisecond)
	})

	t.Run("queued_event_delivered_on_new_stream", func(t *testing.T) {
		stream1 := make(chan *proto.EventBatch, 8)
		stream2 := make(chan *proto.EventBatch, 8)
		h := startIntegrationHarness(t, harnessOptions{
			batchSize: 1,
			handlers: []streamHandler{
				recvNBatchesThenDisconnect(stream1, 1),
				collectBatchesTo(stream2),
			},
		})

		h.waitOpened(1)
		h.sendOpenat("/tmp/first-on-stream1")

		first := waitExactBatches(t, stream1, 1)
		assertBatchFilenames(t, first, "/tmp/first-on-stream1")

		h.sendOpenat("/tmp/second-on-stream2")
		h.waitOpened(2)

		second := waitExactBatches(t, stream2, 1)
		assertBatchOpenatCounts(t, second, 1)
		assertBatchFilenames(t, second, "/tmp/second-on-stream2")
		assertBatchSequencesIncreasing(t, append(first, second...))
	})
}

func TestConsumeEvents_sequenceIncreasesAcrossReconnect(t *testing.T) {
	stream1 := make(chan *proto.EventBatch, 8)
	stream2 := make(chan *proto.EventBatch, 8)
	h := startIntegrationHarness(t, harnessOptions{
		batchSize: 1,
		handlers: []streamHandler{
			recvNBatchesThenDisconnect(stream1, 1),
			collectBatchesTo(stream2),
		},
	})

	h.waitOpened(1)
	h.sendOpenat("/tmp/seq-first")

	first := waitExactBatches(t, stream1, 1)
	h.sendOpenat("/tmp/seq-second")
	h.waitOpened(2)

	second := waitExactBatches(t, stream2, 1)
	assertBatchFilenames(t, first, "/tmp/seq-first")
	assertBatchFilenames(t, second, "/tmp/seq-second")
	assertBatchSequencesIncreasing(t, append(first, second...))
}

func TestConsumeEvents_repeatedDisconnectsThenDeliver(t *testing.T) {
	batches := make(chan *proto.EventBatch, 8)
	h := startIntegrationHarness(t, harnessOptions{
		batches:   batches,
		batchSize: 1,
		handlers: []streamHandler{
			disconnectStream,
			disconnectStream,
			collectBatchesTo(batches),
		},
	})

	h.waitOpened(1)
	h.waitOpened(2)
	h.waitOpened(3)
	h.sendOpenat("/tmp/third-stream")

	got := waitExactBatches(t, batches, 1)
	assertBatchOpenatCounts(t, got, 1)
	assertBatchFilenames(t, got, "/tmp/third-stream")
}

func TestConsumeEvents_cancelDuringBackoff(t *testing.T) {
	batches := make(chan *proto.EventBatch, 8)
	h := startIntegrationHarness(t, harnessOptions{
		batches: batches,
		handlers: []streamHandler{
			disconnectStream,
			collectBatchesTo(batches),
		},
	})

	h.waitOpened(1)
	h.cancel()
	h.assertNoOpen(2, 500*time.Millisecond)

	select {
	case batch := <-batches:
		t.Fatalf("unexpected batch after cancel: %+v", batch)
	case <-time.After(100 * time.Millisecond):
	}
}
