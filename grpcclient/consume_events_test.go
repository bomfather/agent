package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/bomfather/bomfather/agent/metrics"
	"github.com/bomfather/bomfather/agent/proto"
	"github.com/bomfather/bomfather/agent/reader"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type fakeEventIngestionClient struct {
	stream grpc.BidiStreamingClient[proto.EventBatch, proto.BatchAck]
}

func (f *fakeEventIngestionClient) StreamEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[proto.EventBatch, proto.BatchAck], error) {
	return f.stream, nil
}

type scriptedStreamClient struct {
	mu            sync.Mutex
	openFailures  int
	openErr       error
	streams       []grpc.BidiStreamingClient[proto.EventBatch, proto.BatchAck]
	nextStreamIdx int
}

func (c *scriptedStreamClient) StreamEvents(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[proto.EventBatch, proto.BatchAck], error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.openFailures > 0 {
		c.openFailures--
		err := c.openErr
		if err == nil {
			err = errors.New("simulated open failure")
		}
		return nil, fmt.Errorf("%w: %w", errOpenStream, err)
	}
	if c.nextStreamIdx >= len(c.streams) {
		return nil, errors.New("no more scripted streams")
	}
	stream := c.streams[c.nextStreamIdx]
	c.nextStreamIdx++
	return stream, nil
}

func (c *scriptedStreamClient) GetOrCreateNode(context.Context, *proto.GetOrCreateNodeRequest, ...grpc.CallOption) (*proto.GetOrCreateNodeResponse, error) {
	return nil, errors.New("not implemented in tests")
}

// eofSendStream returns io.EOF from Send and then ends Recv so streamOnce exits with pending kept.
type eofSendStream struct {
	ctx         context.Context
	cancel      context.CancelFunc
	attemptedCh chan *proto.EventBatch
}

func newEOFSendStream(parent context.Context) *eofSendStream {
	ctx, cancel := context.WithCancel(parent)
	return &eofSendStream{
		ctx:         ctx,
		cancel:      cancel,
		attemptedCh: make(chan *proto.EventBatch, 1),
	}
}

func (s *eofSendStream) Send(batch *proto.EventBatch) error {
	select {
	case s.attemptedCh <- cloneBatch(batch):
	default:
	}
	s.cancel()
	return io.EOF
}

func (s *eofSendStream) Recv() (*proto.BatchAck, error) {
	<-s.ctx.Done()
	return nil, io.EOF
}

func (s *eofSendStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (s *eofSendStream) Trailer() metadata.MD         { return metadata.MD{} }
func (s *eofSendStream) CloseSend() error             { return nil }
func (s *eofSendStream) Context() context.Context     { return s.ctx }
func (s *eofSendStream) SendMsg(any) error            { return nil }
func (s *eofSendStream) RecvMsg(any) error            { return io.EOF }

func (f *fakeEventIngestionClient) GetOrCreateNode(ctx context.Context, in *proto.GetOrCreateNodeRequest, opts ...grpc.CallOption) (*proto.GetOrCreateNodeResponse, error) {
	return nil, errors.New("not implemented in tests")
}

type fakeBidiStream struct {
	ctx context.Context

	mu        sync.Mutex
	sendCalls int
	sendErrs  []error
	sentCh    chan *proto.EventBatch
	callCh    chan int
}

func newFakeBidiStream(ctx context.Context, sendErrs ...error) *fakeBidiStream {
	return &fakeBidiStream{
		ctx:      ctx,
		sendErrs: sendErrs,
		sentCh:   make(chan *proto.EventBatch, 32),
		callCh:   make(chan int, 32),
	}
}

func (f *fakeBidiStream) Send(batch *proto.EventBatch) error {
	f.mu.Lock()
	f.sendCalls++
	callIdx := f.sendCalls
	if len(f.callCh) < cap(f.callCh) {
		f.callCh <- callIdx
	}
	f.mu.Unlock()

	var err error
	if callIdx-1 < len(f.sendErrs) {
		err = f.sendErrs[callIdx-1]
	}
	if err != nil {
		return err
	}
	if len(f.sentCh) < cap(f.sentCh) {
		f.sentCh <- cloneBatch(batch)
	}
	return nil
}

func (f *fakeBidiStream) Recv() (*proto.BatchAck, error) {
	// Block until the stream context ends so recvUntilDone stays alive for the
	// session (mirrors a live bidi stream that only closes when the RPC ends).
	<-f.ctx.Done()
	return nil, f.ctx.Err()
}

func (f *fakeBidiStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (f *fakeBidiStream) Trailer() metadata.MD         { return metadata.MD{} }
func (f *fakeBidiStream) CloseSend() error             { return nil }
func (f *fakeBidiStream) Context() context.Context     { return f.ctx }
func (f *fakeBidiStream) SendMsg(any) error            { return nil }
func (f *fakeBidiStream) RecvMsg(any) error            { return io.EOF }

func cloneBatch(src *proto.EventBatch) *proto.EventBatch {
	if src == nil {
		return nil
	}
	return &proto.EventBatch{
		Sequence:       src.Sequence,
		BatchId:        src.BatchId,
		TimestampNanos: src.TimestampNanos,
		OpenatEvents:   append([]*proto.OpenatEventWrapper(nil), src.OpenatEvents...),
		ExecveEvents:   append([]*proto.ExecveEventWrapper(nil), src.ExecveEvents...),
		Violations:     append([]*proto.ViolationEventWrapper(nil), src.Violations...),
	}
}

func newTestStreams() reader.EventStreams {
	return reader.EventStreams{
		OpenatStream:    make(chan *proto.OpenatEventWrapper, 64),
		ExecveStream:    make(chan *proto.ExecveEventWrapper, 64),
		ViolationStream: make(chan *proto.ViolationEventWrapper, 64),
	}
}

func mustBatch(t *testing.T, ch <-chan *proto.EventBatch) *proto.EventBatch {
	t.Helper()
	return mustBatchWithin(t, ch, 2*time.Second)
}

func mustBatchWithin(t *testing.T, ch <-chan *proto.EventBatch, within time.Duration) *proto.EventBatch {
	t.Helper()
	select {
	case batch := <-ch:
		return batch
	case <-time.After(within):
		t.Fatalf("timed out after %v waiting for sent batch", within)
		return nil
	}
}

func mustCall(t *testing.T, ch <-chan int) int {
	t.Helper()
	select {
	case n := <-ch:
		return n
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for send call")
		return 0
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestConsumeEventsSendsOpenatBatch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newFakeBidiStream(ctx)
	client := &DefaultClient{grpcClient: &fakeEventIngestionClient{stream: stream}}
	streams := newTestStreams()
	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/first"}}

	client.ConsumeEvents(ctx, testLogger(), streams, 1, 1, 1*time.Second)

	var got *proto.EventBatch
	deadline := time.After(2 * time.Second)
	for got == nil {
		select {
		case <-deadline:
			t.Fatal("did not receive non-empty openat batch")
		case batch := <-stream.sentCh:
			if len(batch.OpenatEvents) == 1 {
				got = batch
			}
		}
	}

	if got.Sequence == 0 {
		t.Fatalf("expected positive sequence, got %d", got.Sequence)
	}
	if len(got.ExecveEvents) != 0 || len(got.Violations) != 0 {
		t.Fatalf("expected only openat events, got execve=%d violations=%d", len(got.ExecveEvents), len(got.Violations))
	}
	if got.OpenatEvents[0].GetEvent().GetFilename() != "/tmp/first" {
		t.Fatalf("unexpected filename: got %q", got.OpenatEvents[0].GetEvent().GetFilename())
	}
}

func TestConsumeEventsRetriesPendingBatchBeforeNewDrain(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newFakeBidiStream(ctx, errors.New("send failed"))
	client := &DefaultClient{grpcClient: &fakeEventIngestionClient{stream: stream}}
	streams := newTestStreams()

	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/first"}}
	client.ConsumeEvents(ctx, testLogger(), streams, 1, 1, 1*time.Second)

	_ = mustCall(t, stream.callCh) // first send attempt (fails)
	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/second"}}

	firstSuccess := mustBatch(t, stream.sentCh)
	secondSuccess := mustBatch(t, stream.sentCh)

	if len(firstSuccess.OpenatEvents) != 1 || firstSuccess.OpenatEvents[0].GetEvent().GetFilename() != "/tmp/first" {
		t.Fatalf("expected retried pending batch with first event, got %+v", firstSuccess.OpenatEvents)
	}
	if len(secondSuccess.OpenatEvents) != 1 || secondSuccess.OpenatEvents[0].GetEvent().GetFilename() != "/tmp/second" {
		t.Fatalf("expected next drained batch with second event, got %+v", secondSuccess.OpenatEvents)
	}
	if secondSuccess.Sequence <= firstSuccess.Sequence {
		t.Fatalf("expected sequence increase, first=%d second=%d", firstSuccess.Sequence, secondSuccess.Sequence)
	}
}

func TestConsumeEvents_pendingSurvivesReconnectAfterSendEOF(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eofStream := newEOFSendStream(ctx)
	successStream := newFakeBidiStream(ctx)
	grpcClient := &scriptedStreamClient{
		streams: []grpc.BidiStreamingClient[proto.EventBatch, proto.BatchAck]{
			eofStream,
			successStream,
		},
	}
	client := &DefaultClient{grpcClient: grpcClient}
	streams := newTestStreams()

	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/first"}}
	client.ConsumeEvents(ctx, testLogger(), streams, 1, 1, 50*time.Millisecond)

	attempted := mustBatch(t, eofStream.attemptedCh)
	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/second"}}

	firstOnStream2 := mustBatchWithin(t, successStream.sentCh, 5*time.Second)
	secondOnStream2 := mustBatchWithin(t, successStream.sentCh, 5*time.Second)

	if firstOnStream2.BatchId != attempted.BatchId {
		t.Fatalf("pending batch id = %q, want %q", firstOnStream2.BatchId, attempted.BatchId)
	}
	if firstOnStream2.Sequence != attempted.Sequence {
		t.Fatalf("pending sequence = %d, want %d", firstOnStream2.Sequence, attempted.Sequence)
	}
	if len(firstOnStream2.OpenatEvents) != 1 || firstOnStream2.OpenatEvents[0].GetEvent().GetFilename() != "/tmp/first" {
		t.Fatalf("expected retried pending batch with first event, got %+v", firstOnStream2.OpenatEvents)
	}
	if len(secondOnStream2.OpenatEvents) != 1 || secondOnStream2.OpenatEvents[0].GetEvent().GetFilename() != "/tmp/second" {
		t.Fatalf("expected next drained batch with second event, got %+v", secondOnStream2.OpenatEvents)
	}
	if secondOnStream2.Sequence <= firstOnStream2.Sequence {
		t.Fatalf("expected sequence increase, first=%d second=%d", firstOnStream2.Sequence, secondOnStream2.Sequence)
	}

	select {
	case extra := <-successStream.sentCh:
		t.Fatalf("unexpected extra batch on stream 2: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestConsumeEvents_recoversAfterStreamOpenFailure(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	successStream := newFakeBidiStream(ctx)
	grpcClient := &scriptedStreamClient{
		openFailures: 1,
		streams: []grpc.BidiStreamingClient[proto.EventBatch, proto.BatchAck]{
			successStream,
		},
	}
	client := &DefaultClient{grpcClient: grpcClient}
	streams := newTestStreams()

	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/during-open-failure"}}
	client.ConsumeEvents(ctx, testLogger(), streams, 1, 1, 50*time.Millisecond)

	got := mustBatchWithin(t, successStream.sentCh, 5*time.Second)
	if len(got.OpenatEvents) != 1 || got.OpenatEvents[0].GetEvent().GetFilename() != "/tmp/during-open-failure" {
		t.Fatalf("expected buffered event after open failure, got %+v", got.OpenatEvents)
	}

	select {
	case extra := <-successStream.sentCh:
		t.Fatalf("unexpected extra batch: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestConsumeEventsUpdatesStreamAndQueueMetrics(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, agentMetrics := metrics.NewRegistry()
	stream := newFakeBidiStream(ctx)
	client := &DefaultClient{
		grpcClient: &fakeEventIngestionClient{stream: stream},
		metrics:    agentMetrics,
	}
	streams := newTestStreams()
	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/queued"}}

	client.ConsumeEvents(ctx, testLogger(), streams, 8, 1, 50*time.Millisecond)

	waitForGauge(t, agentMetrics.GRPCStreamConnected, 1)
	_ = mustBatch(t, stream.sentCh)
	waitForGauge(t, agentMetrics.GRPCQueueLength.WithLabelValues(metrics.Openat), 0)
	if got := gaugeValue(agentMetrics.GRPCStreamConnected); got != 1 {
		t.Fatalf("expected stream connected=1, got %v", got)
	}
}

func TestConsumeEventsQueueMetricsIncludePendingBatch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, agentMetrics := metrics.NewRegistry()
	stream := newFakeBidiStream(ctx, errors.New("send failed"), errors.New("send failed"))
	client := &DefaultClient{
		grpcClient: &fakeEventIngestionClient{stream: stream},
		metrics:    agentMetrics,
	}
	streams := newTestStreams()
	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/pending"}}

	client.ConsumeEvents(ctx, testLogger(), streams, 8, 1, 50*time.Millisecond)

	_ = mustCall(t, stream.callCh) // first send fails and leaves pending
	waitForGauge(t, agentMetrics.GRPCQueueLength.WithLabelValues(metrics.Openat), 1)

	streams.OpenatStream <- &proto.OpenatEventWrapper{Event: &proto.OpenatEvent{Filename: "/tmp/queued"}}
	waitForGauge(t, agentMetrics.GRPCQueueLength.WithLabelValues(metrics.Openat), 2)
}

func waitForGauge(t *testing.T, g prometheus.Gauge, want float64) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if gaugeValue(g) == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for gauge=%v, last=%v", want, gaugeValue(g))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func gaugeValue(g prometheus.Gauge) float64 {
	ch := make(chan prometheus.Metric, 1)
	g.Collect(ch)
	m := <-ch
	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		return -1
	}
	return pb.GetGauge().GetValue()
}
