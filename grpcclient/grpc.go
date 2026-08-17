package grpcclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"math/rand"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/bomfather/bomfather/agent/metrics"
	"github.com/bomfather/bomfather/agent/proto"
	"github.com/bomfather/bomfather/agent/reader"
)

const (
	MetadataKeyAPIKey        = "x-api-key"
	MetadataKeyHostname      = "x-hostname"
	MetadataKeyCorrelationID = "x-request-id"
	healthcheckInterval      = 5 * time.Minute
	healthcheckTimeout       = 10 * time.Second
	serviceName              = "ingestion.EventIngestion"
	reconnectBaseDelay       = 1 * time.Second
	reconnectMaxDelay        = 30 * time.Second
)

var (
	Version          = ""
	Commit           = ""
	registerZstdOnce sync.Once
)

// errOpenStream marks a failed StreamEvents open so ConsumeEvents can ramp
// backoff on consecutive open failures and reset after a session that opened.
var errOpenStream = errors.New("open stream")
var errAuthFailure = errors.New("auth failure")

type Client interface {
	// ConsumeEvents starts the stream loop in the background. The returned
	// channel receives at most one fatal auth error; nil means never-fatal
	// (e.g. local/dummy mode). Callers should exit the process on receive.
	ConsumeEvents(ctx context.Context, logger *slog.Logger, streams reader.EventStreams, bufferSize int, batchSize int, batchInterval time.Duration) <-chan error
	GetOrCreateNode(ctx context.Context, logger *slog.Logger) (uint64, error)
	StartHealthcheck(ctx context.Context, logger *slog.Logger)
}

type DefaultClient struct {
	grpcClient    proto.EventIngestionClient
	conn          *grpc.ClientConn
	apiKey        string
	hostname      string
	correlationID string
	metrics       *metrics.Metrics
}

// DummyClient is a client for when there is no connection to the server.
type DummyClient struct{}

type ringbuf[T any] struct {
	items    []T
	head     int
	len      int
	capacity int
}

// sessionConfig encapsulates contextual information and settings (such as logger, input event channels, and batching interval)
// that remain constant across reconnection attempts in the gRPC event streaming loop (streamOnce).
type sessionConfig struct {
	logger        *slog.Logger
	streams       reader.EventStreams
	batchInterval time.Duration
}

// batcher buffers events in bounded rings for the ConsumeEvents lifetime so
// sequence and undrained events survive reconnects. drain copies into a new
// EventBatch so a pending send does not alias the scratch buffers.
type batcher struct {
	openatQueue    *ringbuf[*proto.OpenatEventWrapper]
	execveQueue    *ringbuf[*proto.ExecveEventWrapper]
	violationQueue *ringbuf[*proto.ViolationEventWrapper]

	openatScratch    []*proto.OpenatEventWrapper
	execveScratch    []*proto.ExecveEventWrapper
	violationScratch []*proto.ViolationEventWrapper

	batchSize int
	sequence  uint64
}

func newBatcher(bufferSize, batchSize int) *batcher {
	return &batcher{
		openatQueue:      newRingbuf[*proto.OpenatEventWrapper](bufferSize),
		execveQueue:      newRingbuf[*proto.ExecveEventWrapper](bufferSize),
		violationQueue:   newRingbuf[*proto.ViolationEventWrapper](bufferSize),
		openatScratch:    make([]*proto.OpenatEventWrapper, batchSize),
		execveScratch:    make([]*proto.ExecveEventWrapper, batchSize),
		violationScratch: make([]*proto.ViolationEventWrapper, batchSize),
		batchSize:        batchSize,
	}
}

// drain pops up to batchSize of each event type into a new sequenced batch.
// Event slices are copied so a held pending batch is not aliased to the
// scratch buffers. The bool is false when every queue is empty.
func (b *batcher) drain() (*proto.EventBatch, bool) {
	openatCount := b.openatQueue.pop(b.batchSize, b.openatScratch)
	execveCount := b.execveQueue.pop(b.batchSize, b.execveScratch)
	violationCount := b.violationQueue.pop(b.batchSize, b.violationScratch)
	if openatCount == 0 && execveCount == 0 && violationCount == 0 {
		return nil, false
	}
	b.sequence++
	return &proto.EventBatch{
		Sequence:       b.sequence,
		BatchId:        uuid.New().String(),
		TimestampNanos: time.Now().UnixNano(),
		OpenatEvents:   append([]*proto.OpenatEventWrapper(nil), b.openatScratch[:openatCount]...),
		ExecveEvents:   append([]*proto.ExecveEventWrapper(nil), b.execveScratch[:execveCount]...),
		Violations:     append([]*proto.ViolationEventWrapper(nil), b.violationScratch[:violationCount]...),
	}, true
}

func (b *batcher) pushOpenat(event *proto.OpenatEventWrapper) {
	b.openatQueue.push(event)
}

func (b *batcher) pushExecve(event *proto.ExecveEventWrapper) {
	b.execveQueue.push(event)
}

func (b *batcher) pushViolation(logger *slog.Logger, event *proto.ViolationEventWrapper) {
	violation := event.GetEvent()
	logger.Info("violation", "type", violation.GetType(), "exe", violation.GetExepath(), "file", violation.GetFilename(), "container", event.GetContainerPath())
	b.violationQueue.push(event)
}

type zstdCompressor struct{}

type healthChecker interface {
	Check(ctx context.Context, in *grpc_health_v1.HealthCheckRequest, opts ...grpc.CallOption) (*grpc_health_v1.HealthCheckResponse, error)
}

func newRingbuf[T any](capacity int) *ringbuf[T] {
	return &ringbuf[T]{
		items:    make([]T, capacity),
		capacity: capacity,
	}
}

func (q *ringbuf[T]) push(item T) {
	if q.len == q.capacity {
		q.head = (q.head + 1) % q.capacity
		q.len = q.capacity - 1
	}
	q.items[(q.head+q.len)%q.capacity] = item
	q.len++
}

func (q *ringbuf[T]) pop(count int, buf []T) int {
	if q.len < count {
		count = q.len
	}
	if q.capacity-q.head >= count {
		copy(buf, q.items[q.head:q.head+count])
		q.head = (q.head + count) % q.capacity
		q.len -= count
	} else {
		right := q.capacity - q.head
		left := count - right

		copy(buf[:right], q.items[q.head:])
		copy(buf[right:count], q.items[:left])
		q.head = count - (q.capacity - q.head)
		q.len -= count
	}
	return count
}

func (q *ringbuf[T]) length() int {
	return q.len
}

func RegisterZstdCompressor() {
	registerZstdOnce.Do(func() {
		encoding.RegisterCompressor(zstdCompressor{})
	})
}

func (zstdCompressor) Name() string { return "zstd" }

func (zstdCompressor) Compress(w io.Writer) (io.WriteCloser, error) { return zstd.NewWriter(w) }

func (zstdCompressor) Decompress(r io.Reader) (io.Reader, error) { return zstd.NewReader(r) }

func parseServerURL(serverURL string) (addr string, useTLS bool, err error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", false, fmt.Errorf("invalid URL: %w", err)
	}

	switch u.Scheme {
	case "grpc":
		useTLS = false
	case "https":
		useTLS = true
	default:
		return "", false, fmt.Errorf("unsupported scheme: %s (use grpc:// or https://)", u.Scheme)
	}

	host := u.Host
	if u.Port() == "" {
		if useTLS {
			host = host + ":443"
		} else {
			host = host + ":50051"
		}
	}

	return host, useTLS, nil
}

func NewDefaultClient(serverURL string, apiKey string, runtimeMetrics *metrics.Metrics) (*DefaultClient, error) {
	RegisterZstdCompressor()

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("get hostname: %w", err)
	}
	correlationID := uuid.New().String()
	c := &DefaultClient{
		apiKey:        apiKey,
		hostname:      hostname,
		correlationID: correlationID,
		metrics:       runtimeMetrics,
	}

	addr, useTLS, err := parseServerURL(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}

	serviceConfig := fmt.Sprintf(`{
		"healthCheckConfig": {
			"serviceName": "%s"
		},
		"methodConfig": [{
			"name": [{"service": "%s"}],
			"waitForReady": true
		}]
	}`, serviceName, serviceName)

	dialOpts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.UseCompressor("zstd"),
			grpc.MaxCallSendMsgSize(16*1024*1024), // 16MB
			grpc.MaxCallRecvMsgSize(4*1024*1024),  // 4MB
		),
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithMaxHeaderListSize(64 * 1024), // 64KB
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if useTLS {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}),
		))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	c.conn = conn
	c.grpcClient = proto.NewEventIngestionClient(conn)

	return c, nil
}

func NewDummyClient() *DummyClient {
	return &DummyClient{}
}

// StartHealthcheck starts the healthcheck loop.
// It creates a new ticker and starts the healthcheck loop.
// The healthcheck loop runs every 5 minutes and checks the health of the server.
// If the healthcheck fails, it logs an error.
// The healthcheck loop is stopped when the context is done.
func (c *DefaultClient) StartHealthcheck(ctx context.Context, logger *slog.Logger) {
	if c.conn == nil {
		return
	}

	healthClient := grpc_health_v1.NewHealthClient(c.conn)
	go func() {
		ticker := time.NewTicker(healthcheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.runHealthcheckOnce(ctx, healthClient, healthcheckTimeout); err != nil {
					logger.Warn("healthcheck failed", "error", err)
				}
			}
		}
	}()
}
func (c *DummyClient) StartHealthcheck(ctx context.Context, logger *slog.Logger) {}

func (c *DefaultClient) runHealthcheckOnce(ctx context.Context, checker healthChecker, timeout time.Duration) error {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_, err := checker.Check(c.withAuth(callCtx), &grpc_health_v1.HealthCheckRequest{Service: serviceName})
	if err != nil {
		c.setState(metrics.StateDegraded)
	} else {
		c.setState(metrics.StateRunning)
	}
	return err
}

func (c *DefaultClient) withAuth(ctx context.Context) context.Context {
	ctx = metadata.AppendToOutgoingContext(ctx, MetadataKeyAPIKey, c.apiKey)
	if c.hostname != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, MetadataKeyHostname, c.hostname)
	}
	if c.correlationID != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, MetadataKeyCorrelationID, c.correlationID)
	}
	return ctx
}

func sendBatch(stream proto.EventIngestion_StreamEventsClient, newBatch *proto.EventBatch) error {
	if newBatch == nil {
		return nil
	}
	if err := stream.Send(newBatch); err != nil {
		return fmt.Errorf("send batch: %w", err)
	}
	return nil
}

// jitteredBackoff returns a backoff duration with jitter.
func jitteredBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	// To handle where the attempt is too large.
	maxShift := bits.UintSize - 2
	if attempt > maxShift {
		attempt = maxShift
	}
	backoff := reconnectBaseDelay * (1 << attempt)
	if backoff <= 0 || backoff > reconnectMaxDelay {
		backoff = reconnectMaxDelay
	}
	// The jitter is for preventing thundering herd problem on the server side.
	jitter := time.Duration(rand.Int63n(int64(backoff)))
	return backoff + jitter
}

// Send the error once on done (buffered chan). Ignore ack payloads for now.
func recvUntilDone(stream proto.EventIngestion_StreamEventsClient, done chan<- error) {
	for {
		ack, err := stream.Recv()
		if err != nil {
			done <- err
			return
		}
		// TODO(batch-acks): process BatchAck (sequence / success / error_code)
		_ = ack
	}
}

// openStream tries StreamEvents once. It does not retry or sleep: ConsumeEvents
// owns reconnect backoff via acceptDuringBackoff so event channels keep draining.
// WaitForReady(false) overrides the service-config waitForReady so a down server
// fails fast instead of blocking this goroutine (and stalling unbuffered producers).
func (c *DefaultClient) openStream(ctx context.Context, logger *slog.Logger) (proto.EventIngestion_StreamEventsClient, error) {
	stream, err := c.grpcClient.StreamEvents(c.withAuth(ctx), grpc.WaitForReady(false))
	if err != nil {
		c.setStreamConnected(false)
		c.setState(metrics.StateDegraded)
		logger.Error("failed to open stream", "error", err)
		return nil, fmt.Errorf("%w: %w", errOpenStream, err)
	}
	logger.Debug("stream opened")
	return stream, nil
}

// openStreamWhileDraining opens a stream while draining the event channels.
func (c *DefaultClient) openStreamWhileDraining(ctx context.Context, cfg sessionConfig, b *batcher) (proto.EventIngestion_StreamEventsClient, error) {
	type openResult struct {
		stream proto.EventIngestion_StreamEventsClient
		err    error
	}

	openCh := make(chan openResult, 1)
	go func() {
		stream, err := c.openStream(ctx, cfg.logger)
		openCh <- openResult{stream: stream, err: err}
	}()

	for {
		// Prefer ctx/open when already ready so event floods cannot delay open.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-openCh:
			return result.stream, result.err
		default:
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-openCh:
			return result.stream, result.err
		case event := <-cfg.streams.OpenatStream:
			b.pushOpenat(event)
		case event := <-cfg.streams.ExecveStream:
			b.pushExecve(event)
		case event := <-cfg.streams.ViolationStream:
			b.pushViolation(cfg.logger, event)
		}
	}
}

// closeAndWait stops the send direction and waits for recvUntilDone to return.
// This happens when the stream is closed from the server side.
func closeAndWait(stream proto.EventIngestion_StreamEventsClient, recvDone <-chan error) {
	_ = stream.CloseSend()
	<-recvDone
}

func (c *DefaultClient) reportQueueMetrics(b *batcher, pending *proto.EventBatch) {
	pendingOpenat, pendingExecve, pendingViolation := 0, 0, 0
	if pending != nil {
		pendingOpenat = len(pending.OpenatEvents)
		pendingExecve = len(pending.ExecveEvents)
		pendingViolation = len(pending.Violations)
	}
	c.setQueueLengths(
		b.openatQueue.length()+pendingOpenat,
		b.execveQueue.length()+pendingExecve,
		b.violationQueue.length()+pendingViolation,
	)
}

func (c *DefaultClient) streamOnce(ctx context.Context, cfg sessionConfig, b *batcher, pending *proto.EventBatch) (*proto.EventBatch, error) {
	stream, err := c.openStreamWhileDraining(ctx, cfg, b)
	if err != nil {
		c.setStreamConnected(false)
		c.setState(metrics.StateDegraded)
		c.reportQueueMetrics(b, pending)
		return pending, fmt.Errorf("open stream: %w", err)
	}
	c.setStreamConnected(true)
	c.setState(metrics.StateRunning)
	defer c.setStreamConnected(false)

	recvDone := make(chan error, 1)
	go recvUntilDone(stream, recvDone)

	t := time.NewTicker(cfg.batchInterval)
	defer t.Stop()
	sending := true
	c.reportQueueMetrics(b, pending)
	for {
		// Prefer ctx/recvDone when already ready so event floods cannot delay
		// session teardown and reconnect after the stream is dead. They are
		// repeated in the blocking select below to cover readiness after this
		// non-blocking priority check.
		select {
		case <-ctx.Done():
			closeAndWait(stream, recvDone)
			return pending, ctx.Err()
		case err := <-recvDone:
			c.setState(metrics.StateDegraded)
			return pending, fmt.Errorf("recv until done: %w", err)
		default:
		}
		select {
		case <-ctx.Done():
			closeAndWait(stream, recvDone)
			return pending, ctx.Err()
		case err := <-recvDone:
			c.setState(metrics.StateDegraded)
			return pending, fmt.Errorf("recv until done: %w", err)
		case <-t.C:
			if !sending {
				continue // send side dead; Recv owns the exit
			}
			if pending == nil {
				batch, ok := b.drain()
				if !ok {
					continue // nothing buffered this interval; skip the empty send
				}
				pending = batch
			}
			if err := sendBatch(stream, pending); err != nil {
				cfg.logger.Error("failed to send event batch", "error", err)
				c.setStreamConnected(false)
				c.setState(metrics.StateDegraded)
				c.reportQueueMetrics(b, pending)
				if errors.Is(err, io.EOF) {
					// Per grpc-go ClientStream.SendMsg: non-client Send errors
					// return io.EOF and "the status of the stream may be
					// discovered using RecvMsg"
					// (https://github.com/grpc/grpc-go/blob/master/stream.go#L115-L118,
					// https://pkg.go.dev/google.golang.org/grpc#ClientStream).
					// Maintainer: if Send returns io.EOF, call Recv for status
					// (https://github.com/grpc/grpc-go/issues/8190#issuecomment-2641471450).
					// Stop sending; keep pending; Recv (recvDone) owns the exit.
					sending = false
					continue
				}
				// Transient error and we will retry pending on this stream next tick.
				continue
			}
			pending = nil
			c.setStreamConnected(true)
			c.setState(metrics.StateRunning)
			c.reportQueueMetrics(b, pending)
		case event := <-cfg.streams.OpenatStream:
			b.pushOpenat(event)
			c.reportQueueMetrics(b, pending)
		case event := <-cfg.streams.ExecveStream:
			b.pushExecve(event)
			c.reportQueueMetrics(b, pending)
		case event := <-cfg.streams.ViolationStream:
			b.pushViolation(cfg.logger, event)
			c.reportQueueMetrics(b, pending)
		}
	}
}

// acceptDuringBackoff keeps draining event channels into the batcher until the
// backoff elapses or ctx is cancelled. Reconnect sleeps the send path only —
// producers on unbuffered channels must not block for the whole backoff window.
// After the timer fires, exit promptly: a fair select among ready event cases
// could otherwise starve t.C under steady traffic and delay reconnect.
func acceptDuringBackoff(ctx context.Context, cfg sessionConfig, b *batcher, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		// Prefer timer/ctx when already ready so event floods cannot prolong backoff.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		case event := <-cfg.streams.OpenatStream:
			b.pushOpenat(event)
		case event := <-cfg.streams.ExecveStream:
			b.pushExecve(event)
		case event := <-cfg.streams.ViolationStream:
			b.pushViolation(cfg.logger, event)
		}
	}
}

func (c *DefaultClient) ConsumeEvents(ctx context.Context, logger *slog.Logger, streams reader.EventStreams, bufferSize int, batchSize int, batchInterval time.Duration) <-chan error {
	fatalCh := make(chan error, 1)
	if bufferSize <= 0 || batchSize <= 0 || batchInterval <= 0 {
		logger.Error("invalid event consumer configuration", "buffer_size", bufferSize, "batch_size", batchSize, "batch_interval", batchInterval)
		return fatalCh
	}

	go func() {
		cfg := sessionConfig{
			logger:        logger,
			streams:       streams,
			batchInterval: batchInterval,
		}
		// This is for batching events and sending them to the server.
		b := newBatcher(bufferSize, batchSize)
		var pending *proto.EventBatch
		attempt := 0
		c.setStreamConnected(false)
		for ctx.Err() == nil {
			var err error
			pending, err = c.streamOnce(ctx, cfg, b, pending)
			if ctx.Err() != nil {
				return
			}
			if isAuthFailure(err) {
				c.setStreamConnected(false)
				c.setState(metrics.StateDegraded)
				c.reportQueueMetrics(b, pending)
				logger.Error("stream auth failure; stopping reconnects", "error", err)
				fatalCh <- fmt.Errorf("%w: %w", errAuthFailure, err)
				return
			}
			opened := !errors.Is(err, errOpenStream)
			if opened {
				attempt = 0 // session ran; next backoff starts from the base delay
			}
			c.setStreamConnected(false)
			c.setState(metrics.StateDegraded)
			c.reportQueueMetrics(b, pending)
			logger.Error("stream session ended; reconnecting", "error", err, "attempt", attempt)
			if err := acceptDuringBackoff(ctx, cfg, b, jitteredBackoff(attempt)); err != nil {
				return
			}
			if !opened {
				attempt++
			}
		}
	}()
	return fatalCh
}

// isAuthFailure reports whether err is an auth rejection that should stop reconnects.
func isAuthFailure(err error) bool {
	if errors.Is(err, errAuthFailure) {
		return true
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	return st.Code() == codes.Unauthenticated || st.Code() == codes.PermissionDenied
}

func (c *DefaultClient) GetOrCreateNode(ctx context.Context, logger *slog.Logger) (uint64, error) {
	response, err := c.grpcClient.GetOrCreateNode(c.withAuth(ctx), &proto.GetOrCreateNodeRequest{
		Hostname:       c.hostname,
		TimestampNanos: time.Now().UnixNano(),
		AgentVersion:   GetVersion(),
	})
	if err != nil {
		c.setState(metrics.StateDegraded)
		return 0, fmt.Errorf("get or create node: %w", err)
	}
	if response.ErrorCode != proto.ErrorCode_ERROR_CODE_UNSPECIFIED {
		c.setState(metrics.StateDegraded)
		return 0, fmt.Errorf("server error: %s", response.ErrorMessage)
	}
	c.setState(metrics.StateRunning)
	logger.Info("node created", "node_id", response.NodeId)
	return response.NodeId, nil
}

func (c *DummyClient) ConsumeEvents(ctx context.Context, logger *slog.Logger, streams reader.EventStreams, bufferSize int, batchSize int, batchInterval time.Duration) <-chan error {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-streams.OpenatStream:
			case <-streams.ExecveStream:
			case event := <-streams.ViolationStream:
				logger.Info("violation", "type", event.Event.Type, "exe", event.Event.Exepath, "file", event.Event.Filename, "container", event.ContainerPath)
			}
		}
	}()
	return nil
}
func (c *DummyClient) GetOrCreateNode(ctx context.Context, logger *slog.Logger) (uint64, error) {
	return 0, nil
}

func (c *DefaultClient) setState(state int) {
	if c.metrics != nil {
		c.metrics.SetComponentState(metrics.ComponentGRPC, state)
	}
}

func (c *DefaultClient) setStreamConnected(connected bool) {
	if c.metrics == nil {
		return
	}
	if connected {
		c.metrics.GRPCStreamConnected.Set(1)
		return
	}
	c.metrics.GRPCStreamConnected.Set(0)
}

func (c *DefaultClient) setQueueLength(queue string, length int) {
	if c.metrics != nil {
		c.metrics.GRPCQueueLength.WithLabelValues(queue).Set(float64(length))
	}
}

func (c *DefaultClient) setQueueLengths(openat, execve, violation int) {
	c.setQueueLength(metrics.Openat, openat)
	c.setQueueLength(metrics.Execve, execve)
	c.setQueueLength(metrics.Violation, violation)
}

func GetVersion() string {
	if Version != "" {
		return fmt.Sprintf("%s (commit: %s)", Version, shortSHA(Commit))
	}
	return shortSHA(Commit)
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
