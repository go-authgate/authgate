package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/util"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

// Compile-time interface check.
var _ core.AuditLogger = (*AuditService)(nil)

// auditEventsDropped is a singleton counter registered once via sync.Once
// to avoid duplicate-registration panics when multiple AuditService
// instances are created (e.g. in tests).
//
// The counter is only registered with Prometheus when a registerer is
// explicitly provided via SetAuditMetricsRegisterer, so deployments with
// metrics disabled do not leak collectors from the services layer.
var (
	auditEventsDropped           prometheus.Counter
	auditEventsDroppedOnce       sync.Once
	auditEventsDroppedRegisterer prometheus.Registerer
)

// SetAuditMetricsRegisterer configures the Prometheus registerer used by the
// audit service. It must be called before any AuditService is created in order
// for the dropped-events counter to be registered with Prometheus.
func SetAuditMetricsRegisterer(registerer prometheus.Registerer) {
	auditEventsDroppedRegisterer = registerer
}

func getAuditEventsDroppedCounter() prometheus.Counter {
	auditEventsDroppedOnce.Do(func() {
		opts := prometheus.CounterOpts{
			Namespace: "authgate",
			Subsystem: "audit",
			Name:      "events_dropped_total",
			Help:      "Total number of audit log events dropped due to a full buffer.",
		}
		counter := prometheus.NewCounter(opts)

		if auditEventsDroppedRegisterer != nil {
			if err := auditEventsDroppedRegisterer.Register(counter); err != nil {
				if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
					if c, ok := existing.ExistingCollector.(prometheus.Counter); ok {
						auditEventsDropped = c
						return
					}
				}
				log.Printf("failed to register audit dropped-events counter: %v", err)
			}
		}
		// When no registerer is set, the counter still works in-memory but
		// is not exposed via the Prometheus /metrics endpoint.
		auditEventsDropped = counter
	})
	return auditEventsDropped
}

// AuditService handles audit logging operations
type AuditService struct {
	store      core.Store
	bufferSize int

	// Async logging channel
	logChan chan *models.AuditLog

	// Batch buffer
	batchBuffer []*models.AuditLog
	batchMutex  sync.Mutex
	batchTicker *time.Ticker

	// Graceful shutdown
	wg      sync.WaitGroup
	sendMu  sync.RWMutex // coordinates Log() senders with Shutdown()
	stopped atomic.Bool

	// Prometheus counter for dropped events
	eventsDropped prometheus.Counter
}

// NewAuditService creates a new audit service
func NewAuditService(s core.Store, bufferSize int) *AuditService {
	if bufferSize <= 0 {
		bufferSize = 1000 // Default buffer size
	}

	service := &AuditService{
		store:         s,
		bufferSize:    bufferSize,
		logChan:       make(chan *models.AuditLog, bufferSize),
		batchBuffer:   make([]*models.AuditLog, 0, 100),
		eventsDropped: getAuditEventsDroppedCounter(),
	}

	service.batchTicker = time.NewTicker(1 * time.Second)
	service.wg.Add(1)
	go service.worker()
	log.Printf("Audit service started with buffer size %d", bufferSize)

	return service
}

// worker is the background goroutine that processes audit logs.
// It drains logChan until the channel is closed by Shutdown, then
// flushes any remaining batch and exits.
func (s *AuditService) worker() {
	defer s.wg.Done()

	for {
		select {
		case entry, ok := <-s.logChan:
			if !ok {
				// Channel closed by Shutdown — flush remaining batch.
				s.flushBatch()
				return
			}
			s.addToBatch(entry)

		case <-s.batchTicker.C:
			// Flush batch every second
			s.flushBatch()
		}
	}
}

// addToBatch adds a log entry to the batch buffer
func (s *AuditService) addToBatch(log *models.AuditLog) {
	s.batchMutex.Lock()
	defer s.batchMutex.Unlock()

	s.batchBuffer = append(s.batchBuffer, log)

	// Flush if batch is full (100 entries)
	if len(s.batchBuffer) >= 100 {
		s.flushBatchUnsafe()
	}
}

// flushBatch flushes the batch buffer to the database (thread-safe)
func (s *AuditService) flushBatch() {
	s.batchMutex.Lock()
	defer s.batchMutex.Unlock()
	s.flushBatchUnsafe()
}

// flushBatchUnsafe flushes the batch buffer without locking (caller must hold lock)
func (s *AuditService) flushBatchUnsafe() {
	if len(s.batchBuffer) == 0 {
		return
	}

	// Copy buffer for writing
	toWrite := make([]*models.AuditLog, len(s.batchBuffer))
	copy(toWrite, s.batchBuffer)

	// Clear buffer
	s.batchBuffer = s.batchBuffer[:0]

	if err := s.store.CreateAuditLogBatch(toWrite); err != nil {
		log.Printf("Failed to write audit log batch: %v", err)
	}
}

// buildAuditLog enriches an AuditLogEntry from context and builds the database record.
func (s *AuditService) buildAuditLog(
	ctx context.Context,
	entry core.AuditLogEntry,
) *models.AuditLog {
	if entry.ActorIP == "" {
		entry.ActorIP = util.GetIPFromContext(ctx)
	}
	if entry.ActorUsername == "" {
		entry.ActorUsername = models.GetUsernameFromContext(ctx)
	}
	if entry.ActorUserID == "" {
		entry.ActorUserID = models.GetUserIDFromContext(ctx)
	}
	if entry.UserAgent == "" {
		entry.UserAgent = util.GetUserAgentFromContext(ctx)
	}
	if entry.RequestPath == "" {
		entry.RequestPath = util.GetRequestPathFromContext(ctx)
	}
	if entry.RequestMethod == "" {
		entry.RequestMethod = util.GetRequestMethodFromContext(ctx)
	}
	entry.Details = maskSensitiveDetails(entry.Details)

	// Truncate fields to match database column size limits.
	// TruncateString appends "..." (3 chars) when truncating, so subtract 3
	// from the varchar limit to guarantee the final length fits the column.
	entry.UserAgent = util.TruncateString(entry.UserAgent, 497)
	entry.RequestPath = util.TruncateString(entry.RequestPath, 497)

	// RequestMethod is stored in a varchar(10) column. Preserve values up to
	// the full column width and hard-truncate anything longer without adding
	// an ellipsis.
	if len(entry.RequestMethod) > 10 {
		entry.RequestMethod = entry.RequestMethod[:10]
	}

	now := time.Now()
	return &models.AuditLog{
		ID:            uuid.New().String(),
		EventType:     entry.EventType,
		EventTime:     now,
		Severity:      entry.Severity,
		ActorUserID:   entry.ActorUserID,
		ActorUsername: entry.ActorUsername,
		ActorIP:       entry.ActorIP,
		ResourceType:  entry.ResourceType,
		ResourceID:    entry.ResourceID,
		ResourceName:  entry.ResourceName,
		Action:        entry.Action,
		Details:       entry.Details,
		Success:       entry.Success,
		ErrorMessage:  entry.ErrorMessage,
		UserAgent:     entry.UserAgent,
		RequestPath:   entry.RequestPath,
		RequestMethod: entry.RequestMethod,
		CreatedAt:     now,
	}
}

// Log records an audit log entry asynchronously.
// Events submitted after Shutdown has been called are dropped.
// The RWMutex ensures all in-flight sends complete before Shutdown
// closes logChan, eliminating the send-on-closed-channel race.
func (s *AuditService) Log(ctx context.Context, entry core.AuditLogEntry) {
	s.sendMu.RLock()
	defer s.sendMu.RUnlock()

	if s.stopped.Load() {
		log.Printf("WARNING: Audit service stopped, dropping event: %s", entry.Action)
		s.eventsDropped.Inc()
		return
	}
	auditLog := s.buildAuditLog(ctx, entry)
	select {
	case s.logChan <- auditLog:
	default:
		log.Printf("WARNING: Audit log buffer full, dropping event: %s", entry.Action)
		s.eventsDropped.Inc()
	}
}

// LogSync records an audit log entry synchronously (for critical events)
func (s *AuditService) LogSync(ctx context.Context, entry core.AuditLogEntry) error {
	return s.store.CreateAuditLog(s.buildAuditLog(ctx, entry))
}

// GetAuditLogs retrieves audit logs with pagination and filtering
func (s *AuditService) GetAuditLogs(
	params store.PaginationParams,
	filters store.AuditLogFilters,
) ([]models.AuditLog, store.PaginationResult, error) {
	return s.store.GetAuditLogsPaginated(params, filters)
}

// CleanupOldLogs deletes audit logs older than the retention period
func (s *AuditService) CleanupOldLogs(retention time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-retention)
	return s.store.DeleteOldAuditLogs(cutoffTime)
}

// GetAuditLogStats returns statistics about audit logs
func (s *AuditService) GetAuditLogStats(startTime, endTime time.Time) (store.AuditLogStats, error) {
	return s.store.GetAuditLogStats(startTime, endTime)
}

// Shutdown gracefully shuts down the audit service
func (s *AuditService) Shutdown(ctx context.Context) error {
	// 1. Reject new events so future Log() calls return immediately.
	s.stopped.Store(true)

	// 2. Wait for all in-flight Log() calls to finish, then close
	//    logChan. The exclusive lock ensures no sender is mid-send
	//    when the channel is closed.
	s.sendMu.Lock()
	close(s.logChan)
	s.sendMu.Unlock()

	// Stop ticker
	s.batchTicker.Stop()

	// Wait for worker to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("Audit service shut down gracefully")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("audit service shutdown timeout: %w", ctx.Err())
	}
}

// maskSensitiveDetails masks sensitive information in audit log details
func maskSensitiveDetails(details models.AuditDetails) models.AuditDetails {
	if details == nil {
		return details
	}

	masked := make(models.AuditDetails)
	for key, value := range details {
		// Partial masking takes priority: token_id, device_code, etc. should
		// show truncated values rather than being fully redacted.
		if isPartialMaskField(key) {
			if str, ok := value.(string); ok && len(str) > 12 {
				masked[key] = str[:8] + "..." + str[len(str)-4:]
				continue
			}
		}

		// Complete masking for sensitive fields (passwords, secrets, raw tokens)
		if isSensitiveField(key) {
			masked[key] = "***REDACTED***"
			continue
		}

		// Keep other fields as-is
		masked[key] = value
	}

	return masked
}

var (
	sensitiveFields = []string{
		"password",
		"client_secret",
		"token",
		"access_token",
		"refresh_token",
		"secret",
	}
	partialMaskFields = []string{"device_code", "token_id"}
)

// isSensitiveField checks if a field should be completely masked
func isSensitiveField(key string) bool {
	key = strings.ToLower(key)
	for _, field := range sensitiveFields {
		if strings.Contains(key, field) {
			return true
		}
	}
	return false
}

// isPartialMaskField checks if a field should be partially masked
func isPartialMaskField(key string) bool {
	key = strings.ToLower(key)
	for _, field := range partialMaskFields {
		if strings.Contains(key, field) {
			return true
		}
	}
	return false
}
