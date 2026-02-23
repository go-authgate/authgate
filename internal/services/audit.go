package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/util"
	"github.com/google/uuid"
)

// AuditLogEntry represents the data needed to create an audit log entry
type AuditLogEntry struct {
	EventType     models.EventType
	Severity      models.EventSeverity
	ActorUserID   string
	ActorUsername string
	ActorIP       string
	ResourceType  models.ResourceType
	ResourceID    string
	ResourceName  string
	Action        string
	Details       models.AuditDetails
	Success       bool
	ErrorMessage  string
	UserAgent     string
	RequestPath   string
	RequestMethod string
}

// AuditService handles audit logging operations
type AuditService struct {
	store      *store.Store
	enabled    bool
	bufferSize int

	// Async logging channel
	logChan chan *models.AuditLog

	// Batch buffer
	batchBuffer []*models.AuditLog
	batchMutex  sync.Mutex
	batchTicker *time.Ticker

	// Graceful shutdown
	wg         sync.WaitGroup
	shutdownCh chan struct{}
}

// NewAuditService creates a new audit service
func NewAuditService(s *store.Store, enabled bool, bufferSize int) *AuditService {
	if bufferSize <= 0 {
		bufferSize = 1000 // Default buffer size
	}

	service := &AuditService{
		store:       s,
		enabled:     enabled,
		bufferSize:  bufferSize,
		logChan:     make(chan *models.AuditLog, bufferSize),
		batchBuffer: make([]*models.AuditLog, 0, 100),
		batchTicker: time.NewTicker(1 * time.Second),
		shutdownCh:  make(chan struct{}),
	}

	if enabled {
		service.wg.Add(1)
		go service.worker()
		log.Printf("Audit service started with buffer size %d", bufferSize)
	} else {
		log.Println("Audit service is disabled")
	}

	return service
}

// worker is the background goroutine that processes audit logs
func (s *AuditService) worker() {
	defer s.wg.Done()

	for {
		select {
		case log := <-s.logChan:
			s.addToBatch(log)

		case <-s.batchTicker.C:
			// Flush batch every second
			s.flushBatch()

		case <-s.shutdownCh:
			// Flush remaining logs before shutdown
			s.flushBatch()
			return
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

// Log records an audit log entry asynchronously
func (s *AuditService) Log(ctx context.Context, entry AuditLogEntry) {
	if !s.enabled {
		return
	}

	// Extract IP from context if not provided
	if entry.ActorIP == "" {
		entry.ActorIP = util.GetIPFromContext(ctx)
	}

	// Extract username from context if not provided
	if entry.ActorUsername == "" {
		entry.ActorUsername = util.GetUsernameFromContext(ctx)
	}

	// Mask sensitive data
	entry.Details = maskSensitiveDetails(entry.Details)

	// Create audit log
	auditLog := &models.AuditLog{
		ID:            uuid.New().String(),
		EventType:     entry.EventType,
		EventTime:     time.Now(),
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
		CreatedAt:     time.Now(),
	}

	// Try to send to channel (non-blocking)
	select {
	case s.logChan <- auditLog:
		// Successfully sent
	default:
		// Channel is full, drop the event and log warning
		log.Printf("WARNING: Audit log buffer full, dropping event: %s", entry.Action)
	}
}

// LogSync records an audit log entry synchronously (for critical events)
func (s *AuditService) LogSync(ctx context.Context, entry AuditLogEntry) error {
	if !s.enabled {
		return nil
	}

	// Extract IP from context if not provided
	if entry.ActorIP == "" {
		entry.ActorIP = util.GetIPFromContext(ctx)
	}

	// Extract username from context if not provided
	if entry.ActorUsername == "" {
		entry.ActorUsername = util.GetUsernameFromContext(ctx)
	}

	// Mask sensitive data
	entry.Details = maskSensitiveDetails(entry.Details)

	// Create audit log
	auditLog := &models.AuditLog{
		ID:            uuid.New().String(),
		EventType:     entry.EventType,
		EventTime:     time.Now(),
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
		CreatedAt:     time.Now(),
	}

	// Write directly to database
	return s.store.CreateAuditLog(auditLog)
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
	if !s.enabled {
		return nil
	}

	// Stop ticker
	s.batchTicker.Stop()

	// Signal worker to stop
	close(s.shutdownCh)

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
		// Complete masking for these fields
		if isSensitiveField(key) {
			masked[key] = "***REDACTED***"
			continue
		}

		// Partial masking for tokens and codes
		if isPartialMaskField(key) {
			if str, ok := value.(string); ok && len(str) > 12 {
				masked[key] = str[:8] + "..." + str[len(str)-4:]
				continue
			}
		}

		// Keep other fields as-is
		masked[key] = value
	}

	return masked
}

// isSensitiveField checks if a field should be completely masked
func isSensitiveField(key string) bool {
	key = strings.ToLower(key)
	sensitiveFields := []string{
		"password",
		"client_secret",
		"token",
		"access_token",
		"refresh_token",
		"secret",
	}

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
	partialMaskFields := []string{
		"device_code",
		"token_id",
	}

	for _, field := range partialMaskFields {
		if strings.Contains(key, field) {
			return true
		}
	}
	return false
}
