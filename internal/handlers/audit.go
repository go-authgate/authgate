package handlers

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/appleboy/authgate/internal/models"
	"github.com/appleboy/authgate/internal/services"
	"github.com/appleboy/authgate/internal/store"
	"github.com/appleboy/authgate/internal/templates"
	"github.com/gin-gonic/gin"
)

const (
	// queryValueTrue represents the string "true" used in query parameters
	queryValueTrue = "true"
)

// AuditHandler handles audit log operations
type AuditHandler struct {
	auditService *services.AuditService
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(auditService *services.AuditService) *AuditHandler {
	return &AuditHandler{
		auditService: auditService,
	}
}

// ShowAuditLogsPage displays the audit logs HTML page
func (h *AuditHandler) ShowAuditLogsPage(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	params := store.PaginationParams{
		Page:     page,
		PageSize: pageSize,
		Search:   c.Query("search"),
	}

	// Parse filters
	filters := store.AuditLogFilters{
		EventType:    models.EventType(c.Query("event_type")),
		ActorUserID:  c.Query("actor_user_id"),
		ResourceType: models.ResourceType(c.Query("resource_type")),
		ResourceID:   c.Query("resource_id"),
		Severity:     models.EventSeverity(c.Query("severity")),
		ActorIP:      c.Query("actor_ip"),
		Search:       c.Query("search"),
	}

	// Parse success filter (optional boolean)
	if successStr := c.Query("success"); successStr != "" {
		success := successStr == queryValueTrue
		filters.Success = &success
	}

	// Parse time range
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filters.StartTime = t
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filters.EndTime = t
		}
	}

	// Get audit logs
	logs, pagination, err := h.auditService.GetAuditLogs(params, filters)
	if err != nil {
		templates.RenderTempl(
			c,
			http.StatusInternalServerError,
			templates.ErrorPage(templates.ErrorPageProps{
				Error: "Failed to retrieve audit logs",
			}),
		)
		return
	}

	// Get current user for navbar
	user, _ := c.Get("user")

	// Render HTML template
	c.HTML(http.StatusOK, "admin/audit_logs.html", gin.H{
		"user":        user,
		"logs":        logs,
		"Page":        pagination.CurrentPage,
		"PageSize":    pagination.PageSize,
		"TotalItems":  pagination.Total,
		"TotalPages":  pagination.TotalPages,
		"PrevPage":    pagination.PrevPage,
		"NextPage":    pagination.NextPage,
		"Search":      c.Query("search"),
		"EventType":   c.Query("event_type"),
		"Severity":    c.Query("severity"),
		"Success":     c.Query("success"),
		"ActorIP":     c.Query("actor_ip"),
		"QueryString": c.Request.URL.RawQuery,
	})
}

// ListAuditLogs retrieves audit logs with pagination and filtering (JSON API)
func (h *AuditHandler) ListAuditLogs(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	params := store.PaginationParams{
		Page:     page,
		PageSize: pageSize,
		Search:   c.Query("search"),
	}

	// Parse filters
	filters := store.AuditLogFilters{
		EventType:    models.EventType(c.Query("event_type")),
		ActorUserID:  c.Query("actor_user_id"),
		ResourceType: models.ResourceType(c.Query("resource_type")),
		ResourceID:   c.Query("resource_id"),
		Severity:     models.EventSeverity(c.Query("severity")),
		ActorIP:      c.Query("actor_ip"),
		Search:       c.Query("search"),
	}

	// Parse success filter (optional boolean)
	if successStr := c.Query("success"); successStr != "" {
		success := successStr == queryValueTrue
		filters.Success = &success
	}

	// Parse time range
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filters.StartTime = t
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filters.EndTime = t
		}
	}

	// Get audit logs
	logs, pagination, err := h.auditService.GetAuditLogs(params, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"})
		return
	}

	// Log this action (viewing audit logs)
	if userID, exists := c.Get("user_id"); exists {
		if username, usernameExists := c.Get("username"); usernameExists {
			h.auditService.Log(c.Request.Context(), services.AuditLogEntry{
				EventType:     models.EventTypeAuditLogView,
				Severity:      models.SeverityInfo,
				ActorUserID:   userID.(string),
				ActorUsername: username.(string),
				Action:        "Viewed audit logs",
				Details: models.AuditDetails{
					"page":      page,
					"page_size": pageSize,
					"filters":   filters,
				},
				Success:       true,
				RequestPath:   c.Request.URL.Path,
				RequestMethod: c.Request.Method,
				UserAgent:     c.Request.UserAgent(),
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":       logs,
		"pagination": pagination,
	})
}

// GetAuditLogStats returns statistics about audit logs
func (h *AuditHandler) GetAuditLogStats(c *gin.Context) {
	// Parse time range
	var startTime, endTime time.Time

	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			startTime = t
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			endTime = t
		}
	}

	// Default to last 30 days if no time range specified
	if startTime.IsZero() && endTime.IsZero() {
		endTime = time.Now()
		startTime = endTime.Add(-30 * 24 * time.Hour)
	}

	// Get stats
	stats, err := h.auditService.GetAuditLogStats(startTime, endTime)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"error": "Failed to retrieve audit log statistics"},
		)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"stats":      stats,
		"start_time": startTime,
		"end_time":   endTime,
	})
}

// ExportAuditLogs exports audit logs as CSV
func (h *AuditHandler) ExportAuditLogs(c *gin.Context) {
	// Parse filters (same as ListAuditLogs)
	filters := store.AuditLogFilters{
		EventType:    models.EventType(c.Query("event_type")),
		ActorUserID:  c.Query("actor_user_id"),
		ResourceType: models.ResourceType(c.Query("resource_type")),
		ResourceID:   c.Query("resource_id"),
		Severity:     models.EventSeverity(c.Query("severity")),
		ActorIP:      c.Query("actor_ip"),
		Search:       c.Query("search"),
	}

	// Parse success filter
	if successStr := c.Query("success"); successStr != "" {
		success := successStr == queryValueTrue
		filters.Success = &success
	}

	// Parse time range
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filters.StartTime = t
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filters.EndTime = t
		}
	}

	// Get all matching logs (with reasonable limit)
	params := store.PaginationParams{
		Page:     1,
		PageSize: 10000, // Export up to 10k records
	}

	logs, _, err := h.auditService.GetAuditLogs(params, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"})
		return
	}

	// Set CSV headers
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf(
		"attachment; filename=audit_logs_%s.csv",
		time.Now().Format("2006-01-02"),
	))

	// Create CSV writer
	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// Write CSV header
	if err := writer.Write([]string{
		"Event Time",
		"Event Type",
		"Severity",
		"Actor Username",
		"Actor IP",
		"Resource Type",
		"Resource Name",
		"Action",
		"Success",
		"Error Message",
	}); err != nil {
		return
	}

	// Write data rows
	for _, log := range logs {
		successStr := "Yes"
		if !log.Success {
			successStr = "No"
		}

		if err := writer.Write([]string{
			log.EventTime.Format(time.RFC3339),
			string(log.EventType),
			string(log.Severity),
			log.ActorUsername,
			log.ActorIP,
			string(log.ResourceType),
			log.ResourceName,
			log.Action,
			successStr,
			log.ErrorMessage,
		}); err != nil {
			return
		}
	}

	// Log this action
	if userID, exists := c.Get("user_id"); exists {
		if username, usernameExists := c.Get("username"); usernameExists {
			h.auditService.Log(c.Request.Context(), services.AuditLogEntry{
				EventType:     models.EventTypeAuditLogExported,
				Severity:      models.SeverityInfo,
				ActorUserID:   userID.(string),
				ActorUsername: username.(string),
				Action:        "Exported audit logs to CSV",
				Details: models.AuditDetails{
					"record_count": len(logs),
					"filters":      filters,
				},
				Success:       true,
				RequestPath:   c.Request.URL.Path,
				RequestMethod: c.Request.Method,
				UserAgent:     c.Request.UserAgent(),
			})
		}
	}
}
