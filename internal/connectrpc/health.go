package connectrpc

import (
	"context"

	"connectrpc.com/connect"

	healthv1 "github.com/go-authgate/authgate/internal/gen/health/v1"
	"github.com/go-authgate/authgate/internal/gen/health/v1/healthv1connect"
	"github.com/go-authgate/authgate/internal/store"
)

// HealthServer implements the connect-go HealthService.
type HealthServer struct {
	healthv1connect.UnimplementedHealthServiceHandler
	db *store.Store
}

// NewHealthServer creates a new HealthServer.
func NewHealthServer(db *store.Store) *HealthServer {
	return &HealthServer{db: db}
}

// Check returns the health status of the service.
func (s *HealthServer) Check(
	_ context.Context,
	_ *connect.Request[healthv1.HealthCheckRequest],
) (*connect.Response[healthv1.HealthCheckResponse], error) {
	resp := &healthv1.HealthCheckResponse{}

	if err := s.db.Health(); err != nil {
		resp.Status = healthv1.HealthCheckResponse_SERVING_STATUS_NOT_SERVING
		resp.Database = "disconnected"
	} else {
		resp.Status = healthv1.HealthCheckResponse_SERVING_STATUS_SERVING
		resp.Database = "connected"
	}

	return connect.NewResponse(resp), nil
}
