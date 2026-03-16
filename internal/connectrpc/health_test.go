package connectrpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-authgate/authgate/internal/config"
	healthv1 "github.com/go-authgate/authgate/internal/gen/health/v1"
	"github.com/go-authgate/authgate/internal/gen/health/v1/healthv1connect"
	"github.com/go-authgate/authgate/internal/store"
)

func TestHealthServer_Check_Serving(t *testing.T) {
	db, err := store.New(context.Background(), "sqlite", ":memory:", &config.Config{})
	require.NoError(t, err)

	mux := http.NewServeMux()
	path, handler := healthv1connect.NewHealthServiceHandler(NewHealthServer(db))
	mux.Handle(path, handler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := healthv1connect.NewHealthServiceClient(srv.Client(), srv.URL)
	resp, err := client.Check(
		context.Background(),
		connect.NewRequest(&healthv1.HealthCheckRequest{}),
	)
	require.NoError(t, err)
	assert.Equal(t, healthv1.HealthCheckResponse_SERVING_STATUS_SERVING, resp.Msg.Status)
	assert.Equal(t, "connected", resp.Msg.Database)
}
