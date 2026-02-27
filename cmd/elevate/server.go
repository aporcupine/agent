package main

import (
	"context"
	"errors"

	"github.com/thand-io/agent/cmd/elevate/handler"
)

// Server coordinates IPC accept loop and delegates per-connection handling.
type Server struct {
	ipc     handler.IPCServer
	handler *handler.Handler
}

func NewServer(ipc handler.IPCServer, h *handler.Handler) *Server {
	return &Server{ipc: ipc, handler: h}
}

func (s *Server) Run(ctx context.Context) error {
	if s.ipc == nil {
		return errors.New("ipc server is required")
	}
	if s.handler == nil {
		return errors.New("handler is required")
	}

	if err := s.ipc.Start(ctx); err != nil {
		return err
	}
	defer s.ipc.Close()

	// TODO(review): Connections are handled sequentially on the accept goroutine.
	// A slow or malicious client blocks all other connections until its request
	// timeout expires. Consider handling each connection in its own goroutine
	// with a bounded concurrency semaphore (e.g. chan struct{} of capacity N)
	// to allow parallel request processing without unbounded goroutine growth.
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		conn, err := s.ipc.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}

		// TODO(review): HandleConnection errors are silently dropped here.
		// At minimum, log the error at warn/debug level so operators can
		// diagnose connection failures (malformed frames, auth rejections, etc.).
		if err := s.handler.HandleConnection(ctx, conn); err != nil {
			_ = conn.Close()
			continue
		}

		_ = conn.Close()
	}
}
