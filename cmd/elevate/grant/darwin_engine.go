package grant

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/thand-io/agent/cmd/elevate/domain"
)

// DarwinEngineOption configures a DarwinEngine instance.
type DarwinEngineOption func(*DarwinEngine)

// WithDarwinNow overrides the wall clock source.
func WithDarwinNow(fn func() time.Time) DarwinEngineOption {
	return func(e *DarwinEngine) {
		e.now = fn
	}
}

// WithAddMember overrides group membership addition for tests.
func WithAddMember(fn func(ctx context.Context, username, group string) error) DarwinEngineOption {
	return func(e *DarwinEngine) {
		e.addMember = fn
	}
}

// WithRemoveMember overrides group membership removal for tests.
func WithRemoveMember(fn func(ctx context.Context, username, group string) error) DarwinEngineOption {
	return func(e *DarwinEngine) {
		e.removeMember = fn
	}
}

// WithCheckMembership overrides group membership check for tests.
func WithCheckMembership(fn func(ctx context.Context, username, group string) (bool, error)) DarwinEngineOption {
	return func(e *DarwinEngine) {
		e.checkMembership = fn
	}
}

// WithDarwinCheckAlreadyPrivileged provides baseline membership hook; persistence is in state layer.
func WithDarwinCheckAlreadyPrivileged(fn func(ctx context.Context, username string) (bool, error)) DarwinEngineOption {
	return func(e *DarwinEngine) {
		e.checkAlreadyPrivileged = fn
	}
}

// DarwinEngine implements local-admin grant/revoke via Directory Services (dseditgroup).
type DarwinEngine struct {
	adminGroup      string
	dseditgroupBin  string
	dsmemberutilBin string
	now             func() time.Time

	addMember              func(ctx context.Context, username, group string) error
	removeMember           func(ctx context.Context, username, group string) error
	checkMembership        func(ctx context.Context, username, group string) (bool, error)
	checkAlreadyPrivileged func(ctx context.Context, username string) (bool, error)
}

// DarwinEngineConfig contains required macOS grant engine configuration.
type DarwinEngineConfig struct {
	AdminGroup      string
	DseditgroupBin  string
	DsmemberutilBin string
}

// NewDarwinEngine constructs a macOS GrantEngine backed by Directory Services.
func NewDarwinEngine(cfg DarwinEngineConfig, opts ...DarwinEngineOption) (*DarwinEngine, error) {
	e := &DarwinEngine{
		adminGroup:      strings.TrimSpace(cfg.AdminGroup),
		dseditgroupBin:  strings.TrimSpace(cfg.DseditgroupBin),
		dsmemberutilBin: strings.TrimSpace(cfg.DsmemberutilBin),
		now:             func() time.Time { return time.Now().UTC() },
		checkAlreadyPrivileged: func(ctx context.Context, username string) (bool, error) {
			_ = ctx
			_ = username
			// Hook only in this chunk; actual baseline persistence happens in state layer.
			return false, nil
		},
	}

	for _, opt := range opts {
		opt(e)
	}
	if e.adminGroup == "" {
		return nil, errors.New("admin group is required")
	}
	if e.dseditgroupBin == "" {
		return nil, errors.New("dseditgroup binary is required")
	}
	if e.dsmemberutilBin == "" {
		return nil, errors.New("dsmemberutil binary is required")
	}

	// Set default command implementations if not overridden by options.
	if e.addMember == nil {
		e.addMember = func(ctx context.Context, username, group string) error {
			cmd := exec.CommandContext(ctx, e.dseditgroupBin, "-o", "edit", "-a", username, "-t", "user", group)
			output, err := cmd.CombinedOutput()
			if err != nil {
				trimmed := strings.TrimSpace(string(output))
				if trimmed == "" {
					return fmt.Errorf("dseditgroup add failed: %w", err)
				}
				return fmt.Errorf("dseditgroup add failed: %s: %w", trimmed, err)
			}
			return nil
		}
	}

	if e.removeMember == nil {
		e.removeMember = func(ctx context.Context, username, group string) error {
			cmd := exec.CommandContext(ctx, e.dseditgroupBin, "-o", "edit", "-d", username, "-t", "user", group)
			output, err := cmd.CombinedOutput()
			if err != nil {
				trimmed := strings.TrimSpace(string(output))
				// dseditgroup returns error if user is not a member — treat as success for idempotency.
				if strings.Contains(trimmed, "not a member") || strings.Contains(trimmed, "NotFound") {
					return nil
				}
				if trimmed == "" {
					return fmt.Errorf("dseditgroup remove failed: %w", err)
				}
				return fmt.Errorf("dseditgroup remove failed: %s: %w", trimmed, err)
			}
			return nil
		}
	}

	if e.checkMembership == nil {
		e.checkMembership = func(ctx context.Context, username, group string) (bool, error) {
			cmd := exec.CommandContext(ctx, e.dsmemberutilBin, "checkmembership", "-U", username, "-G", group)
			output, err := cmd.CombinedOutput()
			if err != nil {
				return false, fmt.Errorf("dsmemberutil checkmembership failed: %w", err)
			}
			return strings.Contains(string(output), "is a member"), nil
		}
	}

	return e, nil
}

// Grant validates input, checks baseline privilege, adds the user to the admin
// group via dseditgroup, verifies membership, and returns expiry metadata.
func (e *DarwinEngine) Grant(ctx context.Context, req domain.GrantRequest) (domain.GrantResult, error) {
	if !isValidRequestID(req.RequestID) || !isValidUsername(req.Username) {
		return domain.GrantResult{}, ErrInvalidGrantRequest
	}
	if req.DurationSeconds <= 0 {
		return domain.GrantResult{}, ErrInvalidGrantRequest
	}

	alreadyPrivileged, err := e.checkAlreadyPrivileged(ctx, req.Username)
	if err != nil {
		return domain.GrantResult{}, fmt.Errorf("check baseline privilege: %w", err)
	}

	if err := e.addMember(ctx, req.Username, e.adminGroup); err != nil {
		return domain.GrantResult{}, fmt.Errorf("add to admin group: %w", err)
	}

	isMember, err := e.checkMembership(ctx, req.Username, e.adminGroup)
	if err != nil {
		return domain.GrantResult{}, fmt.Errorf("verify membership: %w", err)
	}
	if !isMember {
		return domain.GrantResult{}, fmt.Errorf("user %q not confirmed as member of %q after grant", req.Username, e.adminGroup)
	}

	return domain.GrantResult{
		RequestID:            req.RequestID,
		Username:             req.Username,
		Expiry:               e.now().Add(time.Duration(req.DurationSeconds) * time.Second),
		WasAlreadyPrivileged: alreadyPrivileged,
	}, nil
}

// Revoke removes the user from the admin group via dseditgroup and is
// idempotent when the user is already not a member.
func (e *DarwinEngine) Revoke(ctx context.Context, req domain.RevokeRequest) error {
	if !isValidRequestID(req.RequestID) {
		return ErrInvalidRevokeRequest
	}

	if err := e.removeMember(ctx, req.Username, e.adminGroup); err != nil {
		return fmt.Errorf("remove from admin group: %w", err)
	}

	return nil
}
