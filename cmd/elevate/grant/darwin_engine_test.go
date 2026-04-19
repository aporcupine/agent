package grant

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thand-io/agent/cmd/elevate/domain"
)

func TestDarwinGrantAddsAndRevokesGroupMember(t *testing.T) {
	now := time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC)
	members := map[string]bool{}

	engine := mustNewDarwinEngine(t, DarwinEngineConfig{
		AdminGroup:      "admin",
		DseditgroupBin:  "dseditgroup",
		DsmemberutilBin: "dsmemberutil",
	},
		WithDarwinNow(func() time.Time { return now }),
		WithAddMember(func(ctx context.Context, username, group string) error {
			_ = ctx
			members[username] = true
			return nil
		}),
		WithRemoveMember(func(ctx context.Context, username, group string) error {
			_ = ctx
			delete(members, username)
			return nil
		}),
		WithCheckMembership(func(ctx context.Context, username, group string) (bool, error) {
			_ = ctx
			return members[username], nil
		}),
	)

	res, err := engine.Grant(context.Background(), domain.GrantRequest{
		RequestID:       "abc-123",
		WorkflowID:      "wf-1",
		Username:        "alice",
		DurationSeconds: 600,
	})
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}

	if res.RequestID != "abc-123" || res.Username != "alice" {
		t.Fatalf("unexpected grant result: %+v", res)
	}
	if !res.Expiry.Equal(now.Add(600 * time.Second)) {
		t.Fatalf("unexpected expiry: got %s want %s", res.Expiry, now.Add(600*time.Second))
	}

	if !members["alice"] {
		t.Fatal("expected alice to be a member after grant")
	}

	if err := engine.Revoke(context.Background(), domain.RevokeRequest{RequestID: "abc-123", Username: "alice"}); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	if members["alice"] {
		t.Fatal("expected alice to not be a member after revoke")
	}
}

func TestDarwinGrantAddMemberFailureReturnsError(t *testing.T) {
	engine := mustNewDarwinEngine(t, DarwinEngineConfig{
		AdminGroup:      "admin",
		DseditgroupBin:  "dseditgroup",
		DsmemberutilBin: "dsmemberutil",
	},
		WithAddMember(func(ctx context.Context, username, group string) error {
			_ = ctx
			return errors.New("dseditgroup failed")
		}),
	)

	_, err := engine.Grant(context.Background(), domain.GrantRequest{
		RequestID:       "bad",
		Username:        "bob",
		DurationSeconds: 60,
	})
	if err == nil {
		t.Fatal("expected Grant to fail")
	}
}

func TestDarwinGrantInvalidRequest(t *testing.T) {
	engine := mustNewDarwinEngine(t, DarwinEngineConfig{
		AdminGroup:      "admin",
		DseditgroupBin:  "dseditgroup",
		DsmemberutilBin: "dsmemberutil",
	})

	cases := []domain.GrantRequest{
		{RequestID: "", Username: "alice", DurationSeconds: 10},
		{RequestID: "bad/id", Username: "alice", DurationSeconds: 10},
		{RequestID: "bad\nid", Username: "alice", DurationSeconds: 10},
		{RequestID: "x", Username: "", DurationSeconds: 10},
		{RequestID: "x", Username: "bad user", DurationSeconds: 10},
		{RequestID: "x", Username: "bad\nuser", DurationSeconds: 10},
		{RequestID: "x", Username: "alice", DurationSeconds: 0},
	}
	for _, c := range cases {
		if _, err := engine.Grant(context.Background(), c); !errors.Is(err, ErrInvalidGrantRequest) {
			t.Fatalf("expected ErrInvalidGrantRequest for %+v, got %v", c, err)
		}
	}
}

func TestDarwinRevokeMissingIsIdempotent(t *testing.T) {
	engine := mustNewDarwinEngine(t, DarwinEngineConfig{
		AdminGroup:      "admin",
		DseditgroupBin:  "dseditgroup",
		DsmemberutilBin: "dsmemberutil",
	},
		WithRemoveMember(func(ctx context.Context, username, group string) error {
			_ = ctx
			return nil
		}),
	)
	if err := engine.Revoke(context.Background(), domain.RevokeRequest{RequestID: "missing", Username: "alice"}); err != nil {
		t.Fatalf("expected nil on missing revoke, got %v", err)
	}
}

func TestDarwinRevokeInvalidRequestID(t *testing.T) {
	engine := mustNewDarwinEngine(t, DarwinEngineConfig{
		AdminGroup:      "admin",
		DseditgroupBin:  "dseditgroup",
		DsmemberutilBin: "dsmemberutil",
	})
	if err := engine.Revoke(context.Background(), domain.RevokeRequest{RequestID: "bad/id", Username: "alice"}); !errors.Is(err, ErrInvalidRevokeRequest) {
		t.Fatalf("expected ErrInvalidRevokeRequest, got %v", err)
	}
}

func TestDarwinBaselinePrivilegeHook(t *testing.T) {
	members := map[string]bool{}
	engine := mustNewDarwinEngine(t, DarwinEngineConfig{
		AdminGroup:      "admin",
		DseditgroupBin:  "dseditgroup",
		DsmemberutilBin: "dsmemberutil",
	},
		WithAddMember(func(ctx context.Context, username, group string) error {
			_ = ctx
			members[username] = true
			return nil
		}),
		WithCheckMembership(func(ctx context.Context, username, group string) (bool, error) {
			_ = ctx
			return members[username], nil
		}),
		WithDarwinCheckAlreadyPrivileged(func(ctx context.Context, username string) (bool, error) {
			_ = ctx
			_ = username
			return true, nil
		}),
	)

	res, err := engine.Grant(context.Background(), domain.GrantRequest{RequestID: "r1", Username: "alice", DurationSeconds: 30})
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}
	if !res.WasAlreadyPrivileged {
		t.Fatal("expected WasAlreadyPrivileged=true from hook")
	}
}

func TestDarwinGrantMembershipVerificationFailure(t *testing.T) {
	engine := mustNewDarwinEngine(t, DarwinEngineConfig{
		AdminGroup:      "admin",
		DseditgroupBin:  "dseditgroup",
		DsmemberutilBin: "dsmemberutil",
	},
		WithAddMember(func(ctx context.Context, username, group string) error {
			_ = ctx
			return nil
		}),
		WithCheckMembership(func(ctx context.Context, username, group string) (bool, error) {
			_ = ctx
			return false, nil
		}),
	)

	_, err := engine.Grant(context.Background(), domain.GrantRequest{
		RequestID:       "r1",
		Username:        "alice",
		DurationSeconds: 60,
	})
	if err == nil || !strings.Contains(err.Error(), "not confirmed as member") {
		t.Fatalf("expected membership verification error, got %v", err)
	}
}

func TestNewDarwinEngineRequiresConfigFields(t *testing.T) {
	_, err := NewDarwinEngine(DarwinEngineConfig{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func mustNewDarwinEngine(t *testing.T, cfg DarwinEngineConfig, opts ...DarwinEngineOption) *DarwinEngine {
	t.Helper()
	engine, err := NewDarwinEngine(cfg, opts...)
	if err != nil {
		t.Fatalf("NewDarwinEngine failed: %v", err)
	}
	return engine
}
