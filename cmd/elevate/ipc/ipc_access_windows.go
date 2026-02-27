//go:build windows

package ipc

import "fmt"

func (s *UnixServer) configureSocketDirAccess(dir string) error {
	return s.applyWindowsACL(dir)
}

func (s *UnixServer) configureSocketFileAccess(path string) error {
	return s.applyWindowsACL(path)
}

func (s *UnixServer) applyWindowsACL(path string) error {
	if s.socketUser == "" {
		return nil
	}

	// NOTE(review): The socketUser value is used directly in the icacls command
	// arguments. While Unix socket paths are typically controlled by root, the
	// socketUser string comes from environment config. Consider validating it
	// against a safe character pattern (e.g. no semicolons, pipes, quotes) to
	// prevent potential command injection via THAND_ELEVATE_SOCKET_USER.
	args := []string{
		path,
		"/inheritance:r",
		"/grant:r", "SYSTEM:(F)",
	}
	if s.socketUser != "" {
		args = append(args, "/grant", fmt.Sprintf("%s:(M)", s.socketUser))
	}

	if err := s.runCommand("icacls", args...); err != nil {
		return fmt.Errorf("set windows socket ACL on %q: %w", path, err)
	}
	return nil
}
