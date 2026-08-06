package k8s

import (
	"strings"
)

// DefaultCommandTimeout bounds a kubectl command when the caller does not send
// a budget of its own. Callers should send "timeout_seconds" in the request so
// their deadline and ours cannot drift apart.
const DefaultCommandTimeout = 45

// Command timeouts are clamped to this range. A caller-supplied budget is not
// trusted blindly: zero would make every command fail instantly, and an
// unbounded value would let one request pin a worker slot indefinitely.
const (
	MinCommandTimeout = 5
	MaxCommandTimeout = 300
)

// ClampCommandTimeout normalises a caller-supplied budget into the allowed
// range, falling back to DefaultCommandTimeout when none was supplied.
func ClampCommandTimeout(seconds int) int {
	if seconds <= 0 {
		return DefaultCommandTimeout
	}
	if seconds < MinCommandTimeout {
		return MinCommandTimeout
	}
	if seconds > MaxCommandTimeout {
		return MaxCommandTimeout
	}
	return seconds
}

// KubectlExecutor implements the CommandExecutor interface for kubectl commands
type KubectlExecutor struct{}

// This line ensures KubectlExecutor implements the CommandExecutor interface

// NewExecutor creates a new KubectlExecutor instance
func NewExecutor() *KubectlExecutor {
	return &KubectlExecutor{}
}

func (e *KubectlExecutor) executeKubectlCommand(cmd string, args string) (string, error) {
	return e.executeKubectlCommandWithTimeout(cmd, args, DefaultCommandTimeout)
}

func (e *KubectlExecutor) executeKubectlCommandWithTimeout(cmd string, args string, timeout int) (string, error) {
	process := NewShellProcess("kubectl", ClampCommandTimeout(timeout))

	var fullCmd string
	if strings.HasPrefix(cmd, "kubectl ") {
		// If command already includes "kubectl", use it as is (for backward compatibility)
		fullCmd = cmd
	} else {
		// Otherwise build the command
		fullCmd = "kubectl " + cmd
		if args != "" {
			fullCmd += " " + args
		}
	}

	return process.Run(fullCmd)
}

// Execute handles general kubectl command execution (for backward compatibility)
func (e *KubectlExecutor) Execute(command string) (string, error) {
	// Execute the command
	// instead send to pulsar
	return e.executeKubectlCommand(command, "")
}

// ExecuteWithTimeout runs a command under the caller's deadline. Pass 0 to use
// DefaultCommandTimeout; the value is clamped by ClampCommandTimeout.
func (e *KubectlExecutor) ExecuteWithTimeout(command string, timeout int) (string, error) {
	return e.executeKubectlCommandWithTimeout(command, "", timeout)
}

// ExecuteSpecificCommand executes a specific kubectl command with the given arguments
func (e *KubectlExecutor) ExecuteSpecificCommand(cmd string, params map[string]interface{}) (string, error) {
	args, ok := params["args"].(string)
	if !ok {
		args = ""
	}

	// Build the full kubectl command for validation
	fullCmd := cmd
	if args != "" {
		fullCmd += " " + args
	}

	// Execute the command
	return e.executeKubectlCommand(cmd, args)
}
