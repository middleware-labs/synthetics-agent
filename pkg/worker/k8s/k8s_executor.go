package k8s

import (
	"strings"
)

// KubectlExecutor implements the CommandExecutor interface for kubectl commands
type KubectlExecutor struct{}

// This line ensures KubectlExecutor implements the CommandExecutor interface

// NewExecutor creates a new KubectlExecutor instance
func NewExecutor() *KubectlExecutor {
	return &KubectlExecutor{}
}

func (e *KubectlExecutor) executeKubectlCommand(cmd string, args string) (string, error) {
	process := NewShellProcess("kubectl", 60)

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
