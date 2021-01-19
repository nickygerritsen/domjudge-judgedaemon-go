package main

import (
	"fmt"
	"os/exec"
)

func Exec(command string, args ...string) (string, int) {
	output, err := exec.Command(command, args...).CombinedOutput()

	if exitError, ok := err.(*exec.ExitError); ok {
		return string(output), exitError.ExitCode()
	}

	if err != nil {
		Error(err.Error())
	}

	return string(output), 0
}

func ExecAndPrint(command string, args ...string) int {
	output, exitCode := Exec(command, args...)
	if output != "" {
		fmt.Print(output)
	}

	return exitCode
}
