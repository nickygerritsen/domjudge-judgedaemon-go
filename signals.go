package main

import (
	"os"
	"os/signal"
	"syscall"
)

var signalReceived = make(chan os.Signal, 1)

var gracefulexitsignalled = false
var exitsignalled = false

func InitSignals() {
	LogMessage(LogDebug, "Installing signal handlers")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)

	go func() {
		for sig := range sigs {
			signalHandler(sig)
		}
	}()
}

func signalHandler(signal os.Signal) {
	LogMessage(LogDebug, "%v signal received", signal)
	// Update state properties
	switch signal {
	case syscall.SIGHUP:
		gracefulexitsignalled = true
		fallthrough
	case syscall.SIGTERM:
	case syscall.SIGINT:
		exitsignalled = true
	}

	// Send the signal to the public channel in case anyone is interested
	signalReceived <- signal
}

func SignalReceived() chan os.Signal {
	return signalReceived
}