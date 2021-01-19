package main

import (
	"fmt"
	"log/syslog"
	"os"
	"time"
)

type LogLevel int

const (
	LogCritical LogLevel = iota
	LogError
	LogWarning
	LogNotice
	LogInfo
	LogDebug
)

var levelMap = map[string]LogLevel{
	"critical": LogCritical,
	"error":    LogError,
	"warning":  LogWarning,
	"notice":   LogNotice,
	"info":     LogInfo,
	"debug":    LogDebug,
}

var loglevel = LogDebug
var verbose = LogInfo

var logfilename string
var logfile *os.File
var syslogWriter *syslog.Writer
var syslogLevelMap map[LogLevel]func(string) error

func InitLog() {
	logfilename = fmt.Sprintf("%v/judge.%v.log", LogDir, hostname)
	file, err := os.OpenFile(logfilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Cannot open log file %v for appending; continuing without logging: %v", logfilename, err.Error())
	}
	logfile = file

	if useSyslog {
		syslogWriter, _ = syslog.New(syslogFacility, "")
		syslogLevelMap = map[LogLevel]func(string) error{
			LogCritical: syslogWriter.Crit,
			LogError:    syslogWriter.Err,
			LogWarning:  syslogWriter.Warning,
			LogNotice:   syslogWriter.Notice,
			LogInfo:     syslogWriter.Info,
			LogDebug:    syslogWriter.Debug,
		}
	}
}

func LogMessage(level LogLevel, message string, args ...interface{}) {
	// Trim message to reasonable length
	if len(message) > 10000 {
		message = message[1:10000]
	}

	message = fmt.Sprintf(message, args...)

	t := time.Now().Format("Jan 02 15:04:05.000")
	pid := os.Getpid()
	stamp := fmt.Sprintf("[%v] %v[%v]", t, scriptId, pid)

	if level <= verbose {
		_, _ = fmt.Fprintf(os.Stderr, "%v %v\n", stamp, message)
	}

	if level <= loglevel {
		if logfile != nil {
			_, _ = fmt.Fprintf(logfile, "%v %v\n", stamp, message)
		}
		if syslogWriter != nil {
			_ = syslogLevelMap[level](fmt.Sprintln(message))
		}
	}
}

func Error(message string, args ... interface{}) {
	LogMessage(LogError, message, args...)
	os.Exit(1)
}

func Warning(message string, args ...  interface{}) {
	LogMessage(LogWarning, message, args...)
}

func ReadLog() string {
	if logfile == nil {
		return ""
	}

	content, _ := Exec("tail", "-n20", logfilename)
	return content
}

// Make judgedaemon adhere to flag.Value
func (l LogLevel) String() string {
	for k, v := range levelMap {
		if v == l {
			return k
		}
	}

	panic("Level not defined in levelMap")
}

func (l *LogLevel) Set(level string) error {
	if val, ok := levelMap[level]; ok {
		*l = val
		return nil
	}

	return fmt.Errorf("invalid log level %v", level)
}