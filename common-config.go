package main

import "log/syslog"

// Use syslog?
var useSyslog = true
// Syslog facility to use
var syslogFacility = syslog.LOG_LOCAL0