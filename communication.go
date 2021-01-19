package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type config struct {
	OutputStorageLimit int64  `json:"output_storage_limit"`
	TimelimitOvershoot string `json:"timelimit_overshoot"`
	DiskspaceError     uint64 `json:"diskspace_error"`
}

type endpoint struct {
	id            string
	url           string
	user          string
	password      string
	waiting       bool
	errorred      bool
	lastAttempt   time.Time
	configuration *config
}

type disabledKind string

const (
	problem       disabledKind = "problem"
	judgehost                  = "judgehost"
	language                   = "language"
	executable                 = "executable"
	testcase                   = "testcase"
	compileScript              = "compile_script"
	compareScript              = "compare_script"
	runScript                  = "run_script"
)

type disabled struct {
	Kind            disabledKind `json:"kind"`
	ProbId          int          `json:"probid,omitempty"`
	Hostname        string       `json:"hostname,omitempty"`
	LangId          int          `json:"langid,omitempty"`
	ExecId          int          `json:"execid,omitempty"`
	TestCaseId      string       `json:"testcaseid,omitempty"`
	CompileScriptId string       `json:"compile_script_id,omitempty"`
	CompareScriptId string       `json:"compare_script_id,omitempty"`
	RunScriptId     string       `json:"run_script_id,omitempty"`
}

type getFileItem struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
	IsExecutable bool `json:"is_executable"`
}

type getFileResponse []getFileItem

func newDisabled(kind disabledKind, value interface{}) disabled {
	disabled := disabled{Kind: kind}
	switch kind {
	case problem:
		disabled.ProbId = value.(int)
	case judgehost:
		disabled.Hostname = value.(string)
	case language:
		disabled.LangId = value.(int)
	case executable:
		disabled.ExecId = value.(int)
	case testcase:
		disabled.TestCaseId = value.(string)
	case compileScript:
		disabled.CompileScriptId = value.(string)
	case compareScript:
		disabled.CompareScriptId = value.(string)
	case runScript:
		disabled.CompileScriptId = value.(string)
	}

	return disabled
}

var endpoints = make(map[string]*endpoint)
var lastRequest string

func newEndpoint(id string, url string, user string, password string) *endpoint {
	return &endpoint{
		id:          id,
		url:         url,
		user:        user,
		password:    password,
		waiting:     false,
		errorred:    false,
		lastAttempt: time.Time{},
	}
}

func readCredentials() {
	credentialsFile := fmt.Sprintf("%v/restapi.secret", EtcDir)
	credentialsFp, err := os.Open(credentialsFile)
	if err != nil {
		Error("Cannot read REST API credentials file %v", credentialsFile)
		return
	}
	defer credentialsFp.Close()

	scanner := bufio.NewScanner(credentialsFp)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		credential := strings.TrimSpace(scanner.Text())
		if credential == "" || (len(credential) > 0 && credential[0] == '#') {
			continue
		}

		fields := strings.Fields(credential)
		if len(fields) != 4 {
			Error("Error parsing REST API credentials. Invalid format in line %v.", lineNumber)
		}

		endpointid := fields[0]
		if _, ok := endpoints[endpointid]; ok {
			Error("Error parsing REST API credentials. Duplicate endpoint ID '%v' in line %v.", endpointid, lineNumber)
		}

		endpoints[endpointid] = newEndpoint(endpointid, fields[1], fields[2], fields[3])
	}
}

func (e *endpoint) requestFailOnError(path string, verb string, data interface{}, failonerror bool) []byte {
	if strings.Index(path, "judgehosts/fetch-work") == 0 && verb == "POST" {
		if lastRequest != path {
			LogMessage(LogDebug, "API request %v %v", verb, path)
			lastRequest = path
		}
	} else {
		LogMessage(LogDebug, "API request %v %v", verb, path)
		lastRequest = path
	}

	fullUrl := fmt.Sprintf("%v/%v", e.url, path)

	if verb == http.MethodGet {
		// We assume data is a string in this case
		fullUrl = fmt.Sprintf("%v?%v", fullUrl, data)
	}

	var body io.Reader = nil
	var contentType = ""
	if verb == http.MethodPost || verb == http.MethodPut {
		contentType = "application/x-www-form-urlencoded"
		if _, ok := data.(string); ok {
			body = strings.NewReader(data.(string))
		} else if _, ok := data.(url.Values); ok {
			body = strings.NewReader((data.(url.Values)).Encode())
		}
	}
	r, _ := http.NewRequest(verb, fullUrl, body)
	r.Header.Set("User-Agent", fmt.Sprintf("DOMjudge/%v", DomjudgeVersion))
	r.SetBasicAuth(e.user, e.password)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}

	resp, err := http.DefaultClient.Do(r)

	if err != nil {
		errorString := fmt.Sprintf("Error while executing curl %v to url %v: %v", verb, fullUrl, err.Error())
		if failonerror {
			Error(errorString)
			// Error() calls os.Exit and thus never returns, but otherwise IDE's might complain
			return nil
		} else {
			Warning(errorString)
			e.errorred = true
			return nil
		}
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	responseBody := buf.Bytes()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errorString string
		if resp.StatusCode == 401 {
			errorString = fmt.Sprintf("Authentication failed (error %v) while contacting %v. Check credentials in restapi.secret.", resp.StatusCode, fullUrl)
		} else {
			errorString = fmt.Sprintf("Error while executing curl %v to url %v: http status code: %v, response: %v", verb, fullUrl, resp.StatusCode, string(responseBody))
		}

		if failonerror {
			Error(errorString)
			// Error() calls os.Exit and thus never returns, but otherwise IDE's might complain
			return nil
		} else {
			Warning(errorString)
			e.errorred = true
			return nil
		}
	}

	if e.errorred {
		e.errorred = false
		e.waiting = false
		LogMessage(LogNotice, "Reconnected to endpoint %v", e.id)
	}

	return responseBody
}

func (e *endpoint) registerJudgehost(hostname string) {
	// Only try to register every 30s.
	now := time.Now()
	if now.Sub(e.lastAttempt) < 30*time.Second {
		e.waiting = true
		return
	}

	e.lastAttempt = time.Now()

	LogMessage(LogNotice, "Registering judgehost on endpoint %v: %v", e.id, e.url)

	workdirpath := fmt.Sprintf("%v/%v/endpoint-%v", JudgeDir, hostname, e.id)
	exitCode := ExecAndPrint("mkdir", "-p", fmt.Sprintf("%v/testcase", workdirpath))
	if exitCode != 0 {
		Error("Could not create %v", workdirpath)
	}

	_ = os.Chmod(fmt.Sprintf("%v/testcase", workdirpath), 0700)

	// Auto-register judgehost.
	// If there are any unfinished judgings in the queue in my name,
	// they will not be finished. Give them back.
	unfinished := e.request("judgehosts", http.MethodPost, fmt.Sprintf("hostname=%v", url.QueryEscape(hostname)))
	if unfinished == nil {
		LogMessage(LogWarning, "Registering judgehost on endpoint %v failed.", e.id)
	} else {
		var unfinishedJudgings []judgetask
		JsonDecode(unfinished, &unfinishedJudgings)
		for _, task := range unfinishedJudgings {
			workdir := task.JudgingDirectory(workdirpath)
			_ = os.Chmod(workdir, 0700)
			LogMessage(LogWarning, "Found unfinished judging with task %v in my name; given back.", task.JobId)
		}
	}
}

func (e *endpoint) request(url string, verb string, data interface{}) []byte {
	return e.requestFailOnError(url, verb, data, true)
}

func (e *endpoint) RefreshConfig() {
	configData := e.request("config", "GET", nil)
	if configData == nil {
		Error("Can not get config from API for endpoint %v", e.id)
	}

	e.configuration = &config{}
	JsonDecode(configData, e.configuration)
}

// Use -1 for no judgetaskId
func (e *endpoint) Disable(disabled disabled, description string, judgetaskId int, extralog string) string {
	d, _ := json.Marshal(disabled)
	log := ReadLog()
	if extralog != "" {
		log += "\n\n--------------------------------------------------------------------------------\n\n" + extralog
	}

	data := url.Values{}
	data.Set("description", description)
	data.Set("judgehostlog", base64.StdEncoding.EncodeToString([]byte(log)))
	data.Set("disabled", string(d))
	if judgetaskId != -1 {
		data.Set("judgetaskid", strconv.Itoa(judgetaskId))
	}
	return string(e.requestFailOnError("judgehosts/internal-error", http.MethodPost, data, false))
}
