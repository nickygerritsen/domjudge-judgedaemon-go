package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var daemonId int
var showVersion bool
var scriptId = "judgedaemon"
var hostname string

const chrootScript = "chroot-startstop.sh"

var waittime = 5 * time.Second

func init() {
	flag.IntVar(&daemonId, "n", -1, "daemon number. -1 disables this")
	flag.BoolVar(&showVersion, "V", false, "output version information and exit")
	flag.Var(&verbose, "v", "set verbosity to LEVEL (syslog levels)")
}

func main() {
	flag.Parse()
	hostname, _ = os.Hostname()

	if daemonId >= 0 {
		hostname = fmt.Sprintf("%v-%v", hostname, daemonId)
	}
	InitLog()

	if showVersion {
		Version()
		os.Exit(0)
	}

	if os.Getuid() == 0 {
		fmt.Println("This program should not be run as root.")
		os.Exit(1)
	}

	// TODO: check for debugjudge

	runUser := RunUser
	if daemonId >= 0 {
		runUser = fmt.Sprintf("%v-%v", RunUser, daemonId)
	}

	// Set static environment variables for passing path configuration
	// to called programs:
	_ = os.Setenv("DJ_BINDIR", BinDir)
	_ = os.Setenv("DJ_ETCDIR", EtcDir)
	_ = os.Setenv("DJ_JUDGEDIR", JudgeDir)
	_ = os.Setenv("DJ_LIBDIR", LibDir)
	_ = os.Setenv("DJ_LIBJUDGEDIR", LibJudgeDir)
	_ = os.Setenv("DJ_LOGDIR", LogDir)
	_ = os.Setenv("RUNUSER", runUser)
	_ = os.Setenv("RUNGROUP", RunGroup)

	for code, name := range ExitCodes {
		envVar := fmt.Sprintf("E_%v", strings.ToUpper(strings.ReplaceAll(name, "-", "_")))
		_ = os.Setenv(envVar, strconv.Itoa(code))
	}

	if useSyslog {
		_ = os.Setenv("DJ_SYSLOG", strconv.Itoa(int(syslogFacility)))
	}

	if _, err := user.Lookup(runUser); err != nil {
		Error(fmt.Sprintf("runuser %v does not exist", runUser))
	}

	output, _ := Exec("ps", "-u", runUser, "-o", "pid=", "-o", "comm=")
	if len(output) > 0 {
		// TODO enable again
		//Error("found processes still running as '%v', check manually:\n%v", runUser, string(output))
	}

	LogMessage(LogNotice, "Judge started on %v [DOMjudge/%v]", hostname, DomjudgeVersion)

	InitSignals()
	readCredentials()

	// Set umask to allow group,other access, as this is needed for the
	// unprivileged user.
	syscall.Umask(0022)

	LogMessage(LogInfo, "√ Executing chroot script: '%v check'", chrootScript)
	exitCode := ExecAndPrint(fmt.Sprintf("%v/%v", LibJudgeDir, chrootScript), "check")
	if exitCode != 0 {
		Error("chroot sanity check exited with exitcode %v", exitCode)
	}

	for _, endpoint := range endpoints {
		endpoint.registerJudgehost(hostname)
	}

	// Populate the DOMjudge configuration initially
	for _, endpoint := range endpoints {
		endpoint.RefreshConfig()
	}

	endpointids := make([]string, 0)
	for endpointid := range endpoints {
		endpointids = append(endpointids, endpointid)
	}
	currentEndpoint := 0
	lastWorkDir := ""

	for true {
		dosleep := true
		for _, endpoint := range endpoints {
			if endpoint.errorred {
				endpoint.registerJudgehost(hostname)
			}

			if !endpoint.waiting {
				dosleep = false
				break
			}
		}

		// Sleep only if everything is "waiting" and only if we're looking at the first endpoint again
		if dosleep && currentEndpoint == 0 {
			// We want to continue both when we received a signal or when the timeout occurred
			// But we don't care about what the actual signal is
			select {
			case <-time.After(waittime):
			case <-SignalReceived():
			}
		}

		// Increment our currentEndpoint pointer
		currentEndpoint = (currentEndpoint + 1) % len(endpointids)
		endpointid := endpointids[currentEndpoint]
		endpoint := endpoints[endpointid]
		workDirPath := fmt.Sprintf("%v/%v/endpoint-%v", JudgeDir, hostname, endpoint.id)

		if exitsignalled {
			LogMessage(LogNotice, "Received signal, exiting.")
			os.Exit(0)
		}

		if endpoint.errorred {
			continue
		}

		if !endpoint.waiting {
			// Check for available disk space
			var stat syscall.Statfs_t
			_ = syscall.Statfs(JudgeDir, &stat)
			var freeSpace = stat.Bavail * uint64(stat.Bsize)
			var allowedFreeSpace = endpoint.configuration.DiskspaceError * 1024
			if freeSpace < allowedFreeSpace {
				var freeAbs = fmt.Sprintf("%01.2fGB", float64(freeSpace)/1024/1024/1024)
				LogMessage(LogError, "Low on disk space: %v free, clean up or change 'diskspace error' value in config before resolving this error.", freeAbs)
				errorId := endpoint.Disable(newDisabled(judgehost, hostname), fmt.Sprintf("low on disk space on %v", hostname), -1, "")
				LogMessage(LogError, "=> internal error %v", errorId)
			}
		}

		// Request open submissions to judge. Any errors will be treated as
		// non-fatal: we will just keep on retrying in this loop.
		fetchWorkData := url.Values{}
		fetchWorkData.Set("hostname", hostname)
		judgingData := endpoint.requestFailOnError("judgehosts/fetch-work", http.MethodPost, fetchWorkData, false)
		var tasks []judgetask

		if judgingData != nil {
			tasks = append(tasks, judgetask{})
			JsonDecode(judgingData, &tasks)
		}

		if len(tasks) == 0 {
			if !endpoint.waiting {
				endpoint.waiting = true
				if lastWorkDir != "" {
					cleanupJudging(lastWorkDir)
					lastWorkDir = ""
				}
				LogMessage(LogInfo, "No submissions in queue (for endpoint %v), waiting...", endpoint.id)
			}
			continue
		}

		// we have gotten a submission for judging
		endpoint.waiting = false
		LogMessage(LogInfo, "⇝ Received %v '%v' judge tasks (endpoint %v)", len(tasks), tasks[0].Type, endpoint.id)

		// create workdir for judging
		workDir := tasks[0].JudgingDirectory(workDirPath)

		LogMessage(LogInfo, "  Working directory: %v", workDir)

		successFile := fmt.Sprintf("%v/success", workDir)
		// If a database gets reset without removing the judging
		// directories, we might hit an old directory: rename it.
		if _, err := os.Stat(workDir); err == nil {
			needsCleanup := false
			if _, err := os.Stat(successFile); err == nil {
				mypid := os.Getpid()
				successFileContents, _ := ioutil.ReadFile(successFile)
				if strings.TrimSpace(string(successFileContents)) != strconv.Itoa(mypid) {
					needsCleanup = true
				}
				_ = syscall.Unlink(successFile)
			} else {
				needsCleanup = true
			}

			if needsCleanup {
				if lastWorkDir != "" {
					cleanupJudging(lastWorkDir)
					lastWorkDir = ""
				}

				oldWorkDir := fmt.Sprintf("%v-old-%v-%v", workDir, os.Getpid(), time.Now().Format("06-01-02_15:04"))
				if err := os.Rename(workDir, oldWorkDir); err != nil {
					Error("Could not rename stale working directory to '%v': %v", oldWorkDir, err.Error())
				}
				_ = os.Chmod(oldWorkDir, 0700)
				Warning("Found stale working directory; renamed to '%v'", oldWorkDir)
			}
		} else {
			if lastWorkDir != "" {
				cleanupJudging(lastWorkDir)
				lastWorkDir = ""
			}
		}

		if exitCode := ExecAndPrint("mkdir", "-p", fmt.Sprintf("%v/compile", workDir)); exitCode != 0 {
			Error("Could not create '%v/compile'", workDir)
		}

		_ = os.Chmod(workDir, 0755)

		if err := os.Chdir(workDir); err != nil {
			Error("Could not chdir to '%v': %v", workDir, err.Error())
		}

		if lastWorkDir != workDir {
			// create chroot environment
			LogMessage(LogInfo, "  √ Executing chroot script: '%v start'", chrootScript)
			if exitCode := ExecAndPrint(fmt.Sprintf("%v/%v", LibJudgeDir, chrootScript), "start"); exitCode != 0 {
				Error("chroot script exited with exitcode %v", exitCode)
			}

			// Refresh config at start of each batch.
			endpoint.RefreshConfig()

			lastWorkDir = workDir
		}

		for _, task := range tasks {
			if !judge(endpoint, task, workDirPath) {
				break
			}
		}

		_ = ioutil.WriteFile(successFile, []byte(strconv.Itoa(os.Getpid())), 0644)

		// restart the judging loop
	}
}

func cleanupJudging(workdir string) {
	// revoke readablity for domjudge-run user to this workdir
	_ = os.Chmod(workdir, 0700)

	// destroy chroot environment
	LogMessage(LogInfo, "  √ Executing chroot script: '%v stop'", chrootScript)
	if exitCode := ExecAndPrint(fmt.Sprintf("%v/%v", LibJudgeDir, chrootScript), "stop"); exitCode != 0 {
		Error("chroot script exited with exitcode %v", exitCode)
	}

	// Evict all contents of the workdir from the kernel fs cache
	if exitCode := ExecAndPrint(fmt.Sprintf("%v/evict", LibJudgeDir), workdir); exitCode != 0 {
		Error("evict script exited with exitcode %v", exitCode)
	}
}

func judge(endpoint *endpoint, task judgetask, workDirPath string) bool {
	// Set configuration variables for called programs
	if CreateWritableTempDir() {
		_ = os.Setenv("CREATE_WRITABLE_TEMP_DIR", "1")
	} else {
		_ = os.Setenv("CREATE_WRITABLE_TEMP_DIR", "")
	}

	compileConfig := task.GetCompileConfig()
	runConfig := task.getRunConfig()
	compareConfig := task.GetCompareConfig()

	// These are set again below before comparing.
	_ = os.Setenv("SCRIPTTIMELIMIT", strconv.Itoa(compileConfig.ScriptTimelimit))
	_ = os.Setenv("SCRIPTMEMLIMIT", strconv.Itoa(compileConfig.ScriptMemoryLimit))
	_ = os.Setenv("SCRIPTFILELIMIT", strconv.Itoa(compileConfig.ScriptFilesizeLimit))

	_ = os.Setenv("MEMLIMIT", strconv.Itoa(runConfig.MemoryLimit))
	_ = os.Setenv("FILELIMIT", strconv.Itoa(runConfig.OutputLimit))
	_ = os.Setenv("PROCLIMIT", strconv.Itoa(runConfig.ProcessLimit))

	_ = os.Setenv("ENTRY_POINT", runConfig.EntryPoint)

	outputStorageLimit := endpoint.configuration.OutputStorageLimit

	var cpusetOpt []string
	if daemonId >= 0 {
		cpusetOpt = []string{
			"-n",
			strconv.Itoa(daemonId),
		}
	}

	workDir := task.JudgingDirectory(workDirPath)
	if !compile(endpoint, task, workDir, workDirPath, compileConfig, cpusetOpt, outputStorageLimit) {
		return false
	}

	// TODO: How do we plan to handle these?
	overshoot := endpoint.configuration.TimelimitOvershoot

	// Check whether we have received an exit signal (but not a graceful exit signal).
	if exitsignalled && !gracefulexitsignalled {
		LogMessage(LogNotice, "Received HARD exit signal, aborting current judging.")

		// Make sure the domserver knows that we didn't finish this judging.
		unfinished := endpoint.request("judgehosts", http.MethodPost, fmt.Sprintf("hostname=%v", url.QueryEscape(hostname)))
		var unfinishedJudgings []judgetask
		JsonDecode(unfinished, &unfinishedJudgings)
		for _, task := range unfinishedJudgings {
			LogMessage(LogWarning, "Aborted judging task %v due to signal", task.JudgeTaskId)
		}

		// Break, not exit so we cleanup nicely.
		return false
	}

	LogMessage(LogInfo, "  🏃 Running testcase %v...", task.TestCaseId)
	testcaseId, _ := strconv.Atoi(task.TestCaseId)
	testcasedir := fmt.Sprintf("%v/testcase%05d", workDir, testcaseId)
	tcfile := fetchTestcase(endpoint, workDirPath, task.TestCaseId, task.JudgeTaskId)
	if tcfile == nil {
		// error while fetching testcase
		return true
	}

	// Copy program with all possible additional files to testcase
	// dir. Use hardlinks to preserve space with big executables.
	programdir := fmt.Sprintf("%v/execdir", testcasedir)
	if exitCode := ExecAndPrint("mkdir", "-p", programdir); exitCode != 0 {
		Error("Could not create directory '%v'", programdir)
	}

	// We pass this through /bin/sh to have the glob expansion work
	if exitCode := ExecAndPrint("/bin/sh", "-c", fmt.Sprintf("cp -PRl '%v'/compile/* '%v'", workDir, programdir)); exitCode != 0 {
		Error("Could not copy program to '%v'", programdir)
	}

	// do the actual test-run
	hardTimeLimit := float64(runConfig.TimeLimit) + overshootTime(float64(runConfig.TimeLimit), overshoot)

	combinedRunCompare := compareConfig.CombinedRunCompare
	runRunPath, err := fetchExecutable(endpoint, workDirPath, "run", task.RunScriptId, combinedRunCompare)
	if err != nil {
		LogMessage(LogError, "fetching executable failed for run script '%v': %v", task.RunScriptId, err)
		description := fmt.Sprintf("%v: fetch, compile, or deploy of run script failed.", task.RunScriptId)
		endpoint.Disable(newDisabled(runScript, task.RunScriptId), description, task.JudgeTaskId, "")
		return false
	}

	var compareRunPath string
	if combinedRunCompare {
		// set to empty string to signal the testcase_run script that the
		// run script also acts as compare script
		compareRunPath = ""
	} else {
		var err error
		compareRunPath, err = fetchExecutable(endpoint, workDirPath, "compare", task.CompareScriptId, false)
		if err != nil {
			LogMessage(LogError, "fetching executable failed for compare script '%v': %v", task.CompareScriptId, err)
			description := fmt.Sprintf("%v: fetch, compile, or deploy of validation script failed.", task.CompareScriptId)
			endpoint.Disable(newDisabled(compareScript, task.CompareScriptId), description, task.JudgeTaskId, "")
			return false
		}
	}

	// While we already set those above to likely the same values from the
	// compile config, we do set them again from the compare config here.
	_ = os.Setenv("SCRIPTTIMELIMIT", strconv.Itoa(compareConfig.ScriptTimelimit))
	_ = os.Setenv("SCRIPTMEMLIMIT", strconv.Itoa(compareConfig.ScriptMemoryLimit))
	_ = os.Setenv("SCRIPTFILELIMIT", strconv.Itoa(compareConfig.ScriptFilesizeLimit))

	testcaseArgs := append(cpusetOpt, []string{
		tcfile["input"],
		tcfile["output"],
		fmt.Sprintf("%v:%v", runConfig.TimeLimit, hardTimeLimit),
		testcasedir, runRunPath,
		compareRunPath,
		compareConfig.CompareArgs,
	}...)
	exitCode := ExecAndPrint(fmt.Sprintf("%v/testcase_run.sh", LibJudgeDir), testcaseArgs...)
	result, ok := ExitCodes[exitCode]
	if !ok {
		Alert("error")
		Error("Unknown exitcode from testcase_run.sh for s%v: %v", task.SubmitId, exitCode)
	}

	runTime := ""
	metadata := readMetadata(fmt.Sprintf("%v/program.meta", testcasedir))
	if _, ok := metadata["time-used"]; ok {
		runTime = metadata[metadata["time-used"]]
	}

	if result == "compare-error" {
		LogMessage(LogError, "comparing failed for compare script '%v'", task.CompareScriptId)
		description := fmt.Sprintf("compare script %v crashed", task.CompareScriptId)
		endpoint.Disable(newDisabled(compareScript, task.CompareScriptId), description, task.JudgeTaskId, "")
		return false
	}

	judgingRunData := url.Values{}
	judgingRunData.Set("runresult", result)
	judgingRunData.Set("runtime", runTime)
	judgingRunData.Set("output_run", restEncodeFile(fmt.Sprintf("%v/program.out", testcasedir), -1))
	judgingRunData.Set("output_error", restEncodeFile(fmt.Sprintf("%v/program.err", testcasedir), outputStorageLimit))
	judgingRunData.Set("output_system", restEncodeFile(fmt.Sprintf("%v/program.out", testcasedir), outputStorageLimit))
	judgingRunData.Set("output_diff", restEncodeFile(fmt.Sprintf("%v/feedback/judgemessage.txt", testcasedir), outputStorageLimit))
	judgingRunData.Set("metadata", restEncodeFile(fmt.Sprintf("%v/program.meta", testcasedir), outputStorageLimit))
	judgingRunData.Set("hostname", hostname)

	addJudgingRunUrl := fmt.Sprintf("judgehosts/add-judging-run/%v/%v", url.QueryEscape(hostname), task.JudgeTaskId)
	if result == "correct" {
		// Post result back asynchronously
		go endpoint.requestFailOnError(addJudgingRunUrl, http.MethodPost, judgingRunData, false)
	} else {
		// Post result back synchronously
		endpoint.requestFailOnError(addJudgingRunUrl, http.MethodPost, judgingRunData, false)
	}

	var icon string
	if result == "correct" {
		icon = "\033[0;32m✔\033[0m"
	} else {
		icon = "\033[1;31m✗\033[0m"
	}
	LogMessage(LogInfo, "   %v ...done in %vs, result: %v", icon, runTime, result)

	return true
}

func compile(endpoint *endpoint, task judgetask, workDir string, workDirPath string, compileConfig judgetaskCompileConfig, cpusetOpt []string, outputStorageLimit int64) bool {
	// Re-use compilation if it already exists.
	if FileExists(fmt.Sprintf("%v/compile.success", workDir)) {
		return true
	}

	// Get the source code from the DB and store in local file(s).
	content := endpoint.request(fmt.Sprintf("judgehosts/get_files/source/%v", task.SubmitId), http.MethodGet, "")
	var sources getFileResponse
	JsonDecode(content, &sources)
	var files []string
	hasFiltered := false
	for _, source := range sources {
		file := source.Filename
		sourceFile := fmt.Sprintf("%v/compile/%v", workDir, file)
		if compileConfig.FilterCompilerFiles {
			picked := false
			for _, extension := range compileConfig.LanguageExtensions {
				if strings.HasSuffix(file, extension) {
					files = append(files, file)
					picked = true
					break
				}
			}
			if !picked {
				hasFiltered = true
			}
		} else {
			files = append(files, file)
		}

		data, err := base64.StdEncoding.DecodeString(source.Content)
		if err != nil {
			Error("Source file %v is not valid base64 data", source.Filename)
		}

		if err := ioutil.WriteFile(sourceFile, data, 0644); err != nil {
			Error("Could not create %v", sourceFile)
		}
	}

	if len(files) == 0 && hasFiltered {
		// Note: It may be tempting to assume that this codepath can be never
		// reached since we prevent these submissions from being submitted both
		// via command line and the web interface. However, the code path can
		// be triggered when the filtering is activated between submission and
		// rejudge.

		message := fmt.Sprintf("No files with allowed extensions found to pass to compiler. Allowed extensions: %v", compileConfig.LanguageExtensions)
		args := url.Values{}
		args.Set("compile_success", "0")
		args.Set("output_compile", base64.StdEncoding.EncodeToString([]byte(message)))
		endpoint.request(fmt.Sprintf("judgehosts/update-judging/%v/%v", url.PathEscape(hostname), task.JudgeTaskId), http.MethodPut, args)

		// Revoke readablity for domjudge-run user to this workdir.
		_ = os.Chmod(workDir, 0700)
		LogMessage(LogNotice, "Judging s%v, task %v: compile error", task.SubmitId, task.JudgeTaskId)
		return false
	}

	if len(files) == 0 {
		Error("No submission files could be downloaded.")
	}

	execRunPath, err := fetchExecutable(endpoint, workDirPath, "compile", task.CompileScriptId, false)
	if err != nil {
		LogMessage(LogError, "Fetching executable failed for compile script '%v': %v", task.CompileScriptId, err)
		description := fmt.Sprintf("%v: fetch, compile, or deploy of compile script failed: %v", task.CompileScriptId, err)
		endpoint.Disable(newDisabled(compareScript, task.CompileScriptId), description, task.JudgeTaskId, "")
		return false
	}

	// Compile the program.
	compileArgs := append(cpusetOpt, []string{
		execRunPath,
		workDir,
		strings.Join(files, ""),
	}...)
	exitCode := ExecAndPrint(fmt.Sprintf("%v/compile.sh", LibJudgeDir), compileArgs...)

	compileOutput := ""
	compileOut := fmt.Sprintf("%v/compile.out", workDir)
	compileTmp := fmt.Sprintf("%v/compile.tmp", workDir)
	compileMeta := fmt.Sprintf("%v/compile.meta", workDir)

	if FileExists(compileOut) {
		compileOutput = FileGetContents(compileOut, 50000)
	}
	if len(compileOutput) == 0 && FileExists(compileTmp) {
		compileOutput = FileGetContents(compileTmp, 50000)
	}

	// Try to read metadata from file
	metadata := readMetadata(compileMeta)
	if internalError, ok := metadata["internal-error"]; ok {
		Alert("error")
		compileOutput += "\n--------------------------------------------------------------------------------\n\n"
		compileOutput += "Internal errors reported:\n"
		compileOutput += internalError
		var description string
		if strings.HasPrefix(internalError, "compile script: ") {
			internalError = internalError[len("compile script: "):]
			description = fmt.Sprintf("The compile script returned an error: %v", internalError)
			endpoint.Disable(newDisabled(compileScript, task.CompileScriptId), description, task.JudgeTaskId, compileOutput)
		} else {
			description = fmt.Sprintf("Running compile.sh caused an error/crash: %v", internalError)
			// Note we are disabling the judgehost in this case since it's
			// likely an error intrinsic to this judgehost's setup, e.g.
			// missing cgroups.
			endpoint.Disable(newDisabled(judgehost, hostname), description, task.JudgeTaskId, compileOutput)
		}

		LogMessage(LogError, description)
		return false
	}

	exitCodeMeaning, ok := ExitCodes[exitCode]

	if !ok {
		Alert("error")
		description := fmt.Sprintf("Unknown exitcode from compile.sh for s%v: %v", task.SubmitId, exitCode)
		LogMessage(LogError, description)
		endpoint.Disable(newDisabled(compileScript, task.CompileScriptId), description, task.JudgeTaskId, compileOutput)
		return false
	}

	LogMessage(LogInfo, "  💻 Compilation: (%v) '%v'", files[0], ExitCodes[exitCode])

	// What does the exitcode mean?
	compileSucess := exitCodeMeaning == "correct"

	// pop the compilation result back into the judging table
	args := url.Values{}
	if compileSucess {
		args.Set("compile_success", "1")
	} else {
		args.Set("compile_success", "0")
	}
	args.Set("output_compile", restEncodeFile(fmt.Sprintf("%v/compile.out", workDir), outputStorageLimit))
	if entryPoint, ok := metadata["entry_point"]; ok {
		args.Set("entry_point", entryPoint)
	}

	endpoint.request(fmt.Sprintf("judgehosts/update-judging/%v/%v", url.PathEscape(hostname), task.JudgeTaskId), http.MethodPut, args)

	if !compileSucess {
		return false
	}

	compileSuccess := fmt.Sprintf("%v/compile.success", workDir)
	if !FileExists(compileSuccess) {
		_ = ioutil.WriteFile(compileSuccess, []byte(""), 0644)
	} else {
		_ = os.Chtimes(compileSuccess, time.Now(), time.Now())
	}

	return true
}

func fetchTestcase(endpoint *endpoint, workDirPath string, testcaseId string, judgeTaskId int) map[string]string {
	tcfile := make(map[string]string)
	bothFilesExist := true
	files := []string{"input", "output"}
	for _, inout := range files {
		tcfile[inout] = fmt.Sprintf("%v/testcase/testcase.%v.%v", workDirPath, testcaseId, strings.ReplaceAll(inout, "put", ""))

		if !FileExists(tcfile[inout]) {
			bothFilesExist = false
		}
	}

	if bothFilesExist {
		return tcfile
	}

	content := endpoint.requestFailOnError(fmt.Sprintf("judgehosts/get_files/testcase/%v", testcaseId), http.MethodGet, "", false)
	if content == nil {
		e := fmt.Sprintf("Download of testcase data failed for case %v, check your problem integrity.", testcaseId)
		LogMessage(LogError, e)
		endpoint.Disable(newDisabled(testcase, testcaseId), e, judgeTaskId, "")
		return nil
	}

	var testcaseResponse getFileResponse
	JsonDecode(content, &testcaseResponse)

	for _, file := range testcaseResponse {
		filename := tcfile[file.Filename]
		data, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			Error("%v for testcase %v is not valid base64 data", file.Filename, testcaseId)
		}

		if err := ioutil.WriteFile(filename, data, 0644); err != nil {
			Error("Can not write %v for testcase %v: %v", file.Filename, testcaseId, err)
		}
	}

	LogMessage(LogInfo, "  💾 Fetched new testcase %v.", testcaseId)

	return tcfile
}

// Fetches new executable from database if necessary, and
// runs build script to compile executable.
func fetchExecutable(endpoint *endpoint, workdirPath string, executableType string, execId string, combinedRunCompare bool) (string, error) {
	execDir := fmt.Sprintf("%v/executable/%v/%v", workdirPath, executableType, execId)
	execDeployPath := fmt.Sprintf("%v/.deployed", execDir)
	execBuildDir := fmt.Sprintf("%v/build", execDir)
	execBuildPath := fmt.Sprintf("%v/build", execBuildDir)
	execRunPath := fmt.Sprintf("%v/run", execBuildDir)

	if !IsDir(execDir) || !FileExists(execDeployPath) {
		ExecAndPrint("rm", "-rf", execDir)
		ExecAndPrint("rm", "-rf", execBuildDir)
		if exitCode := ExecAndPrint("mkdir", "-p", execBuildDir); exitCode != 0 {
			Error("Could not create directory '%v'", execBuildDir)
		}

		LogMessage(LogInfo, "  💾 Fetching new executable '%v/%v'", executableType, execId)

		content := endpoint.request(fmt.Sprintf("judgehosts/get_files/%v/%v", executableType, execId), http.MethodGet, "")
		var files getFileResponse
		JsonDecode(content, &files)
		for _, file := range files {
			filename := fmt.Sprintf("%v/%v", execBuildDir, file.Filename)
			data, err := base64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				Error("File of executable %v/%v with filename %v is not valid base64 data", executableType, execId, file.Filename)
			}

			if err := ioutil.WriteFile(filename, data, 0644); err != nil {
				Error("Can not write file for executable %v/%v with filename %v: %v", executableType, execId, file.Filename, err)
			}

			if file.IsExecutable {
				_ = os.Chmod(filename, 0755)
			}
		}

		doCompile := true
		if !FileExists(execBuildPath) {
			if FileExists(execRunPath) {
				// 'run' already exists, 'build' does not => don't compile anything
				LogMessage(LogDebug, "'run' exists without 'build', we are done.")
				doCompile = false
			} else {
				languageExtensions := map[string][]string{
					"c":    {"c"},
					"cpp":  {"cpp", "C", "cc"},
					"java": {"java"},
					"py":   {"py", "py2", "py3"},
				}

				buildScript := "#!/bin/sh\n\n"
				execLang := ""
				source := ""
				for lang, extensions := range languageExtensions {
					files, err := ioutil.ReadDir(execBuildDir)
					if err != nil {
						Error("Could not open %v", execBuildDir)
						return "", err
					}

					for _, file := range files {
						ext := filepath.Ext(file.Name())
						if ext != "" {
							ext = ext[1:]
						}

						for _, extension := range extensions {
							if ext == extension {
								execLang = lang
								source = file.Name()
							}
						}
					}

					if execLang != "" {
						break
					}
				}

				if execLang == "" {
					return "", errors.New("executable must either provide an executable file named 'build' or a C/C++/Java or Python file")
				}

				switch execLang {
				case "c":
					buildScript += fmt.Sprintf("gcc -Wall -O2 -std=gnu11 '%v' -o run -lm\n", source)
				case "cpp":
					buildScript += fmt.Sprintf("g++ -Wall -O2 -std=gnu++17 '%v' -o run\n", source)
				case "java":
					source = filepath.Base(source)
					source = source[0 : len(source)-5] // 5 = .java
					buildScript += fmt.Sprintf("javac -cp ./ -d ./ '%v'.java\n", source)
					buildScript += fmt.Sprintf("echo '#!/bin/sh' > run\n")
					// no main class detection here
					buildScript += "echo 'java -cp ./ '$source' >> run\n"
				case "py":
					buildScript += "echo '#!/bin/sh' > run\n"
					buildScript += fmt.Sprintf("echo 'python '%v' >> run\n", source)
				}

				if combinedRunCompare {
					buildScript += `
mv run runjury

cat <<'EOF' > run
#!/bin/sh

# Run wrapper-script to be called from 'testcase_run.sh'.
#
# This script is meant to simplify writing interactive problems where the
# contestants' solution bi-directionally communicates with a jury program, e.g.
# while playing a two player game.
#
# Usage: $0 <testin> <progout> <testout> <metafile> <feedbackdir> <program>...
#
# <testin>      File containing test-input.
# <testout>     File containing test-output.
# <progout>     File where to write solution output. Note: this is unused.
# <feedbackdir> Directory to write jury feedback files to.
# <program>     Command and options of the program to be run.

# A jury-written program called 'runjury' should be available; this program
# will normally be compiled by the build script in the validator directory.
# This program should communicate with the contestants' program to provide
# input and read output via stdin/stdout. This wrapper script handles the setup
# of bi-directional pipes. The jury program should accept the following calling
# syntax:
#
#    runjury <testin> <testout> <feedbackdir> < <output of the program>
#
# The jury program should exit with exitcode 42 if the submissions is accepted,
# 43 otherwise.

TESTIN="$1";  shift
PROGOUT="$1"; shift
TESTOUT="$1"; shift
META="$1"; shift
FEEDBACK="$1"; shift

MYDIR=$(dirname $0)

# Run the program while redirecting its stdin/stdout to 'runjury' via
# 'runpipe'. Note that "$@" expands to separate, quoted arguments.
exec ../dj-bin/runpipe ${DEBUG:+-v} -M "$META" -o "$PROGOUT" "$MYDIR/runjury" "$TESTIN" "$TESTOUT" "$FEEDBACK" = "$@"
EOF

chmod +x run
`
				}

				if err := ioutil.WriteFile(execBuildPath, []byte(buildScript), 0755); err != nil {
					Error("Could not write file 'build' in %v: %v", execBuildDir, err)
				}
			}
		} else if !IsExecutable(execBuildPath) {
			return "", errors.New("invalid executable, file 'build' exists but is not executable")
		}

		if doCompile {
			LogMessage(LogDebug, "Building executable in %v, under 'build/'", execDir)
			if exitCode := ExecAndPrint(fmt.Sprintf("%v/build_executable.sh", LibJudgeDir), execDir); exitCode != 0 {
				return "", fmt.Errorf("failed to build executable in %v", execDir)
			}
		}

		if !IsExecutable(execRunPath) {
			return "", errors.New("invalid build file, must produce an executable file 'run'")
		}
	}

	// Create file to mark executable successfully deployed.
	if !FileExists(execDeployPath) {
		_ = ioutil.WriteFile(execDeployPath, []byte(""), 0644)
	} else {
		_ = os.Chtimes(execDeployPath, time.Now(), time.Now())
	}

	return execRunPath, nil
}

func readMetadata(file string) map[string]string {
	fp, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer fp.Close()

	var data = make(map[string]string)

	scanner := bufio.NewScanner(fp)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			data[parts[0]] = strings.TrimSpace(parts[1])
		}
	}

	return data
}

func FileGetContents(file string, sizelimit int64) string {
	var reader io.Reader
	var err error
	reader, err = os.Open(file)
	if err != nil {
		Error("File is not readable or does not exist: %v", file)
		return ""
	}

	if sizelimit > 0 {
		reader = io.LimitReader(reader, sizelimit)
	}

	data, err := ioutil.ReadAll(reader)
	if err != nil {
		Error("Error reading from file: %v", file)
		return ""
	}

	return string(data)
}

func restEncodeFile(file string, sizelimit int64) string {
	data := FileGetContents(file, sizelimit)
	return base64.StdEncoding.EncodeToString([]byte(data))
}
