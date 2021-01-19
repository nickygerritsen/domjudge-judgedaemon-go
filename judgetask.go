package main

import "fmt"

type judgetasktype string

type judgetaskCompileConfig struct {
	ScriptTimelimit     int      `json:"script_timelimit"`
	ScriptMemoryLimit   int      `json:"script_memory_limit"`
	ScriptFilesizeLimit int      `json:"script_filesize_limit"`
	LanguageExtensions  []string `json:"language_extensions"`
	FilterCompilerFiles bool     `json:"filter_compiler_files"`
}

type judgetaskRunConfig struct {
	TimeLimit    int    `json:"time_limit"`
	MemoryLimit  int    `json:"memory_limit"`
	OutputLimit  int    `json:"output_limit"`
	ProcessLimit int    `json:"process_limit"`
	EntryPoint   string `json:"entry_point"`
}

type judgetaskCompareConfig struct {
	ScriptTimelimit     int    `json:"script_timelimit"`
	ScriptMemoryLimit   int    `json:"script_memory_limit"`
	ScriptFilesizeLimit int    `json:"script_filesize_limit"`
	CompareArgs         string `json:"compare_args"`
	CombinedRunCompare  bool   `json:"combined_run_compare"`
}

const (
	judgingRun  judgetasktype = "judging_run"
	genericTask               = "generic_task"
	configCheck               = "config_check"
	debugInfo                 = "debug_info"
)

type judgetask struct {
	Type            judgetasktype
	JudgeTaskId     int    `json:"judgetaskid"`
	SubmitId        string `json:"submitid"`
	TestCaseId      string `json:"testcase_id"`
	JobId           string `json:"jobid"`
	CompileScriptId string `json:"compile_script_id"`
	RunScriptId     string `json:"run_script_id"`
	CompareScriptId string `json:"compare_script_id"`
	CompileConfig   string `json:"compile_config"`
	RunConfig       string `json:"run_config"`
	CompareConfig   string `json:"compare_config"`
}

func (j judgetask) JudgingDirectory(workdirpath string) string {
	return fmt.Sprintf("%v/%v/%v", workdirpath, j.SubmitId, j.JobId)
}

func (j judgetask) GetCompileConfig() judgetaskCompileConfig {
	var compileConfig judgetaskCompileConfig
	JsonDecode([]byte(j.CompileConfig), &compileConfig)
	return compileConfig
}

func (j judgetask) getRunConfig() judgetaskRunConfig {
	var runConfig judgetaskRunConfig
	JsonDecode([]byte(j.RunConfig), &runConfig)
	return runConfig
}

func (j judgetask) GetCompareConfig() judgetaskCompareConfig {
	var compareConfig judgetaskCompareConfig
	JsonDecode([]byte(j.CompareConfig), &compareConfig)
	return compareConfig
}
