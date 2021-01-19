package main

const DomjudgeVersion = "8.0.0DEV"

const BinDir = "/domjudge/bin"
const EtcDir = "/domjudge/etc"
const LibDir = "/domjudge/lib"
const LibJudgeDir = "/domjudge/lib/judge"
const LogDir = "/domjudge/output/log"
const RunDir = "/domjudge/output/run"
const TmpDir = "/domjudge/output/tmp"
const JudgeDir = "/domjudge/output/judgings"
const ChrootDir = "/chroot/domjudge"
const CgroupDir = "/sys/fs/cgroup"

const RunUser = "domjudge-run"
const RunGroup = "domjudge-run"

var ExitCodes = map[int]string{
	0:   "correct",
	101: "compiler-error",
	102: "timelimit",
	103: "run-error",
	104: "no-output",
	105: "wrong-answer",
	//  106 : "presentation-error", /* dropped since 5.0 */
	107: "memory-limit", /* not in use internally */
	108: "output-limit",
	120: "compare-error",
	/* Uncomment the next line(s) to accept internal errors in the judging
	 * backend as outcome. WARNING: it is highly discouraged to enable
	 * this, as the judgehost may be in an inconsistent state after an
	 * internal error occurred and it is recommended to inspect manually.
	 */
	//  127 : "internal-error",
}
