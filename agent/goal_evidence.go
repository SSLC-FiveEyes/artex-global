package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// This verifies provenance and file persistence, NOT the semantic correctness
// of a security conclusion. A successful HTTP call does not prove a vulnerability.
const diagnosticEvidenceGuidance = `

실행 근거와 완료 판정:
- 실제 응답에서 발견한 링크·폼의 전체 경로와 query를 보존하세요. /login의 404는 /login.php 부재나 로그인 기능 전체 부재를 뜻하지 않습니다.
- 도구 실행 실패·미설치·ok:false는 미실행으로 기록하세요. 요청 성공, 취약점 확인, 미확인을 구분하고 응답에 없는 버전·헤더·폼을 만들어 쓰지 마세요.
- evidence에 적는 출력 값(버전·헤더·표식 문자열·따옴표 안 문구)은 도구 출력에서 그대로 복사하세요. 실제 입력·출력에 없는 값이 있으면 prove_goal이 거부됩니다.
- record_fact는 메모 저장입니다. 그 성공만으로 진단이나 보고서 생성이 증명되지 않습니다. prove_goal 전에 get_worker_trace로 해당 근거를 만든 실제 도구 결과를 확인하세요.
- 작업 종료 후 자동 보고서는 시스템의 별도 후처리입니다. 자동 보고서 생성을 진단 완료 조건이나 별도 진단 목표로 삼지 마세요. 사용자가 작업 중 파일 작성을 별도로 명시한 경우에만 Write로 현재 의도 폴더에 Markdown을 저장하고 같은 intent_id의 fact에 경로를 기록하세요. echo나 사실 노드만으로 파일 저장을 증명하지 마세요.
- 보고서에는 실제 시험 범위·요청/응답 근거·실패·미실행·추정·확정 결과를 구분하세요. 취약점 0건은 전체 안전을 뜻하지 않습니다. 현재 근거가 목표에 부족하면 완료로 증명하지 마세요.
`

func withoutLegacyObserver(in []actool.CoreTool) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(in))
	for _, tool := range in {
		// This custom tool belongs to the old fixed-scope black-box experiment.
		if tool.Name() != "scoped_http_observe" {
			out = append(out, tool)
		}
	}
	return out
}

func allGoalsProven(goals []*db.Node) bool {
	if len(goals) == 0 {
		return false
	}
	for _, goal := range goals {
		if goal.State != "met" {
			return false
		}
	}
	return true
}

// Exclude graph/memory writes and reads: those only repeat model-authored claims.
// The fiveeyes_* scanners run real nmap/sqlmap/ffuf behind the server receipt, so
// they count as execution tools; verifiedScannerReceipt then requires a completed
// server-owned receipt whose embedded body is a conclusive test.
func isExecutionTool(name string) bool {
	switch strings.ToLower(name) {
	case "bash", "webfetch", "web_fetch", "read", "write", "edit", "shell_send":
		return true
	case "fiveeyes_nmap_scan", "fiveeyes_sqlmap_check", "fiveeyes_ffuf_paths":
		return true
	}
	return false
}

func successfulEvidenceResult(a db.Activity) bool {
	if a.Kind != "tool_result" || a.IsError || strings.TrimSpace(a.Detail) == "" {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(a.Detail))
	if strings.HasPrefix(s, "error:") || strings.HasPrefix(s, "blocked by hook:") ||
		strings.Contains(s, "[exit code ") || strings.Contains(s, "[exit: ") ||
		strings.Contains(s, "[超时终止]") || strings.Contains(s, "command not found") {
		return false
	}
	var status map[string]json.RawMessage
	if json.Unmarshal([]byte(a.Detail), &status) == nil {
		if string(status["ok"]) == "false" || string(status["success"]) == "false" {
			return false
		}
		var declared string
		if json.Unmarshal(status["status"], &declared) == nil {
			switch strings.ToLower(strings.TrimSpace(declared)) {
			case "not_run", "incomplete", "failed", "error", "blocked", "timeout", "timed_out":
				return false
			}
		}
		if raw, exists := status["exit_code"]; exists {
			var code int
			if json.Unmarshal(raw, &code) != nil || strings.TrimSpace(string(raw)) == "null" || code != 0 {
				return false
			}
		}
		if e := string(status["error"]); e != "" && e != "null" && e != `""` && e != "false" {
			return false
		}
	}
	return true
}

func isScannerTool(name string) bool {
	switch strings.ToLower(name) {
	case "fiveeyes_nmap_scan", "fiveeyes_sqlmap_check", "fiveeyes_ffuf_paths":
		return true
	}
	return false
}

// scannerReceipt / scannerReceiptEnvelope mirror the server-owned envelope that
// server/customtool_receipt.go wraps around every custom-tool result:
//
//	{"artex_execution_receipt":{...,"runner":{"outcome":...,"result_is_error":...}},
//	 "output":"<the tool's own printed body>"}
//
// A script cannot forge this: its entire stdout becomes the Output string, while
// the top-level receipt is written by the server. The runner outcome — not the
// tool's self-reported body — is authoritative for whether the run completed.
type scannerReceipt struct {
	RunID string `json:"run_id"`
	Tool  struct {
		Key              string `json:"key"`
		DefinitionSHA256 string `json:"definition_sha256"`
	} `json:"tool"`
	InputSHA256  string `json:"input_sha256"`
	OutputSHA256 string `json:"output_sha256"`
	Runner       struct {
		Outcome       string `json:"outcome"`
		ResultIsError bool   `json:"result_is_error"`
	} `json:"runner"`
}

type scannerReceiptEnvelope struct {
	Receipt scannerReceipt `json:"artex_execution_receipt"`
	Output  string         `json:"output"`
}

// approvedScannerDefinitions is the operator-approved set of execution-time tool
// definitions: tool key -> set of approved definition_sha256 hashes. The server
// populates it at startup from an operator-owned source via
// SetApprovedScannerDefinitions. It is empty by default and FAIL-CLOSED: a
// definition whose hash is not on the list is rejected, so a present-but-
// unapproved definition hash is not sufficient on its own.
var approvedScannerDefinitions = map[string]map[string]bool{}

// SetApprovedScannerDefinitions replaces the operator-approved definition set.
// Keys and hashes are compared case-insensitively.
func SetApprovedScannerDefinitions(approved map[string][]string) {
	next := map[string]map[string]bool{}
	for key, hashes := range approved {
		set := map[string]bool{}
		for _, h := range hashes {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				set[h] = true
			}
		}
		next[strings.ToLower(strings.TrimSpace(key))] = set
	}
	approvedScannerDefinitions = next
}

func approvedScannerDefinition(key, hash string) bool {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return false
	}
	return approvedScannerDefinitions[strings.ToLower(strings.TrimSpace(key))][hash]
}

// Transport/connection failures a scanner's body may report: the target could
// not actually be tested (e.g. HTTP 503). These key off the error text, NOT the
// word CRITICAL — sqlmap prints [CRITICAL] for the legitimate "not injectable"
// conclusion too, so a completed negative test stays valid.
var scannerInconclusiveMarkers = []string{
	"could interfere with the results",
	"http error code",
	"unable to connect",
	"connection timed out",
	"503 (service unavailable)",
}

// verifiedScannerReceipt reports whether a scanner tool_result is backed by a
// server execution receipt for a completed, un-errored run of an operator-
// approved scanner, bound to this very call, whose embedded body is a conclusive
// per-tool result. The self-reported body is never trusted on its own.
func verifiedScannerReceipt(use, result db.Activity) bool {
	if !isScannerTool(result.Tool) || result.Kind != "tool_result" || result.IsError {
		return false
	}
	var env scannerReceiptEnvelope
	if json.Unmarshal([]byte(result.Detail), &env) != nil {
		return false
	}
	r := env.Receipt
	// A server-owned receipt is required: a bare or model-authored body has no
	// runner, so it can never self-declare an execution.
	if strings.TrimSpace(r.Runner.Outcome) == "" {
		return false
	}
	// The server runner is authoritative; only a completed, un-errored run counts.
	if r.Runner.Outcome != "completed" || r.Runner.ResultIsError {
		return false
	}
	// The receipt must name this very allowlisted scanner, by an operator-approved
	// execution-time definition (a present-but-unapproved hash is insufficient).
	if !isScannerTool(r.Tool.Key) || !strings.EqualFold(r.Tool.Key, result.Tool) {
		return false
	}
	if !approvedScannerDefinition(r.Tool.Key, r.Tool.DefinitionSHA256) {
		return false
	}
	// Output integrity: the body must be exactly the bytes the server hashed, so a
	// conclusive body cannot be substituted for the receipt's real one.
	if r.OutputSHA256 == "" || sha256Hex(env.Output) != r.OutputSHA256 {
		return false
	}
	// The receipt must belong to this call: its run_id must match the input's.
	if !receiptMatchesCall(r, use) {
		return false
	}
	return conclusiveScannerBody(r.Tool.Key, env.Output)
}

// receiptMatchesCall binds the receipt to the paired tool_use: the input's
// run_id must match the receipt, and the receipt's input_sha256 must equal the
// hash of the canonical input — the same compact, key-sorted JSON the server
// hashes (customToolValueSHA256). This catches a receipt reused for a call whose
// target differs but whose run_id is identical.
func receiptMatchesCall(r scannerReceipt, use db.Activity) bool {
	if strings.TrimSpace(r.RunID) == "" || strings.TrimSpace(r.InputSHA256) == "" {
		return false
	}
	var params map[string]any
	if json.Unmarshal([]byte(use.Detail), &params) != nil {
		return false
	}
	runID, _ := params["run_id"].(string)
	if strings.TrimSpace(runID) == "" || runID != r.RunID {
		return false
	}
	canonical, err := json.Marshal(params)
	if err != nil {
		return false
	}
	return sha256Hex(string(canonical)) == r.InputSHA256
}

// conclusiveScannerBody applies a per-tool completeness check to the tool's own
// body. The body must report an "executed" run that exited 0 (a future wrapper
// that reclassifies an unreachable run as "incomplete" is rejected here) and must
// carry a recognized terminal result for that tool, validated against the run's
// own argv: an empty, malformed, out-of-scope or operational-error body is not a
// completed test.
func conclusiveScannerBody(toolKey, body string) bool {
	var w struct {
		Status          string          `json:"status"`
		ExitCode        *int            `json:"exit_code"`
		Argv            []string        `json:"argv"`
		Stdout          string          `json:"stdout"`
		Stderr          string          `json:"stderr"`
		Matches         json.RawMessage `json:"matches"`
		NegativeControl json.RawMessage `json:"negative_control"`
	}
	if json.Unmarshal([]byte(body), &w) != nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(w.Status), "executed") || w.ExitCode == nil || *w.ExitCode != 0 {
		return false
	}
	switch strings.ToLower(toolKey) {
	case "fiveeyes_sqlmap_check":
		return conclusiveSqlmapBody(w.Argv, w.Stdout, w.Stderr)
	case "fiveeyes_nmap_scan":
		return conclusiveNmapBody(w.Argv, w.Stdout)
	case "fiveeyes_ffuf_paths":
		return conclusiveFfufBody(w.Matches, w.NegativeControl)
	}
	return false
}

const sqlmapNegativeVerdict = "all tested parameters do not appear to be injectable"

var (
	reSqlmapInjectionBlock = regexp.MustCompile(`(?s)sqlmap identified the following injection point\(s\).*?\n---\s*\n(.*?)\n---`)
	reSqlmapCriticalLine   = regexp.MustCompile(`\[(?:CRITICAL|ERROR)\]([^\n]*)`)
	reSqlmapType           = regexp.MustCompile(`(?m)^\s+Type:\s*boolean-based blind\s*$`)
	reSqlmapPayload        = regexp.MustCompile(`(?m)^\s+Payload:\s*\S`)
)

// conclusiveSqlmapBody mirrors check_sqlmap_result.py: a completed test ends
// cleanly, is free of transport/cache/interrupt errors, and reports a recognized
// terminal finding — either the explicit negative verdict, or an injection block
// that actually names the tested GET parameter (from -p) with a supported type
// and a payload. A block with no real content ("no parameter or payload") is not
// a finding. Keep both in sync (shared pinned-version contract).
func conclusiveSqlmapBody(argv []string, stdout, stderr string) bool {
	param, ok := sqlmapParam(argv)
	if !ok {
		return false
	}
	if !strings.Contains(stdout, "[*] ending @") {
		return false // no end marker: truncated / interrupted
	}
	text := stdout + "\n" + stderr
	lower := strings.ToLower(text)
	for _, m := range scannerInconclusiveMarkers {
		if strings.Contains(lower, m) {
			return false // transport error (e.g. 503)
		}
	}
	for _, s := range []string{"resumed the following injection", "resuming back-end", "resuming injection", "time limit", "time-limit", "user aborted", "user quit", "[truncated]", "[exit:"} {
		if strings.Contains(lower, s) {
			return false // cached / interrupted / truncated
		}
	}
	for _, m := range reSqlmapCriticalLine.FindAllStringSubmatch(text, -1) {
		if !strings.Contains(strings.ToLower(m[1]), sqlmapNegativeVerdict) {
			return false // an operational error line, not the benign verdict
		}
	}
	hasNegative := strings.Contains(lower, sqlmapNegativeVerdict)
	hasInjection := false
	if m := reSqlmapInjectionBlock.FindStringSubmatch(stdout); m != nil {
		if !validSqlmapInjectionBlock(m[1], param) {
			return false // a reported injection block must have real content
		}
		hasInjection = true
	}
	if hasInjection && hasNegative {
		return false // contradictory
	}
	return hasInjection || hasNegative
}

func sqlmapParam(argv []string) (string, bool) {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "-p" {
			p := strings.TrimSpace(argv[i+1])
			return p, p != ""
		}
	}
	return "", false
}

func validSqlmapInjectionBlock(block, param string) bool {
	paramLine := regexp.MustCompile(`(?m)^Parameter:\s*` + regexp.QuoteMeta(param) + `\s*\(GET\)\s*$`)
	return paramLine.MatchString(block) && reSqlmapType.MatchString(block) && reSqlmapPayload.MatchString(block)
}

var nmapPortStates = map[string]bool{
	"open": true, "closed": true, "filtered": true,
	"unfiltered": true, "open|filtered": true, "closed|filtered": true,
}

type nmapXMLRun struct {
	XMLName  xml.Name `xml:"nmaprun"`
	Scanner  string   `xml:"scanner,attr"`
	ScanInfo []struct {
		Protocol    string `xml:"protocol,attr"`
		Type        string `xml:"type,attr"`
		Services    string `xml:"services,attr"`
		NumServices string `xml:"numservices,attr"`
	} `xml:"scaninfo"`
	Host []struct {
		TimedOut string `xml:"timedout,attr"`
		Status   struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Address []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
		Port []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   string `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
		} `xml:"ports>port"`
		ExtraPorts []struct {
			State string `xml:"state,attr"`
			Count string `xml:"count,attr"`
		} `xml:"ports>extraports"`
	} `xml:"host"`
	RunStats struct {
		Finished []struct {
			Exit string `xml:"exit,attr"`
		} `xml:"finished"`
		Hosts []struct {
			Total string `xml:"total,attr"`
			Up    string `xml:"up,attr"`
			Down  string `xml:"down,attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}

// conclusiveNmapBody is a faithful subset of check_nmap_result.py: it validates
// the fixed TCP-connect profile's receipt against its OWN argv and XML — the argv
// is the approved profile, the XML parses (custom DTD/entity rejected), scan
// scope matches, the run finished successfully, exactly one up host matches the
// scanned target, and every requested port is accounted for by an explicit
// <port> state or an <extraports> aggregate (so an aggregate-only result is valid
// and a wrong-target / failed / malformed result is not).
func conclusiveNmapBody(argv []string, stdout string) bool {
	target, ports, ok := nmapArgvScope(argv)
	if !ok {
		return false
	}
	safe := strings.Replace(stdout, "<!DOCTYPE nmaprun>", "", 1)
	if u := strings.ToUpper(safe); strings.Contains(u, "<!DOCTYPE") || strings.Contains(u, "<!ENTITY") {
		return false
	}
	var run nmapXMLRun
	if xml.Unmarshal([]byte(safe), &run) != nil || run.Scanner != "nmap" {
		return false
	}
	if len(run.ScanInfo) != 1 || run.ScanInfo[0].Protocol != "tcp" || run.ScanInfo[0].Type != "connect" {
		return false
	}
	if !sameNmapPortSet(run.ScanInfo[0].Services, ports) || run.ScanInfo[0].NumServices != strconv.Itoa(len(ports)) {
		return false
	}
	if len(run.RunStats.Finished) != 1 || run.RunStats.Finished[0].Exit != "success" {
		return false
	}
	if len(run.Host) != 1 || len(run.RunStats.Hosts) != 1 {
		return false
	}
	if h := run.RunStats.Hosts[0]; h.Total != "1" || h.Up != "1" || h.Down != "0" {
		return false
	}
	host := run.Host[0]
	var ipv4 []string
	for _, a := range host.Address {
		if a.AddrType == "ipv4" {
			ipv4 = append(ipv4, a.Addr)
		}
	}
	if len(ipv4) != 1 || ipv4[0] != target {
		return false
	}
	if host.TimedOut == "true" || host.Status.State != "up" {
		return false
	}
	seen := map[int]bool{}
	for _, p := range host.Port {
		pid, err := strconv.Atoi(p.PortID)
		if err != nil || p.Protocol != "tcp" || !ports[pid] || seen[pid] || !nmapPortStates[p.State.State] {
			return false
		}
		seen[pid] = true
	}
	count := 0
	for _, g := range host.ExtraPorts {
		n, err := strconv.Atoi(g.Count)
		if err != nil || !nmapPortStates[g.State] || n <= 0 {
			return false
		}
		count += n
	}
	return count == len(ports)-len(seen)
}

func nmapArgvScope(argv []string) (string, map[int]bool, bool) {
	profile := []string{"nmap", "-sT", "-Pn", "-n", "--max-rate", "5", "--max-retries", "0", "--host-timeout", "30s", "-p"}
	if len(argv) != 15 || filepath.Base(argv[0]) != "nmap" {
		return "", nil, false
	}
	for i := 1; i < len(profile); i++ {
		if argv[i] != profile[i] {
			return "", nil, false
		}
	}
	if argv[12] != "-oX" || argv[13] != "-" {
		return "", nil, false
	}
	ports, ok := parseNmapPorts(argv[11])
	if !ok {
		return "", nil, false
	}
	return argv[14], ports, true
}

var reNmapPortItem = regexp.MustCompile(`^(\d+)(?:-(\d+))?$`)

// parseNmapPorts parses comma/range port notation into a set, rejecting
// duplicates and out-of-range values.
func parseNmapPorts(spec string) (map[int]bool, bool) {
	ports := map[int]bool{}
	for _, item := range strings.Split(spec, ",") {
		m := reNmapPortItem.FindStringSubmatch(item)
		if m == nil {
			return nil, false
		}
		low, _ := strconv.Atoi(m[1])
		high := low
		if m[2] != "" {
			high, _ = strconv.Atoi(m[2])
		}
		if low < 1 || low > high || high > 65535 {
			return nil, false
		}
		for p := low; p <= high; p++ {
			if ports[p] {
				return nil, false
			}
			ports[p] = true
		}
	}
	return ports, len(ports) > 0
}

func sameNmapPortSet(spec string, ports map[int]bool) bool {
	got, ok := parseNmapPorts(spec)
	if !ok || len(got) != len(ports) {
		return false
	}
	for p := range ports {
		if !got[p] {
			return false
		}
	}
	return true
}

// conclusiveFfufBody requires the structured ffuf result: a JSON array of matches
// (null or non-array rejected) and a negative-control object carrying a baseline
// status (false/null/non-object rejected). An empty matches array is a valid
// "no paths found" completion.
func conclusiveFfufBody(matches, negativeControl json.RawMessage) bool {
	if len(matches) == 0 || strings.TrimSpace(string(matches)) == "null" {
		return false
	}
	var ms []json.RawMessage
	if json.Unmarshal(matches, &ms) != nil {
		return false // matches must be a JSON array
	}
	if len(negativeControl) == 0 || strings.TrimSpace(string(negativeControl)) == "null" {
		return false
	}
	var nc map[string]json.RawMessage
	if json.Unmarshal(negativeControl, &nc) != nil {
		return false // negative control must be an object
	}
	_, hasStatus := nc["status"]
	return hasStatus
}

var reSHA256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// LoadApprovedScannerDefinitions loads the operator-reviewed approval file (tool
// key -> list of approved definition_sha256) and installs it. An empty path
// leaves the fail-closed empty set (scanner evidence disabled) and is NOT an
// error. A set path whose file cannot be read, is not the expected shape, names a
// non-scanner key, has an empty list, or lists a non-64-hex value is a hard
// startup error. It loads once at startup; there is no runtime refresh.
func LoadApprovedScannerDefinitions(path string) error {
	if strings.TrimSpace(path) == "" {
		SetApprovedScannerDefinitions(nil)
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("approved scanner definitions: %w", err)
	}
	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("approved scanner definitions: invalid JSON: %w", err)
	}
	for key, hashes := range raw {
		if !isScannerTool(key) {
			return fmt.Errorf("approved scanner definitions: unknown tool key %q", key)
		}
		if len(hashes) == 0 {
			return fmt.Errorf("approved scanner definitions: %q lists no hashes", key)
		}
		for _, h := range hashes {
			if !reSHA256Hex.MatchString(strings.TrimSpace(h)) {
				return fmt.Errorf("approved scanner definitions: %q lists a non-64-hex value", key)
			}
		}
	}
	SetApprovedScannerDefinitions(raw)
	return nil
}

func sha256Hex(b string) string {
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])
}

// Return real executions only, pairing by intent, worker, tool and call ID.
// Results are required to follow calls, so reused IDs cannot prove earlier work.
func successfulEvidenceCalls(records []db.Activity) []db.Activity {
	uses := map[string]db.Activity{}
	key := func(a db.Activity) string {
		var node int64
		if a.NodeID != nil {
			node = *a.NodeID
		}
		return fmt.Sprintf("%d/%s/%s/%s", node, a.Worker, a.Tool, a.ToolUseID)
	}
	var out []db.Activity
	for _, a := range records {
		if a.ToolUseID == "" || !isExecutionTool(a.Tool) {
			continue
		}
		if a.Kind == "tool_use" {
			uses[key(a)] = a
			continue
		}
		use, ok := uses[key(a)]
		accepted := false
		if ok {
			if isScannerTool(a.Tool) {
				// Scanners are verified through their server receipt, not the
				// generic body-status heuristic.
				accepted = verifiedScannerReceipt(use, a)
			} else {
				accepted = successfulEvidenceResult(a)
			}
		}
		if accepted {
			// Preserve the result on Metadata for fixed report-tool validation.
			use.Metadata, _ = json.Marshal(a.Detail)
			out = append(out, use)
			delete(uses, key(a))
		}
	}
	return out
}

func (t *ToolSet) intentEvidence(intent int64) ([]db.Activity, error) {
	var all []db.Activity
	var cursor int64
	for {
		batch, next, err := t.ts.ActivityList(&intent, cursor, 500)
		if err != nil {
			return nil, err
		}
		ids := make([]int64, 0, len(batch))
		for _, a := range batch {
			if a.Kind == "tool_use" || a.Kind == "tool_result" {
				ids = append(ids, a.ID)
			}
		}
		details, err := t.ts.ActivityByIDs(ids)
		if err != nil {
			return nil, err
		}
		byID := map[int64]string{}
		for _, a := range details {
			byID[a.ID] = a.Detail
		}
		for _, a := range batch {
			if detail, ok := byID[a.ID]; ok {
				a.Detail = detail
				all = append(all, a)
			}
		}
		if len(batch) < 500 {
			return all, nil
		}
		cursor = next
	}
}

var englishReportWord = regexp.MustCompile(`(?i)\breports?\b`)

func reportGoal(node *db.Node) bool {
	var p struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(node.Payload, &p)
	s := strings.ToLower(p.Text)
	return strings.Contains(s, "보고서") || englishReportWord.MatchString(s) || strings.Contains(s, "报告")
}

// --- B3/F1: 인증 완주류 목표의 구조화 성공 술어 ---
// 자유서술 리터럴(H1·H3)과 truncate 스킵(H2)에 의존하지 않고, 실제 tool_result 의
// HTTP 상태줄에서 완주 신호를 구조적으로 확인한다. score_task.py 와 동일 판정식:
//   완주 = 실제 응답에 303 Location:/account*  또는  (POST /mfa* 303 다음 GET /account* 200)

// authCompletionGoal: 목표가 /account 접근을 완주 기준으로 삼는 인증류인지.
func authCompletionGoal(node *db.Node) bool {
	var p struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(node.Payload, &p)
	return strings.Contains(strings.ToLower(p.Text), "/account")
}

type httpTx struct {
	method, path string
	status       int
	location     string
}

var (
	reHTTPStatus = regexp.MustCompile(`HTTP/\d(?:\.\d)?\s+(\d{3})`)
	reHTTPLoc    = regexp.MustCompile(`(?im)^\s*Location:\s*(\S+)`)
	rePostish    = regexp.MustCompile(`(?i)-X\s*POST|--data`)
	reCurlURL    = regexp.MustCompile(`https?://[^\s"']+`)
	reURLPath    = regexp.MustCompile(`https?://[^/]+(/[^\s"'?]*)`)
)

func curlMethodPath(command string) (string, string) {
	method := "GET"
	if rePostish.MatchString(command) {
		method = "POST"
	}
	path := ""
	if urls := reCurlURL.FindAllString(command, -1); len(urls) > 0 {
		if m := reURLPath.FindStringSubmatch(urls[len(urls)-1]); m != nil {
			path = m[1]
		}
	}
	return method, path
}

// httpTransactions extracts (method,path,status,location) from each successful
// Bash curl call. Input is successfulEvidenceCalls output: Detail=tool input,
// Metadata=json-encoded result output. Status lines are read from the real
// output; a truncated output simply yields no /account signal (fail-closed).
func httpTransactions(calls []db.Activity) []httpTx {
	var txs []httpTx
	for _, c := range calls {
		if !strings.EqualFold(c.Tool, "bash") {
			continue
		}
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal([]byte(c.Detail), &in) != nil {
			continue
		}
		var output string
		_ = json.Unmarshal(c.Metadata, &output)
		method, path := curlMethodPath(in.Command)
		idx := reHTTPStatus.FindAllStringSubmatchIndex(output, -1)
		for i, m := range idx {
			status, _ := strconv.Atoi(output[m[2]:m[3]])
			end := len(output)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			block := output[m[1]:end]
			loc := ""
			if lm := reHTTPLoc.FindStringSubmatch(block); lm != nil {
				loc = strings.TrimSpace(lm[1])
			}
			txs = append(txs, httpTx{method, path, status, loc})
		}
	}
	return txs
}

// hasAccountSuccess: 실제 tool_result 에 인증 완주 구조 신호가 있는가.
func hasAccountSuccess(calls []db.Activity) bool {
	mfaPost303, account200 := false, false
	for _, tx := range httpTransactions(calls) {
		if tx.status == 303 && strings.HasPrefix(tx.location, "/account") {
			return true
		}
		if tx.method == "POST" && strings.HasPrefix(tx.path, "/mfa") && tx.status == 303 {
			mfaPost303 = true
		}
		if tx.method == "GET" && strings.HasPrefix(tx.path, "/account") && tx.status == 200 {
			account200 = true
		}
	}
	return mfaPost303 && account200
}

func (t *ToolSet) checkGoalEvidence(goal, node *db.Node) error {
	if node.Inherited || node.State != "confirmed" {
		return fmt.Errorf("완료 근거는 현재 작업에서 실행·확인한 confirmed 사실/발견이어야 합니다. 이전 작업 결과는 현재 범위에서 재확인하세요")
	}
	var p struct {
		Confidence string `json:"confidence"`
	}
	_ = json.Unmarshal(node.Payload, &p)
	if node.Kind == db.KindFact && !strings.EqualFold(strings.TrimSpace(p.Confidence), "observed") {
		return fmt.Errorf("추정 또는 신뢰도 미표시 사실은 완료 증명이 아닙니다. 실제 관측 근거를 기록하세요")
	}
	command := claimedCommand(node.Payload)
	var mismatch []string
	var authMissing bool
	edges, err := t.ts.EdgesTouching([]int64{node.ID})
	if err != nil {
		return err
	}
	for _, edge := range edges {
		if edge.To != node.ID || edge.Rel != db.RelYields {
			continue
		}
		records, err := t.intentEvidence(edge.From)
		if err != nil {
			return err
		}
		// Later execution cannot retroactively validate a previously invented fact.
		prior := records[:0]
		for _, a := range records {
			if !a.CreatedAt.After(node.CreatedAt) {
				prior = append(prior, a)
			}
		}
		calls := successfulEvidenceCalls(prior)
		if len(calls) == 0 || (command != "" && !commandHasResult(command, prior)) {
			continue
		}
		if missing := missingEvidenceLiterals(node.Payload, calls); len(missing) > 0 {
			mismatch = missing
			continue
		}
		// F1(H1·H2·H3): 인증 완주류 목표는 자유서술 리터럴이 아니라 실제 tool_result 의
		// 구조화 성공 신호를 요구한다. truncate 로 리터럴 검증이 스킵됐어도 상태줄에서 직접
		// 확인하므로 우회가 막힌다(fail-closed).
		if authCompletionGoal(goal) && !hasAccountSuccess(calls) {
			authMissing = true
			continue
		}
		if !reportGoal(goal) {
			return nil
		}
		if verifiedReportWrite(t.taskDir, edge.From, calls) {
			return nil
		}
	}
	if authMissing {
		return fmt.Errorf("인증 완주 목표의 완료 근거가 부족합니다. 실제 tool_result 에 303 Location:/account/ (또는 MFA POST 303 다음 GET /account 200)가 없습니다. 로그인 1차의 중간 리디렉션(303 /mfa.php)이나 미인증 302 만으로는 완주가 아닙니다. 실제 /account 도달 응답을 받은 뒤 그 응답을 record_fact 하세요")
	}
	if len(mismatch) > 0 {
		return fmt.Errorf("evidence에 적은 값 %s이(가) 이 사실을 만든 intent의 실제 실행 입력·출력에 없습니다. 도구 출력에 나온 값을 그대로 옮겨 적은 새 fact를 기록하세요", quoteList(mismatch))
	}
	if reportGoal(goal) {
		return fmt.Errorf("보고서 저장 근거가 없습니다. 해당 intent에서 Write로 작업 폴더에 Markdown 보고서를 저장한 뒤 경로를 포함한 새 fact를 기록하세요. 실제 파일 내용과 성공한 Write 입력이 일치해야 합니다")
	}
	return fmt.Errorf("해당 사실을 만든 intent에 성공한 실행 도구 호출과 결과가 없습니다. record_fact 자체나 실패한 도구는 완료 근거가 아닙니다")
}

// os.Root prevents traversal and escaping symlinks. We compare the current bytes
// with the successful Write input; echo, a missing file or a later replacement
// cannot establish persistence. This is not a report-quality/content validator.
func verifiedReportWrite(taskDir string, intent int64, calls []db.Activity) bool {
	if taskDir == "" {
		return false
	}
	root, err := os.OpenRoot(taskDir)
	if err != nil {
		return false
	}
	defer root.Close()
	for _, call := range calls {
		toolName := strings.ToLower(call.Tool)
		if toolName != "write" {
			continue
		}
		var in struct {
			Path    string `json:"file_path"`
			Content string `json:"content"`
		}
		if json.Unmarshal([]byte(call.Detail), &in) != nil || strings.TrimSpace(in.Content) == "" {
			continue
		}
		expected := in.Content
		if in.Path == "" {
			continue
		}
		path := in.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(taskDir, fmt.Sprintf("i%d", intent), path)
		}
		rel, err := filepath.Rel(taskDir, path)
		if err != nil || !filepath.IsLocal(rel) || strings.ToLower(filepath.Ext(rel)) != ".md" {
			continue
		}
		file, err := root.Open(rel)
		if err != nil {
			continue
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			file.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
		file.Close()
		if err != nil || len(data) > 2<<20 || strings.TrimSpace(string(data)) == "" {
			continue
		}
		if toolName == "write" && string(data) == expected {
			return true
		}
	}
	return false
}

// Only explicit `command:` claims are checked. This is a provenance check, not
// a semantic verification of the output or a general hallucination detector.
var explicitCommand = regexp.MustCompile(`(?im)^\s*(?:command|명령)\s*:\s*(.+?)(?:\s+output\s*:.*)?$`)

func claimedCommand(payload json.RawMessage) string {
	var p struct {
		Evidence string `json:"evidence"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return ""
	}
	m := explicitCommand.FindStringSubmatch(p.Evidence)
	if len(m) != 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// commandHasResult requires the same shell command and a paired, successful
// tool result. Activity supplied here has full detail and the tool-use ID.
func commandHasResult(command string, records []db.Activity) bool {
	for _, a := range successfulEvidenceCalls(records) {
		if strings.ToLower(a.Tool) != "bash" {
			continue
		}
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal([]byte(a.Detail), &in) == nil && strings.TrimSpace(in.Command) == command {
			return true
		}
	}
	return false
}

// Literal claims in a fact's one-line evidence must come from the execution
// record. A model that paraphrases "ARTEX_REPORT_TEST_SUCCESS" as
// "ARTEX_REPORT_SUCCESS" has not observed what it reports, even when the command
// itself really ran. Only two kinds of text are treated as literal claims:
//   - spans inside backticks or double quotes that contain an ASCII letter/digit
//   - tokens with a letter plus a digit or one of _ . / : (HTTP/1.1, nginx/1.25,
//     index.php, ARTEX_REPORT_SUCCESS)
//
// Plain words, Korean prose and bare dates/numbers are not checked, so ordinary
// explanation does not fail the proof. Matching is case-insensitive with
// collapsed whitespace against both the tool inputs and the tool outputs of the
// same intent. This narrows fabricated observations; it is not a general
// hallucination detector.
var (
	quotedEvidenceClaim = regexp.MustCompile("`([^`\n]{3,200})`|\"([^\"\n]{3,200})\"")
	evidenceToken       = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_./:%=-]*[A-Za-z0-9]`)
	evidenceTokenLetter = regexp.MustCompile(`[A-Za-z]`)
	evidenceTokenMark   = regexp.MustCompile(`[0-9_./:]`)
	asciiAlnum          = regexp.MustCompile(`[A-Za-z0-9]`)
	collapseSpace       = regexp.MustCompile(`\s+`)
)

func claimedEvidenceLiterals(payload json.RawMessage) []string {
	var p struct {
		Evidence string `json:"evidence"`
	}
	if json.Unmarshal(payload, &p) != nil || strings.TrimSpace(p.Evidence) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		k := strings.ToLower(s)
		if s != "" && !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	for _, m := range quotedEvidenceClaim.FindAllStringSubmatch(p.Evidence, -1) {
		for _, g := range m[1:] {
			if g != "" && asciiAlnum.MatchString(g) {
				add(g)
			}
		}
	}
	rest := quotedEvidenceClaim.ReplaceAllString(p.Evidence, " ")
	for _, tok := range evidenceToken.FindAllString(rest, -1) {
		if len(tok) >= 4 && evidenceTokenLetter.MatchString(tok) && evidenceTokenMark.MatchString(tok) {
			add(tok)
		}
	}
	return out
}

// missingEvidenceLiterals returns the literal claims absent from every input
// and output of calls. A truncated/spilled output may hide the cited text, so
// in that case the literal check is skipped rather than rejecting a real
// observation; the command provenance check still applies.
func missingEvidenceLiterals(payload json.RawMessage, calls []db.Activity) []string {
	claims := claimedEvidenceLiterals(payload)
	if len(claims) == 0 {
		return nil
	}
	var hay strings.Builder
	for _, c := range calls {
		var output string
		_ = json.Unmarshal(c.Metadata, &output)
		if strings.Contains(output, "<persisted-output>") || strings.Contains(output, "characters truncated]") {
			return nil
		}
		hay.WriteString(c.Detail)
		hay.WriteString("\n")
		hay.WriteString(output)
		hay.WriteString("\n")
	}
	norm := func(s string) string { return strings.ToLower(collapseSpace.ReplaceAllString(s, " ")) }
	h := norm(hay.String())
	// Tool inputs are stored as JSON; also match their decoded form so a claim
	// such as "a/b" is found even when the input encodes it as "a\/b".
	h += "\n" + norm(strings.NewReplacer(`\/`, "/", `\"`, `"`, `\n`, " ", `\t`, " ").Replace(hay.String()))
	var missing []string
	for _, c := range claims {
		if !strings.Contains(h, norm(c)) {
			missing = append(missing, c)
		}
	}
	return missing
}

func quoteList(items []string) string {
	q := make([]string, 0, len(items))
	for i, s := range items {
		if i == 5 {
			q = append(q, "…")
			break
		}
		q = append(q, strconv.Quote(s))
	}
	return strings.Join(q, ", ")
}
