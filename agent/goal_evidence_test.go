package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func evidencePair(tool, input, output string) []db.Activity {
	return []db.Activity{
		{Kind: "tool_use", Tool: tool, ToolUseID: "call1", Detail: input},
		{Kind: "tool_result", Tool: tool, ToolUseID: "call1", Detail: output},
	}
}

func TestEvidenceRejectsTask32FalseSuccess(t *testing.T) {
	cases := map[string][]db.Activity{
		"fact only":                      evidencePair("record_fact", `{"evidence":"echo 'report generated'"}`, "fact recorded: 336"),
		"custom error marked successful": evidencePair("scoped_http_observe", `{}`, `{"ok":false,"error":"baseline needs input"}`),
		"failed process":                 evidencePair("Bash", `{}`, "(no output)\n[exit code 1]"),
		"missing result":                 {{Kind: "tool_use", Tool: "Bash", ToolUseID: "call1"}},
	}
	for name, records := range cases {
		t.Run(name, func(t *testing.T) {
			if len(successfulEvidenceCalls(records)) != 0 {
				t.Fatal("non-execution accepted")
			}
		})
	}
	valid := evidencePair("WebFetch", `{"url":"http://example.test/login.php"}`, "[200 OK] login form")
	if len(successfulEvidenceCalls(valid)) != 1 {
		t.Fatal("real result rejected")
	}
	valid[1].ToolUseID = "other"
	if len(successfulEvidenceCalls(valid)) != 0 {
		t.Fatal("unmatched result accepted")
	}
	valid[1].ToolUseID = "call1"
	valid[1].Worker = "other-worker"
	if len(successfulEvidenceCalls(valid)) != 0 {
		t.Fatal("cross-worker result accepted")
	}
}

func TestReportProofRequiresPersistedMatchingWrite(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "i335")
	if err := os.Mkdir(run, 0700); err != nil {
		t.Fatal(err)
	}
	body := "# 진단 보고서\n\n관찰: /login.php 200. SQLi/XSS 미실행.\n"
	input, _ := json.Marshal(map[string]string{"file_path": "report.md", "content": body})
	calls := successfulEvidenceCalls(evidencePair("Write", string(input), "File written"))
	if verifiedReportWrite(dir, 335, calls) {
		t.Fatal("missing report accepted")
	}
	path := filepath.Join(run, "report.md")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if !verifiedReportWrite(dir, 335, calls) {
		t.Fatal("matching report rejected")
	}
	for _, alias := range []string{"write", "WRITE"} {
		if !verifiedReportWrite(dir, 335, successfulEvidenceCalls(evidencePair(alias, string(input), "File written"))) {
			t.Fatalf("real %s alias rejected", alias)
		}
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if verifiedReportWrite(dir, 335, calls) {
		t.Fatal("changed report accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if verifiedReportWrite(dir, 335, calls) {
		t.Fatal("escaping symlink accepted")
	}
	if verifiedReportWrite(dir, 335, successfulEvidenceCalls(evidencePair("Bash", `{"command":"echo 'report generated'"}`, "report generated"))) {
		t.Fatal("echo accepted as report")
	}
}

// Real handler + PostgreSQL regression: task32's exact style of fabricated fact
// must leave the goal open. Then successful Write + matching file must pass.
func TestProveGoalRejectsTask32AndAcceptsRealReport(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("evidence regression", "취약점 진단 보고서 작성", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	goal, err := ts.AddNode(db.KindGoal, map[string]any{"text": "취약점 진단 보고서 작성"}, 5, "open", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.AddNode(db.KindIntent, map[string]any{"summary": "보고서 작성"}, 5, "running", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(ts, "planner")
	tools.taskDir = t.TempDir()
	makeFact := func() int64 {
		id, err := tools.recordOneFact(factItem{Summary: "취약점 진단 보고서 작성 완료", Evidence: "echo 'report generated'", Confidence: "observed"}, intent)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	fake := makeFact()
	prove := func(id int64) string {
		res, err := tools.proveGoal().Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d}`, goal, id)), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}
	prove(fake)
	g, _ := ts.GetNode(goal)
	if g.State != "open" || tools.GoalMet {
		t.Fatal("fabricated fact completed goal")
	}
	res, err := tools.goalMet().Call(context.Background(), json.RawMessage(`{"reason":"done"}`), nil)
	if err != nil || !strings.Contains(res.Flatten(), "미증명") || tools.GoalMet {
		t.Fatal("goal_met bypass", err, res.Flatten())
	}
	body := "# 보고서\n실제 시험 없음. 성공이나 취약점으로 판정하지 않음.\n"
	run := filepath.Join(tools.taskDir, fmt.Sprintf("i%d", intent))
	if err := os.Mkdir(run, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "report.md"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"file_path": "report.md", "content": body})
	for _, a := range evidencePair("Write", string(input), "File written") {
		a.NodeID = &intent
		if _, err := ts.AppendActivity(a); err != nil {
			t.Fatal(err)
		}
	}
	// Future execution must not validate the old invented fact.
	prove(fake)
	g, _ = ts.GetNode(goal)
	if g.State != "open" {
		t.Fatal("future execution validated old fact")
	}
	real, err := tools.recordOneFact(factItem{Summary: "보고서 파일 저장", Evidence: "Write report.md", Confidence: "observed"}, intent)
	if err != nil {
		t.Fatal(err)
	}
	out := prove(real)
	g, _ = ts.GetNode(goal)
	if g.State != "met" || !tools.GoalMet {
		t.Fatalf("real report rejected: %s", out)
	}
}

func TestGoalMetRequiresEveryGoal(t *testing.T) {
	if allGoalsProven(nil) || allGoalsProven([]*db.Node{{State: "open"}}) || allGoalsProven([]*db.Node{{State: "met"}, {State: "abandoned"}}) {
		t.Fatal("unproven goal accepted")
	}
	if !allGoalsProven([]*db.Node{{State: "met"}}) {
		t.Fatal("all met rejected")
	}
}

func TestExplicitCommandProofRequiresMatchingSuccessfulExecution(t *testing.T) {
	claim := claimedCommand(json.RawMessage(`{"evidence":"command: zap-cli quick-scan http://example.test output: no new alerts"}`))
	if claim != "zap-cli quick-scan http://example.test" {
		t.Fatalf("claim = %q", claim)
	}
	use := db.Activity{Kind: "tool_use", Tool: "Bash", ToolUseID: "1", Detail: `{"command":"zap-cli quick-scan http://example.test"}`}
	result := db.Activity{Kind: "tool_result", Tool: "Bash", ToolUseID: "1", Detail: "no new alerts"}
	if commandHasResult(claim, nil) {
		t.Fatal("fabricated ZAP claim accepted")
	}
	if commandHasResult(claim, []db.Activity{use}) {
		t.Fatal("missing result accepted")
	}
	if !commandHasResult(claim, []db.Activity{use, result}) {
		t.Fatal("paired successful execution rejected")
	}
	result.Detail = "bash: zap-cli: command not found"
	if commandHasResult(claim, []db.Activity{use, result}) {
		t.Fatal("missing executable accepted")
	}
	result.Detail = "[exit code 1]"
	if commandHasResult(claim, []db.Activity{use, result}) {
		t.Fatal("failed execution accepted")
	}
	result.Detail = "no new alerts"
	result.ToolUseID = "other"
	if commandHasResult(claim, []db.Activity{use, result}) {
		t.Fatal("unrelated output accepted")
	}
}

func TestClaimedCommandIsNarrow(t *testing.T) {
	if got := claimedCommand(json.RawMessage(`{"evidence":"GET / returned 200"}`)); got != "" {
		t.Fatalf("unexpected claim %q", got)
	}
}

func TestCustomToolsCannotSelfDeclareGoalProof(t *testing.T) {
	// A self-reported body — scanner or not — can never self-declare an execution
	// without the server-owned receipt. For scanner tools this bare-body case is
	// rejected by verifiedScannerReceipt (no envelope); for other custom tools the
	// name is not an execution tool at all.
	for _, tool := range []string{"fiveeyes_nmap_scan", "fiveeyes_sqlmap_check", "unknown_custom"} {
		for _, output := range []string{
			`{"status":"executed","exit_code":0,"stdout":"offline fixture"}`,
			`{"status":"not_run","reason":"no target"}`,
			`{"status":"not_run"}` + "\nwarning text",
			`{"status":"unknown","exit_code":0}`,
			`{"status":"skipped","exit_code":0}`,
			"model-authored successful result",
		} {
			if len(successfulEvidenceCalls(evidencePair(tool, `{}`, output))) != 0 {
				t.Fatalf("custom output self-declared execution proof: %s %s", tool, output)
			}
		}
	}
}

func TestEvidenceRejectsExplicitFailureVerdicts(t *testing.T) {
	for name, output := range map[string]string{
		"unconfigured scope": `{"status":"not_run","reason":"no target"}`,
		"incomplete":         `{"status":"incomplete"}`,
		"native exit":        `{"status":"executed","exit_code":1}`,
		"invalid exit":       `{"status":"executed","exit_code":"0"}`,
		"null exit":          `{"status":"executed","exit_code":null}`,
		"failed":             `{"status":"FAILED"}`,
		"ok false":           `{"ok":false}`,
		"legacy exit suffix": "partial output\n[exit: exit status 2]",
		"legacy timeout":     "partial output\n... [超时终止] ...",
	} {
		t.Run(name, func(t *testing.T) {
			if len(successfulEvidenceCalls(evidencePair("Bash", `{}`, output))) != 0 {
				t.Fatal("explicit failed/non-executed result accepted")
			}
		})
	}
}

// --- B3/F1 회귀테스트: 인증 완주 구조화 성공 술어 (R-1~R-4 거부 / A-1·A-2 승인) ---
func bashEvidence(cmd, output string) db.Activity {
	in, _ := json.Marshal(map[string]string{"command": cmd})
	meta, _ := json.Marshal(output)
	return db.Activity{Tool: "Bash", Detail: string(in), Metadata: meta}
}

func TestHasAccountSuccess(t *testing.T) {
	const base = "http://host.docker.internal:8088"
	// A-1: MFA POST → 303 Location:/account/  (base 75~77 실제 패턴)
	a1 := []db.Activity{bashEvidence(
		"curl -s -i -c cookies.txt -b cookies.txt -X POST "+base+"/mfa.php --data-urlencode otp=123456",
		"HTTP/1.1 303 See Other\r\nLocation: /account/\r\nContent-Length: 0\r\n")}
	if !hasAccountSuccess(a1) {
		t.Error("A-1: 실제 303 /account 승인돼야 함")
	}
	// A-2: POST /mfa 303 + GET /account 200 조합
	a2 := []db.Activity{
		bashEvidence("curl -s -i -b cookies.txt -X POST "+base+"/mfa.php --data-urlencode otp=123456",
			"HTTP/1.1 303 See Other\r\nLocation: /dashboard\r\n"),
		bashEvidence("curl -s -i -b cookies.txt "+base+"/account/",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"),
	}
	if !hasAccountSuccess(a2) {
		t.Error("A-2: MFA303+account200 승인돼야 함")
	}
	// R-1: login GET 200 뿐 (#66 재현) → 거부
	r1 := []db.Activity{bashEvidence("curl -s -i -c cookies.txt -b cookies.txt "+base+"/login.php",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")}
	if hasAccountSuccess(r1) {
		t.Error("R-1: login GET 200 만으로 완주 아님 (거부돼야)")
	}
	// R-2: 로그인 POST 303→/mfa (1차) 만 → 거부
	r2 := []db.Activity{bashEvidence("curl -s -i -c cookies.txt -b cookies.txt -X POST "+base+"/login.php --data-urlencode csrf=x --data-urlencode username=u --data-urlencode password=p",
		"HTTP/1.1 303 See Other\r\nLocation: /mfa.php\r\n")}
	if hasAccountSuccess(r2) {
		t.Error("R-2: 로그인 303/mfa 중간 리디렉션은 완주 아님 (거부돼야)")
	}
	// R-4: 미인증 GET /account 302→/login → 거부
	r4 := []db.Activity{bashEvidence("curl -s -i -c cookies.txt -b cookies.txt "+base+"/account/",
		"HTTP/1.1 302 Found\r\nLocation: /login.php\r\n")}
	if hasAccountSuccess(r4) {
		t.Error("R-4: 미인증 302 는 완주 아님 (거부돼야)")
	}
	// R-3: /account 성공을 주장하지만 실제 출력이 truncate 되어 상태줄 없음 → 거부(fail-closed)
	r3 := []db.Activity{bashEvidence("curl -s -i -b cookies.txt -X POST "+base+"/mfa.php --data-urlencode otp=123456",
		"[이전 출력 생략] <persisted-output> characters truncated]")}
	if hasAccountSuccess(r3) {
		t.Error("R-3: truncate 된 출력은 완주 신호 없음 (거부돼야)")
	}
}

func TestAuthCompletionGoalDetect(t *testing.T) {
	mk := func(text string) *db.Node {
		p, _ := json.Marshal(map[string]string{"text": text})
		return &db.Node{Payload: p}
	}
	if !authCompletionGoal(mk("정상 사용자 흐름 완주: 로그인→MFA→인증후 /account 접근")) {
		t.Error("인증 완주 목표(/account) 인식돼야")
	}
	if authCompletionGoal(mk("대상 웹앱의 SQL 주입 취약점을 실제 요청으로 시험")) {
		t.Error("일반 탐색 목표는 인증 완주로 오인하면 안 됨")
	}
}
