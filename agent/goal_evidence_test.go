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
