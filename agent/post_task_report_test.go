package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestPostRunReportingSeparatedFromDiagnosticGoal(t *testing.T) {
	input := "로컬 명령으로 ARTEX_REPORT_TEST_SUCCESS를 출력하고 결과를 기록하세요.\n작업 종료 후 자동 보고서에는 결과와 미실행 항목을 표시하세요."
	got := DiagnosticGoalText(input)
	if !strings.Contains(got, "ARTEX_REPORT_TEST_SUCCESS") || strings.Contains(got, "자동 보고서") {
		t.Fatalf("wrong fallback: %q", got)
	}
	if got := DiagnosticGoalText("결과를 기록하세요. 작업 종료 후 자동 보고서를 생성하세요."); got != "결과를 기록하세요." {
		t.Fatalf("lost same-line diagnostic objective: %q", got)
	}
	if got := DiagnosticGoalText("로컬 명령을 한 번 실행하세요. 작업 종료 후 자동 보고서에 수행 내용과 결과, 미실행 항목을 표시하세요."); got != "로컬 명령을 한 번 실행하세요." {
		t.Fatalf("lost fallback diagnostic objective: %q", got)
	}
	for _, original := range []string{
		"로컬 명령을 실행하고 자동 보고서를 생성해",
		"작업 종료 후 자동 보고서를 생성하세요. 로컬 명령도 실행하세요.",
		"작업 종료 후 자동 보고서를 작성하고 다른 로컬 명령을 실행하세요",
		"로컬 명령 실행\n자동 보고서를 생성하고 다른 명령을 실행하세요",
		"작업 중 report.md 파일을 직접 작성하세요",
	} {
		if got := DiagnosticGoalText(original); got != original {
			t.Fatalf("ambiguous or manual instruction changed: %q => %q", original, got)
		}
	}
	if got := DiagnosticGoalText("작업 종료 후 자동 보고서를 생성하세요."); got != "" {
		t.Fatalf("post-run-only instruction should yield an empty diagnostic fallback: %q", got)
	}
	for _, s := range []string{"Generate an automated report detailing the executed command", "작업 종료 후 자동 보고서 작성"} {
		if !IsAutomaticReportGoal(s) {
			t.Fatalf("automatic report goal was missed: %q", s)
		}
	}
	for _, s := range []string{"Write report.md during the task", "취약점 진단 보고서 파일 작성", "ARTEX_REPORT_TEST_SUCCESS 출력"} {
		if IsAutomaticReportGoal(s) {
			t.Fatalf("ordinary goal misclassified: %q", s)
		}
	}
}

func TestPostRunGoalDecompositionLocalModelPG(t *testing.T) {
	dsn, base, model := os.Getenv("ARTEX_TEST_POSTGRES_DSN"), os.Getenv("ARTEX_TEST_LLM_BASE"), os.Getenv("ARTEX_TEST_LLM_MODEL")
	if dsn == "" || base == "" || model == "" {
		t.Skip("isolated database or local model not configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("로컬 자동 보고서 시험", "로컬 명령으로 ARTEX_REPORT_TEST_SUCCESS를 한 번 출력하고 실제 결과를 기록하세요.\n작업 종료 후 자동 보고서에 수행 내용과 미실행 항목을 표시하세요.", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTaskCascade(task.ID, false, false)
	cfg := Config{Format: llm.FormatOpenAI, BaseURL: base, APIKey: "ollama", Model: model, ReasoningEffort: "low", ThinkingType: os.Getenv("ARTEX_TEST_LLM_THINKING")}
	provider, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	goals := DecomposeGoalsWithProvider(ctx, provider, t.TempDir(), task.Goal, task.Description, nil, d.Exploration(task.ExplorationID), task.ID, true, 4096, nil)
	if len(goals) == 0 {
		t.Fatal("no diagnostic goals generated")
	}
	for _, g := range goals {
		t.Logf("generated goal: %s", g.Text)
		if IsAutomaticReportGoal(g.Text) {
			t.Fatalf("automatic report used as goal: %q", g.Text)
		}
		p, _ := json.Marshal(map[string]string{"text": g.Text})
		if reportGoal(&db.Node{Payload: p}) {
			t.Fatalf("diagnostic marker classified as report file: %q", g.Text)
		}
	}
}

func TestDiagnosticGoalCompletesBeforeAutoReportPG(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("separation fixture", "로컬 명령 결과 확인", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskCascade(task.ID, false, false) })
	ts := d.Exploration(task.ExplorationID)
	decomposer := NewToolSet(ts, "goals")
	if _, err := decomposer.addOneGoal(goalItem{Text: "Generate an automated report of the command"}); err == nil {
		t.Fatal("automatic report accepted as a diagnostic goal")
	}
	goal, err := decomposer.addOneGoal(goalItem{Text: "ARTEX_REPORT_TEST_SUCCESS 출력과 결과 확인"})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.AddNode(db.KindIntent, map[string]any{"summary": "로컬 명령 실행"}, 5, "running", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("sh", "-c", "printf ARTEX_REPORT_TEST_SUCCESS").Output()
	if err != nil || string(output) != "ARTEX_REPORT_TEST_SUCCESS" {
		t.Fatalf("local fixture failed: %q %v", output, err)
	}
	for _, a := range evidencePair("Bash", `{"command":"printf ARTEX_REPORT_TEST_SUCCESS"}`, string(output)) {
		a.NodeID = &intent
		if _, err := ts.AppendActivity(a); err != nil {
			t.Fatal(err)
		}
	}
	tools := NewToolSet(ts, "planner")
	fact, err := tools.recordOneFact(factItem{Summary: "로컬 명령 출력 확인", Evidence: "printf ARTEX_REPORT_TEST_SUCCESS", Confidence: "Observed"}, intent)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tools.proveGoal().Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d}`, goal, fact)), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ts.GetNode(goal)
	if err != nil || got.State != "met" {
		t.Fatalf("goal not met: %v %v (%s)", got, err, res.Flatten())
	}
	var before int
	if err := d.QueryRow(`SELECT count(*) FROM task_auto_reports WHERE task_id=$1`, task.ID).Scan(&before); err != nil || before != 0 {
		t.Fatalf("report ran before completion: %d %v", before, err)
	}
	if err := d.SetStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := d.QueryRow(`SELECT state FROM task_auto_reports WHERE task_id=$1`, task.ID).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("report not queued after completion: %s %v", state, err)
	}
}

func TestReportGoalDoesNotMatchMarkerSubstring(t *testing.T) {
	for text, want := range map[string]bool{
		"ARTEX_REPORT_TEST_SUCCESS 출력하고 결과 기록": false,
		"취약점 진단 보고서 작성":                        true,
		"Write a report file":                  true,
	} {
		p, _ := json.Marshal(map[string]string{"text": text})
		if got := reportGoal(&db.Node{Payload: p}); got != want {
			t.Fatalf("%q: got %v want %v", text, got, want)
		}
	}
}
