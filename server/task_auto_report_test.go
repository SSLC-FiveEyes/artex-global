package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestAutoReportSourceRemovesCredentialLinesAndProofBlocks(t *testing.T) {
	in := "관찰 결과\nAuthorization: Bearer sensitive-value\npassword=other-secret\n**PoC / 증거:**\n```\nprivate-body\n```\n다음 내용\n**PoC / 증거:**\n```\nanother-body\n```"
	got := sanitizeReportSource(in)
	for _, secret := range []string{"sensitive-value", "other-secret", "private-body", "another-body"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q survived redaction: %q", secret, got)
		}
	}
	if !strings.Contains(got, "관찰 결과") || !strings.Contains(got, "다음 내용") {
		t.Fatalf("unrelated content lost: %q", got)
	}
}

func TestAutoReportRealLocalModelPG(t *testing.T) {
	dsn, base, model := os.Getenv("ARTEX_TEST_POSTGRES_DSN"), os.Getenv("ARTEX_TEST_LLM_BASE"), os.Getenv("ARTEX_TEST_LLM_MODEL")
	if dsn == "" || base == "" || model == "" {
		t.Skip("isolated database or local model not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	pt, err := pg.CreateTask("격리 보고서 검증", "실제 공격 없이 가상의 도구 기록을 한국어 보고서로 정리", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTaskCascade(pt.ID, false, false)
	key := strconv.FormatInt(pt.ID, 10)
	task := &Task{ID: key, Description: pt.Description, Goal: pt.Goal, Store: pg.Exploration(pt.ExplorationID)}
	if _, err := task.Store.AppendActivity(db.Activity{Worker: "worker", Kind: "tool_use", Tool: "WebFetch", Summary: "가상 /login 경로 정상 요청"}); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AppendActivity(db.Activity{Worker: "worker", Kind: "tool_result", Tool: "WebFetch", Summary: "가상 응답 HTTP 200"}); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AddNode(db.KindFact, map[string]any{"summary": "가상 /login 요청에 HTTP 200 응답을 관측함"}, 0, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}
	m := &Manager{pg: pg, tasks: map[string]*Task{key: task}}
	cfg := agent.Config{Format: llm.FormatOpenAI, BaseURL: base, APIKey: "ollama", Model: model, ReasoningEffort: "low", ThinkingType: os.Getenv("ARTEX_TEST_LLM_THINKING")}
	prov, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, ctx: context.Background(), llmOn: true, llmProv: prov, llmCfg: cfg}
	s.engine = NewEngine(m)
	if err := pg.SetStatus(pt.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE task_auto_reports SET created_at=now()-interval '30 seconds' WHERE task_id=$1`, pt.ID); err != nil {
		t.Fatal(err)
	}
	s.processAutoReport()
	var state, body, message string
	if err := pg.QueryRow(`SELECT state,body,error FROM task_auto_reports WHERE task_id=$1`, pt.ID).Scan(&state, &body, &message); err != nil {
		t.Fatal(err)
	}
	if state != "ready" || !strings.Contains(body, "AI 작성 보고서 초안") {
		t.Fatalf("state=%s error=%s body=%s", state, message, body)
	}
	modelSection, _, found := strings.Cut(body, "\n\n---\n\n## 작성에 사용한 작업 기록\n\n")
	if !found {
		t.Fatal("report has no source boundary")
	}
	modelText := strings.TrimPrefix(modelSection, "# AI 작성 보고서 초안 · 검토 필요")
	if !strings.ContainsFunc(modelText, func(r rune) bool { return unicode.In(r, unicode.Hangul) }) {
		t.Fatalf("Korean model output not observed: %s", modelText)
	}
	if strings.Contains(modelText, "취약점 데이터베이스 대조") || strings.Contains(modelText, "취약점 DB 대조") {
		t.Fatal("model invented a database check")
	}
	if !strings.Contains(body, "HTTP 200") || !strings.Contains(body, "WebFetch") {
		t.Fatal("source evidence not retained")
	}
	t.Logf("synthetic model report:\n%s", modelText)
	t.Logf("local model report saved, %d characters", len([]rune(body)))
}

func TestAutoReportWorkerPG(t *testing.T) {
	dsn := os.Getenv("ARTEX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated test PostgreSQL not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	pt, err := pg.CreateTask("격리 시험", "보고서 확인", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ARTEX_TEST_KEEP_REPORT") == "" {
		defer pg.DeleteTaskCascade(pt.ID, false, false)
	} else {
		t.Logf("fixture task id: %d", pt.ID)
	}
	key := strconv.FormatInt(pt.ID, 10)
	task := &Task{ID: key, Description: pt.Description, Goal: pt.Goal, Store: pg.Exploration(pt.ExplorationID)}
	m := &Manager{pg: pg, tasks: map[string]*Task{key: task}}
	s := &Server{m: m, ctx: context.Background(), llmOn: true}
	s.engine = NewEngine(m)
	var fail bool
	s.llmProv = retestProvider{complete: func(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		if len(req.Tools) != 0 {
			t.Fatal("report generation must not receive tools")
		}
		if fail {
			return llm.Message{}, "", llm.Usage{}, errors.New("fixture error")
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("## 진단 결과\n격리 시험 결과입니다.")}}, "", llm.Usage{}, nil
	}}
	if err := pg.SetStatus(pt.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE task_auto_reports SET created_at=now()-interval '30 seconds' WHERE task_id=$1`, pt.ID); err != nil {
		t.Fatal(err)
	}
	s.processAutoReport()
	var state, body string
	if err := pg.QueryRow(`SELECT state,body FROM task_auto_reports WHERE task_id=$1`, pt.ID).Scan(&state, &body); err != nil || state != "ready" || !strings.Contains(body, "격리 시험 결과") {
		t.Fatalf("state=%s body=%q err=%v", state, body, err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.SetPathValue("id", key)
	s.getAutoReport(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "격리 시험 결과") {
		t.Fatalf("API status=%d body=%s", w.Code, w.Body.String())
	}
	if err := pg.SetStatus(pt.ID, "running"); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetStatus(pt.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE task_auto_reports SET created_at=now()-interval '30 seconds' WHERE task_id=$1 AND state='pending'`, pt.ID); err != nil {
		t.Fatal(err)
	}
	var beforeActivities int
	if err := pg.QueryRow(`SELECT count(*) FROM activity WHERE exploration_id=$1 AND tool='Bash' AND kind='tool_use'`, pt.ExplorationID).Scan(&beforeActivities); err != nil {
		t.Fatal(err)
	}
	fail = true
	s.processAutoReport()
	if err := pg.QueryRow(`SELECT state,body FROM task_auto_reports WHERE task_id=$1 ORDER BY id DESC LIMIT 1`, pt.ID).Scan(&state, &body); err != nil || state != "failed" {
		t.Fatalf("state=%s err=%v", state, err)
	}
	// Simulate an older rejected draft left in storage: no non-ready response
	// may expose it, including while a user requests a retry.
	if _, err := pg.Exec(`UPDATE task_auto_reports SET body='REJECTED_DRAFT' WHERE task_id=$1 AND state='failed'`, pt.ID); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/", nil)
	req.SetPathValue("id", key)
	s.retryAutoReport(w, req)
	if w.Code != 200 {
		t.Fatalf("retry status %d", w.Code)
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/", nil)
	req.SetPathValue("id", key)
	s.getAutoReport(w, req)
	if w.Code != 200 || strings.Contains(w.Body.String(), "REJECTED_DRAFT") {
		t.Fatalf("pending report exposed rejected text: status=%d body=%s", w.Code, w.Body.String())
	}
	fail = false
	s.processAutoReport()
	if err := pg.QueryRow(`SELECT state,body FROM task_auto_reports WHERE task_id=$1 ORDER BY id DESC LIMIT 1`, pt.ID).Scan(&state, &body); err != nil || state != "ready" {
		t.Fatalf("retried state=%s err=%v", state, err)
	}
	var afterActivities int
	var taskStatus string
	if err := pg.QueryRow(`SELECT count(*) FROM activity WHERE exploration_id=$1 AND tool='Bash' AND kind='tool_use'`, pt.ExplorationID).Scan(&afterActivities); err != nil {
		t.Fatal(err)
	}
	if err := pg.QueryRow(`SELECT status FROM tasks WHERE id=$1`, pt.ID).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "timeout" || afterActivities != beforeActivities {
		t.Fatalf("report retry changed diagnosis: status=%s, Bash calls %d -> %d", taskStatus, beforeActivities, afterActivities)
	}
}

// This must use an explicitly isolated test database, never the configured app DB.
func TestAutoReportQueueTerminalEpisodesPG(t *testing.T) {
	dsn := os.Getenv("ARTEX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated test PostgreSQL not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("auto report test", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTaskCascade(task.ID, false, false)
	if err := pg.SetStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pg.QueryRow(`SELECT count(*) FROM task_auto_reports WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate terminal: count=%d err=%v", count, err)
	}
	if err := pg.SetStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetStatus(task.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	if err := pg.QueryRow(`SELECT count(*) FROM task_auto_reports WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("new episode: count=%d err=%v", count, err)
	}
}

func TestAutoReportSourceCapsInput(t *testing.T) {
	got := sanitizeReportSource(strings.Repeat("가", 31000))
	if !strings.Contains(got, "자료 길이 제한") {
		t.Fatal("truncation must be disclosed")
	}
}

func TestAutoReportRejectsUnsupportedAbsence(t *testing.T) {
	if validateAutoReportNarrative("  ", "") == nil {
		t.Fatal("empty AI report was accepted")
	}
	if validateAutoReportNarrative("모든 작업은 기록에 따라 안전하게 수행되었다.", "") == nil {
		t.Fatal("unsupported safety claim was accepted")
	}
	for _, text := range []string{"| 취약점 | 없음 |", "공격 성공: 없음", "취약점이 없다"} {
		if validateAutoReportNarrative(text, "") == nil {
			t.Fatalf("unsafe claim accepted: %q", text)
		}
	}
	if err := validateAutoReportNarrative("확인된 취약점 기록 0건. 범위 밖은 미확인.", ""); err != nil {
		t.Fatal(err)
	}
	if validateAutoReportNarrative("HTTP 800", "HTTP 200") == nil {
		t.Fatal("unsupported HTTP status accepted")
	}
	if err := validateAutoReportNarrative("HTTP 200", "가상 HTTP 200"); err != nil {
		t.Fatal(err)
	}
	if validateAutoReportNarrative("Snort/Jupyter 침입 탐지", "Snort") == nil {
		t.Fatal("unrecorded system accepted")
	}
}
