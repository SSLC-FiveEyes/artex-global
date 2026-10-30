package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
- record_fact는 메모 저장입니다. 그 성공만으로 진단이나 보고서 생성이 증명되지 않습니다. prove_goal 전에 get_worker_trace로 해당 근거를 만든 실제 도구 결과를 확인하세요.
- 보고서 목표는 Write로 현재 의도의 작업 폴더에 비어 있지 않은 Markdown 파일을 실제 저장한 뒤, 같은 intent_id의 record_fact에 경로를 기록하세요. echo로 완료 문구만 출력하거나 사실 노드만 등록하는 것은 보고서 저장이 아닙니다.
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
func isExecutionTool(name string) bool {
	switch strings.ToLower(name) {
	case "bash", "webfetch", "web_fetch", "read", "write", "edit", "shell_send":
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
		strings.Contains(s, "[exit code ") || strings.Contains(s, "command not found") {
		return false
	}
	var status map[string]json.RawMessage
	if json.Unmarshal([]byte(a.Detail), &status) == nil {
		if string(status["ok"]) == "false" || string(status["success"]) == "false" {
			return false
		}
		if e := string(status["error"]); e != "" && e != "null" && e != `""` && e != "false" {
			return false
		}
	}
	return true
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
		if ok && successfulEvidenceResult(a) {
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

func reportGoal(node *db.Node) bool {
	var p struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(node.Payload, &p)
	s := strings.ToLower(p.Text)
	return strings.Contains(s, "보고서") || strings.Contains(s, "report") || strings.Contains(s, "报告")
}

func (t *ToolSet) checkGoalEvidence(goal, node *db.Node) error {
	if node.Inherited || node.State != "confirmed" {
		return fmt.Errorf("완료 근거는 현재 작업에서 실행·확인한 confirmed 사실/발견이어야 합니다. 이전 작업 결과는 현재 범위에서 재확인하세요")
	}
	var p struct {
		Confidence string `json:"confidence"`
	}
	_ = json.Unmarshal(node.Payload, &p)
	if node.Kind == db.KindFact && p.Confidence != "observed" {
		return fmt.Errorf("추정 또는 신뢰도 미표시 사실은 완료 증명이 아닙니다. 실제 관측 근거를 기록하세요")
	}
	command := claimedCommand(node.Payload)
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
		if !reportGoal(goal) {
			return nil
		}
		if verifiedReportWrite(t.taskDir, edge.From, calls) {
			return nil
		}
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
	uses := map[string]bool{}
	for _, a := range records {
		if a.Kind != "tool_use" || a.ToolUseID == "" || (a.Tool != "Bash" && a.Tool != "bash") {
			continue
		}
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal([]byte(a.Detail), &in) == nil && strings.TrimSpace(in.Command) == command {
			uses[a.ToolUseID] = true
		}
	}
	for _, a := range records {
		if a.Kind != "tool_result" || a.IsError || !uses[a.ToolUseID] {
			continue
		}
		s := strings.ToLower(a.Detail)
		if strings.Contains(s, "command not found") || strings.Contains(s, "[exit code ") || strings.HasPrefix(s, "blocked by hook:") || strings.HasPrefix(s, "error:") {
			continue
		}
		return true
	}
	return false
}
