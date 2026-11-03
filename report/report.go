// Package report renders a deliverable Markdown report from the exploration
// graph: confirmed findings (with severity/evidence) (docs §15 P5).
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Input bundles what the report needs.
type Input struct {
	TaskID      string
	Status      string
	Title       string
	Goal        string
	GeneratedAt time.Time
	AssetCounts map[string]int
	Findings    []*db.Node
	Facts       []*db.Node
	Intents     []*db.Node
	Goals       []*db.Node
	Activities  []db.Activity
}

type findingView struct {
	ID        int64
	State     string
	VulnClass string
	Name      string
	Severity  string
	Summary   string
	PoC       string
}

func parseFinding(n *db.Node) findingView {
	var p struct {
		VulnClass string `json:"vulnclass"`
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Summary   string `json:"summary"`
		Evidence  struct {
			PoC string `json:"poc"`
		} `json:"evidence"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return findingView{n.ID, n.State, p.VulnClass, p.Name, p.Severity, p.Summary, p.Evidence.PoC}
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

// Markdown renders the report.
func Markdown(in Input) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 침투 테스트 보고서: %s\n\n", nz(in.Title, "이름 없는 작업"))
	fmt.Fprintf(&b, "- **작업 목표**: %s\n", nz(in.Goal, "(지정되지 않음)"))
	if in.TaskID != "" {
		fmt.Fprintf(&b, "- **작업 번호**: %s\n- **작업 상태**: %s\n", in.TaskID, nz(in.Status, "미확인"))
	}
	fmt.Fprintf(&b, "- **생성 시각**: %s\n\n", in.GeneratedAt.Format("2006-01-02 15:04:05"))

	// summary
	fmt.Fprintf(&b, "## 요약\n\n")
	if in.TaskID != "" {
		fmt.Fprintf(&b, "- 등록된 취약점 기록: **%d**건 (상태·근거 검토 필요)\n", len(in.Findings))
	} else {
		fmt.Fprintf(&b, "- 확인된 취약점: **%d**건\n", len(in.Findings))
	}
	if len(in.AssetCounts) > 0 {
		fmt.Fprintf(&b, "- 자산: ")
	}
	var types []string
	for t := range in.AssetCounts {
		types = append(types, t)
	}
	sort.Strings(types)
	for i, t := range types {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s %d", t, in.AssetCounts[t])
	}
	if len(in.AssetCounts) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// findings
	fmt.Fprintf(&b, "## 취약점\n\n")
	if len(in.Findings) == 0 {
		b.WriteString("_이번에 확인된 취약점이 없습니다._\n\n")
	} else {
		fs := make([]findingView, 0, len(in.Findings))
		for _, n := range in.Findings {
			fs = append(fs, parseFinding(n))
		}
		sort.SliceStable(fs, func(i, j int) bool { return sevRank[fs[i].Severity] < sevRank[fs[j].Severity] })
		for i, f := range fs {
			fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, strings.ToUpper(nz(f.Severity, "info")), nz(f.Name, nz(f.VulnClass, "미분류")))
			if in.TaskID != "" {
				fmt.Fprintf(&b, "기록 #%d · 상태: %s\n\n", f.ID, f.State)
			}
			fmt.Fprintf(&b, "%s\n\n", nz(f.Summary, ""))
			if f.PoC != "" {
				fmt.Fprintf(&b, "**PoC / 증거:**\n\n```\n%s\n```\n\n", f.PoC)
			}
		}
	}
	if in.TaskID != "" {
		b.WriteString("## 목표와 시도 상태\n\n")
		for _, group := range []struct {
			label string
			nodes []*db.Node
		}{{"목표", in.Goals}, {"시도 계획", in.Intents}} {
			for _, n := range group.nodes {
				var p struct {
					Summary string `json:"summary"`
					Title   string `json:"title"`
				}
				if json.Unmarshal(n.Payload, &p) != nil {
					continue
				}
				fmt.Fprintf(&b, "- %s #%d (%s): %s\n", group.label, n.ID, n.State, nz(p.Summary, nz(p.Title, "내용 미확인")))
			}
		}
		b.WriteString("\n시도 계획의 상태는 공격 성공이나 취약점 입증을 뜻하지 않습니다.\n\n")
		b.WriteString("## 도구 실행 기록\n\n")
		count := 0
		for _, a := range in.Activities {
			if a.Kind != "tool_use" && a.Kind != "tool_result" {
				continue
			}
			count++
			kind := "호출"
			if a.Kind == "tool_result" {
				kind = "결과"
			}
			status := ""
			if a.IsError {
				status = " · 오류"
			}
			fmt.Fprintf(&b, "- %s · %s · %s%s (기록 #%d)\n", a.CreatedAt.Format(time.RFC3339), nz(a.Tool, "도구 미확인"), kind, status, a.ID)
			if strings.TrimSpace(a.Summary) != "" {
				fmt.Fprintf(&b, "  - 기록 요약: %s\n", strings.ReplaceAll(a.Summary, "\n", " "))
			}
		}
		if count == 0 {
			b.WriteString("도구 실행 기록이 없습니다.\n")
		}
		b.WriteString("\n도구 호출이나 정상 종료만으로 공격 성공·취약점 확인을 뜻하지 않습니다. 상세 입력과 출력은 작업 활동에서 확인하세요.\n\n")
		b.WriteString("## 기록된 관찰\n\n")
		if len(in.Facts) == 0 {
			b.WriteString("기록된 관찰이 없습니다.\n")
		}
		for _, n := range in.Facts {
			var p struct {
				Summary string `json:"summary"`
			}
			if json.Unmarshal(n.Payload, &p) != nil {
				continue
			}
			fmt.Fprintf(&b, "- 기록 #%d (%s): %s\n", n.ID, n.State, nz(p.Summary, "요약 없음"))
		}
		b.WriteString("\n## 관제 확인\n\nSnort 탐지·실제 차단·Splunk 수집은 독립 로그 대조 전까지 미확인입니다.\n\n")
		b.WriteString("이 보고서는 기록을 모아 표시한 초안입니다. 사실·취약점은 각각 최대 1,000건이며, 원문 언어는 자동 번역되지 않습니다. 내용과 민감 정보를 검토한 후 공유하세요.\n")
	}

	return b.String()
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
