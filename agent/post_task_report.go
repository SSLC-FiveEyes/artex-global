package agent

import "strings"

// Post-task automatic reporting is a lifecycle action, not an agent goal. This
// deliberately recognises explicit automation wording only; manually requested
// reports still need their own verified Write evidence.
func IsAutomaticReportGoal(text string) bool {
	s := strings.ToLower(text)
	korean := strings.Contains(s, "보고서") && (strings.Contains(s, "자동") || strings.Contains(s, "종료 후") || strings.Contains(s, "완료 후"))
	english := strings.Contains(s, "report") && (strings.Contains(s, "automated") || strings.Contains(s, "automatic") || strings.Contains(s, "automatically"))
	chinese := strings.Contains(s, "报告") && (strings.Contains(s, "自动") || strings.Contains(s, "结束后"))
	return korean || english || chinese
}

// DiagnosticGoalText removes explicit post-run reporting instructions from
// fallback goal text without inventing a diagnostic goal or touching other lines.
func DiagnosticGoalText(text string) string {
	var kept []string
	for _, line := range strings.Split(text, "\n") {
		if !IsAutomaticReportGoal(line) {
			kept = append(kept, line)
			continue
		}
		// Preserve text preceding an explicit post-run clause on the same line.
		lower := strings.ToLower(line)
		cut := -1
		for _, marker := range []string{"작업 종료 후", "작업 완료 후", "after the task", "after task", "after completion"} {
			if i := strings.Index(lower, marker); i >= 0 && (cut < 0 || i < cut) {
				cut = i
			}
		}
		// Only strip an unambiguous, final reporting clause. A mixed line
		// without a post-run marker, or a clause followed by more instructions,
		// must survive unchanged rather than silently losing diagnostic work.
		if cut < 0 {
			kept = append(kept, line)
			continue
		}
		clause := strings.TrimSpace(line[cut:])
		// Natural-language conjunctions are too varied to safely split by a
		// blacklist. Only remove phrases known to contain no other action.
		plain := strings.TrimRight(strings.ToLower(clause), ".!?。！？ ")
		switch plain {
		case "작업 종료 후 자동 보고서를 생성하세요", "작업 완료 후 자동 보고서를 생성하세요",
			"작업 종료 후 자동 보고서 작성", "작업 완료 후 자동 보고서 작성",
			"작업 종료 후 자동 보고서에는 결과와 미실행 항목을 표시하세요",
			"작업 종료 후 자동 보고서에 수행 내용과 결과, 미실행 항목을 표시하세요":
		default:
			kept = append(kept, line)
			continue
		}
		if cut > 0 {
			kept = append(kept, strings.TrimSpace(line[:cut]))
		}
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}
