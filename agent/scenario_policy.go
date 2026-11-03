package agent

import (
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// ScenarioToolPolicy is the task-scoped tool boundary used by controlled
// exercises. It intentionally says nothing about whether a target-side action
// succeeded: it only controls which ARTEX tools may be offered to a task agent.
//
// An unenforced (zero-value) policy preserves the legacy tool surface. An
// enforced policy is deny-by-default and permits only exact tool names, compared
// case-insensitively. For example, allowing WebFetch does not implicitly allow
// the separate alias web_fetch or an arbitrary similarly named custom tool.
type ScenarioToolPolicy struct {
	Enforced           bool
	ScenarioID         string
	ProfileState       string
	ProfileFingerprint string
	AllowedTools       []string
}

// ScenarioToolPolicyResolver is wired by the host when it has a persisted
// scenario profile for a task. Leaving it nil keeps existing ARTEX behavior.
// It is read for every task-agent run so an explicit profile change applies to
// the next planner/worker/main-agent turn without rebuilding the agent objects.
var ScenarioToolPolicyResolver func(taskID int64) ScenarioToolPolicy

// ResolveScenarioToolPolicy returns an unenforced policy when no host resolver
// is configured. A resolver returning an enforced policy with no tools is a
// deliberate full stop, not a fallback to unrestricted execution.
func ResolveScenarioToolPolicy(taskID int64) ScenarioToolPolicy {
	if ScenarioToolPolicyResolver == nil || taskID <= 0 {
		return ScenarioToolPolicy{}
	}
	return ScenarioToolPolicyResolver(taskID)
}

// AllowsTool applies the exact, case-insensitive allowlist. Empty and
// whitespace-only names are never accepted by an enforced policy.
func (p ScenarioToolPolicy) AllowsTool(name string) bool {
	if !p.Enforced {
		return true
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, allowed := range p.AllowedTools {
		if strings.EqualFold(name, strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

// FilterTools keeps the original order and never mutates the caller's slice.
func (p ScenarioToolPolicy) FilterTools(in []actool.CoreTool) []actool.CoreTool {
	if !p.Enforced {
		return in
	}
	out := make([]actool.CoreTool, 0, len(in))
	for _, tool := range in {
		if tool != nil && p.AllowsTool(tool.Name()) {
			out = append(out, tool)
		}
	}
	return out
}

// FilterDeferred removes names the policy does not permit from both model-facing
// deferred lists. Unlock remains untouched: it may still contain a historical
// name, but that name is neither exposed to the model nor present in Tools after
// FilterTools, so it cannot recreate a removed callable tool.
func (p ScenarioToolPolicy) FilterDeferred(in DeferredInfo) DeferredInfo {
	if !p.Enforced {
		return in
	}
	out := in
	out.Deferred = p.filterNames(in.Deferred)
	out.GlobalNames = p.filterNames(in.GlobalNames)
	return out
}

func (p ScenarioToolPolicy) filterNames(in []string) []string {
	out := make([]string, 0, len(in))
	for _, name := range in {
		if p.AllowsTool(name) {
			out = append(out, name)
		}
	}
	return out
}

// AllowsWebFetch controls agentcore's separately configured WebFetch surface.
// It must be enabled explicitly in an enforced scenario profile even when the
// normal agent default is true.
func (p ScenarioToolPolicy) AllowsWebFetch() bool {
	return p.AllowsTool("WebFetch")
}

// AllowsWebSearch similarly keeps external search off in an enforced profile
// unless WebSearch is an explicit allowlist entry. The project currently has
// global web search disabled, but this closes the boundary if that setting later
// changes.
func (p ScenarioToolPolicy) AllowsWebSearch() bool {
	return p.AllowsTool("WebSearch")
}

// PromptBlock makes the active boundary visible to the model. It is guidance,
// not the security control; FilterTools and the disabled WebFetch/Search paths
// enforce the boundary independently.
func (p ScenarioToolPolicy) PromptBlock() string {
	if !p.Enforced {
		return ""
	}
	profile := p.ScenarioID
	if profile == "" {
		profile = "unknown"
	}
	if p.ProfileState != "armed" {
		return fmt.Sprintf("\n\n[시나리오 실행 프로필]\n프로필 %q의 상태는 %q입니다. 아직 armed 상태가 아니므로 대상 요청·스캔·명령 실행을 시도하지 마세요. 계획·기록이 필요하면 사람의 명시적 승인과 armed 프로필을 기다리세요.\n", profile, p.ProfileState)
	}
	allowed := append([]string(nil), p.AllowedTools...)
	return fmt.Sprintf("\n\n[시나리오 실행 프로필]\n현재 프로필: %q (armed). 아래 도구만 실제 실행 후보이며, 그 외 대상 요청·스캔·명령·웹 검색은 금지됩니다: %s\n- 도구 실행됨, 취약점 확인됨, 관제 탐지됨을 서로 다른 사실로 기록하세요.\n- 실행 실패·timeout·not_run은 성공으로 바꾸어 표현하지 마세요.\n- 도구가 허용돼도 입력 범위·중지 조건·독립 서버 증거가 부족하면 실행하지 말고 부족한 정보를 기록하세요.\n", profile, strings.Join(allowed, ", "))
}
