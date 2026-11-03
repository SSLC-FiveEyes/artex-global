package agent

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func scenarioPolicyFixtureTool(name string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name,
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("fixture"), nil
		},
	})
}

func scenarioPolicyToolNames(in []actool.CoreTool) []string {
	out := make([]string, 0, len(in))
	for _, tool := range in {
		out = append(out, tool.Name())
	}
	return out
}

func TestScenarioToolPolicyExactCaseInsensitiveAllowlist(t *testing.T) {
	policy := ScenarioToolPolicy{
		Enforced:     true,
		AllowedTools: []string{"Read", "WebFetch", "mcp__lab__observe"},
	}
	tools := []actool.CoreTool{
		scenarioPolicyFixtureTool("Bash"),
		scenarioPolicyFixtureTool("READ"),
		scenarioPolicyFixtureTool("WebFetch"),
		scenarioPolicyFixtureTool("web_fetch"),
		scenarioPolicyFixtureTool("mcp__lab__observe"),
	}
	if got, want := scenarioPolicyToolNames(policy.FilterTools(tools)), []string{"READ", "WebFetch", "mcp__lab__observe"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered tools = %v, want %v", got, want)
	}
	if policy.AllowsTool("bash") || policy.AllowsTool("web_fetch") {
		t.Fatal("similarly named aliases must not pass an exact allowlist")
	}
	if !policy.AllowsTool("read") || !policy.AllowsWebFetch() || policy.AllowsWebSearch() {
		t.Fatalf("unexpected policy decisions: read=%v webfetch=%v websearch=%v", policy.AllowsTool("read"), policy.AllowsWebFetch(), policy.AllowsWebSearch())
	}

	deferred := policy.FilterDeferred(DeferredInfo{
		Deferred:    []string{"WEBFETCH", "web_fetch", "mcp__lab__observe", "mcp__blocked__run"},
		GlobalNames: []string{"web_fetch", "MCP__LAB__OBSERVE"},
	})
	if got, want := deferred.Deferred, []string{"WEBFETCH", "mcp__lab__observe"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered deferred = %v, want %v", got, want)
	}
	if got, want := deferred.GlobalNames, []string{"MCP__LAB__OBSERVE"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered deferred globals = %v, want %v", got, want)
	}
}

func TestScenarioToolPolicyZeroValuePreservesLegacySurface(t *testing.T) {
	tools := []actool.CoreTool{scenarioPolicyFixtureTool("Bash"), scenarioPolicyFixtureTool("WebFetch")}
	policy := ScenarioToolPolicy{}
	if got := policy.FilterTools(tools); len(got) != len(tools) || got[0] != tools[0] || got[1] != tools[1] {
		t.Fatalf("zero policy unexpectedly changed tools: %v", scenarioPolicyToolNames(got))
	}
	if !policy.AllowsTool("anything") || !policy.AllowsWebFetch() || !policy.AllowsWebSearch() {
		t.Fatal("zero policy must preserve the existing unrestricted behavior")
	}
}

func TestResolveScenarioToolPolicyAndRunInfoAttribution(t *testing.T) {
	old := ScenarioToolPolicyResolver
	t.Cleanup(func() { ScenarioToolPolicyResolver = old })
	ScenarioToolPolicyResolver = func(taskID int64) ScenarioToolPolicy {
		if taskID != 42 {
			t.Fatalf("resolver task id = %d, want 42", taskID)
		}
		return ScenarioToolPolicy{
			Enforced: true, ScenarioID: "recon", ProfileState: "armed", ProfileFingerprint: "abc123",
			AllowedTools: []string{"Read"},
		}
	}
	policy := ResolveScenarioToolPolicy(42)
	if !policy.Enforced || policy.ScenarioID != "recon" || policy.ProfileState != "armed" || policy.ProfileFingerprint != "abc123" {
		t.Fatalf("resolver policy = %+v", policy)
	}
	info := WithRunInfo(context.Background(), RunInfo{
		TaskID: 42, ScenarioID: policy.ScenarioID, ScenarioProfileState: policy.ProfileState,
		ScenarioProfileSHA256: policy.ProfileFingerprint,
	})
	got := RunInfoFrom(info)
	if got.ScenarioID != "recon" || got.ScenarioProfileState != "armed" || got.ScenarioProfileSHA256 != "abc123" {
		t.Fatalf("scenario run attribution missing: %+v", got)
	}
}

func TestScenarioToolPolicyPromptDoesNotPretendToBeTheEnforcement(t *testing.T) {
	draft := ScenarioToolPolicy{Enforced: true, ScenarioID: "recon", ProfileState: "draft"}.PromptBlock()
	if !strings.Contains(draft, "armed 상태가 아니") || !strings.Contains(draft, "실행을 시도하지") {
		t.Fatalf("draft prompt must instruct a stop: %q", draft)
	}
	armed := ScenarioToolPolicy{Enforced: true, ScenarioID: "recon", ProfileState: "armed", AllowedTools: []string{"Read", "fiveeyes_nmap_scan"}}.PromptBlock()
	for _, want := range []string{"fiveeyes_nmap_scan", "서로 다른 사실", "독립 서버 증거"} {
		if !strings.Contains(armed, want) {
			t.Fatalf("armed prompt missing %q: %q", want, armed)
		}
	}
	if got := (ScenarioToolPolicy{}).PromptBlock(); got != "" {
		t.Fatalf("legacy policy must not alter prompt: %q", got)
	}
}

func TestScenarioActivityMetadataCarriesProfileProvenanceOnlyWhenPresent(t *testing.T) {
	if got := scenarioActivityMetadata(context.Background()); got != nil {
		t.Fatalf("ordinary run unexpectedly received scenario metadata: %s", got)
	}
	ctx := WithRunInfo(context.Background(), RunInfo{
		ScenarioID: "fiveeyes_recon", ScenarioProfileState: "armed", ScenarioProfileSHA256: "abc123",
	})
	raw := scenarioActivityMetadata(ctx)
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["scenario_id"] != "fiveeyes_recon" || got["scenario_profile_state"] != "armed" || got["scenario_profile_sha256"] != "abc123" {
		t.Fatalf("missing scenario activity provenance: %v", got)
	}
}
