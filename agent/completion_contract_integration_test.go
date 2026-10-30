package agent

import (
	"context"
	"encoding/json"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"testing"
)

func TestCompletionSessionRepairsPromiseWithoutExecutingAgain(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls, executions := 0, 0
	persisted := false
	h := &completionContractHooks{needsRepair: func() bool { return !persisted }, success: func() bool { return persisted }, cancel: cancel}
	provider := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
		calls++
		if calls == 1 {
			if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: "결과를 기록하겠습니다."}, nil) {
				return
			}
		} else {
			name := "Bash"
			if calls > 2 {
				name = "record_fact"
			}
			if !y(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: "fixture", ToolName: name}, nil) {
				return
			}
			if !y(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: "{}"}, nil) {
				return
			}
		}
		stop := "tool_use"
		if calls == 1 {
			stop = "end_turn"
		}
		if !y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			return
		}
		y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}}
	makeTool := func(name string, run func()) tool.CoreTool {
		return tool.Build(tool.Spec{Name: name, Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
			run()
			return tool.Text("ok"), nil
		}})
	}
	_, _, _ = captureRun(ctx, agentcore.Options{Provider: provider, Hooks: h, Tools: []tool.CoreTool{makeTool("Bash", func() { executions++ }), makeTool("record_fact", func() { persisted = true })}, PermissionMode: permission.ModeBypass, MaxTurns: 6, WorkingDir: t.TempDir()}, "fixture: persist existing observation", nil)
	if !persisted || executions != 0 || calls != 3 {
		t.Fatalf("persisted=%v new executions=%d calls=%d", persisted, executions, calls)
	}
}

func TestCompletionSessionStopsAfterProofWithoutAnotherModelCall(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	proven := false
	calls := 0
	h := &completionContractHooks{success: func() bool { return proven }, cancel: func() { cancel(errCompletionSatisfied) }}
	provider := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
		calls++
		if !y(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: "proof", ToolName: "prove_goal"}, nil) {
			return
		}
		if !y(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: "{}"}, nil) {
			return
		}
		if !y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "tool_use"}, nil) {
			return
		}
		y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}}
	proof := tool.Build(tool.Spec{Name: "prove_goal", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
		proven = true
		return tool.Text("goal marked met"), nil
	}})
	_, _, runErr := captureRun(ctx, agentcore.Options{Provider: provider, Hooks: h, Tools: []tool.CoreTool{proof}, PermissionMode: permission.ModeBypass, MaxTurns: 4, WorkingDir: t.TempDir()}, "fixture proof", nil)
	if runErr != nil {
		t.Fatalf("successful proof was reported as cancellation: %v", runErr)
	}
	if !proven || calls != 1 {
		t.Fatalf("proof=%v model calls=%d", proven, calls)
	}
}

func TestCompletionSessionStartsFirstExecutionAfterPromise(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls, executions := 0, 0
	persisted := false
	h := &completionContractHooks{waitForObservation: true, needsRepair: func() bool { return !persisted }, success: func() bool { return persisted }, cancel: cancel}
	provider := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
		calls++
		if calls == 1 || calls == 3 {
			if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: "결과를 기록하겠습니다."}, nil) {
				return
			}
		} else {
			name := "Bash"
			if calls > 2 {
				name = "record_fact"
			}
			if !y(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: "fixture", ToolName: name}, nil) {
				return
			}
			if !y(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: "{}"}, nil) {
				return
			}
		}
		stop := "tool_use"
		if calls == 1 || calls == 3 {
			stop = "end_turn"
		}
		if !y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			return
		}
		y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}}
	makeTool := func(name string, run func()) tool.CoreTool {
		return tool.Build(tool.Spec{Name: name, Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
			run()
			return tool.Text("ok"), nil
		}})
	}
	_, _, _ = captureRun(ctx, agentcore.Options{Provider: provider, Hooks: h, Tools: []tool.CoreTool{makeTool("Bash", func() { executions++ }), makeTool("record_fact", func() { persisted = true })}, PermissionMode: permission.ModeBypass, MaxTurns: 6, WorkingDir: t.TempDir()}, "fixture: persist existing observation", nil)
	if !persisted || executions != 1 || calls != 4 {
		t.Fatalf("persisted=%v new executions=%d calls=%d", persisted, executions, calls)
	}
}
