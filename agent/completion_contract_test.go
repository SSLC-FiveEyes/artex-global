package agent

import (
	"context"
	"github.com/Autumn-27/norma/llm"
	"testing"
)

func TestCompletionRepairBlocksNewExecution(t *testing.T) {
	h := &completionContractHooks{needsRepair: func() bool { return true }}
	_, messages, _ := h.Stop(context.Background(), []llm.Message{{Role: llm.RoleAssistant}})
	if len(messages) == 0 {
		t.Fatal("missing repair instruction")
	}
	for _, name := range []string{"Bash", "WebFetch", "Write", "add_intent"} {
		blocked, _, _ := h.PreToolUse(context.Background(), name, nil)
		if !blocked {
			t.Fatalf("new action %s allowed", name)
		}
	}
	blocked, _, _ := h.PreToolUse(context.Background(), "record_fact", nil)
	if blocked {
		t.Fatal("persistence blocked")
	}
}
func TestCompletionRepairIsBounded(t *testing.T) {
	h := &completionContractHooks{needsRepair: func() bool { return true }}
	for i := 0; i < 2; i++ {
		_, m, _ := h.Stop(context.Background(), nil)
		if len(m) == 0 {
			t.Fatal("early stop")
		}
	}
	_, m, _ := h.Stop(context.Background(), nil)
	if len(m) > 0 {
		t.Fatal("unbounded retry")
	}
}

func TestCompletionCancellationRequiresSuccessfulTransition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := false
	h := &completionContractHooks{success: func() bool { return done }, cancel: cancel}
	h.PostToolUse(ctx, "prove_goal", nil, nil, false)
	if ctx.Err() != nil {
		t.Fatal("cancelled without proof")
	}
	done = true
	h.PostToolUse(ctx, "prove_goal", nil, nil, true)
	if ctx.Err() != nil {
		t.Fatal("cancelled failed tool")
	}
	h.PostToolUse(ctx, "prove_goal", nil, nil, false)
	if ctx.Err() == nil {
		t.Fatal("did not end after successful proof")
	}
}
func TestCompletionMissingWritesIsNotSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &completionContractHooks{needsRepair: func() bool { return true }, abort: cancel}
	h.Stop(ctx, nil)
	for i := 0; i < 3; i++ {
		h.PreToolUse(ctx, "Bash", nil)
	}
	if ctx.Err() == nil {
		t.Fatal("repeated blocked execution did not stop")
	}
}

func TestCompletionAllowsFirstAuthorizedExecutionBeforeWriteRepair(t *testing.T) {
	h := &completionContractHooks{waitForObservation: true, needsRepair: func() bool { return true }}
	_, m, _ := h.Stop(context.Background(), nil)
	if len(m) == 0 {
		t.Fatal("missing initial-action nudge")
	}
	b, _, _ := h.PreToolUse(context.Background(), "Bash", nil)
	if b {
		t.Fatal("first authorized execution blocked")
	}
	b, _, _ = h.PreToolUse(context.Background(), "Bash", nil)
	if !b {
		t.Fatal("repeat execution allowed during persistence repair")
	}
	b, _, _ = h.PreToolUse(context.Background(), "record_fact", nil)
	if b {
		t.Fatal("writeback blocked after observation")
	}
}
