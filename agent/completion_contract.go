package agent

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

var errCompletionSatisfied = errors.New("completion contract satisfied")
var errCompletionIncomplete = errors.New("completion contract incomplete")

func completionSatisfied(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errCompletionSatisfied)
}

const completionSummary = "필요한 실제 저장·상태 전환을 확인해 실행을 정상 종료했습니다."

// completionContractHooks repairs a missing persistence/state transition. It
// never manufactures evidence or marks a goal itself. Recovery can only use
// graph tools; execution tools stay blocked while the model records old results.
type completionContractHooks struct {
	inner              harness.HookRunner
	needsRepair        func() bool
	success            func() bool
	cancel             context.CancelFunc
	abort              context.CancelFunc
	repair             atomic.Bool
	attempts           atomic.Int32
	blocked            atomic.Int32
	waitForObservation bool
	observed           atomic.Bool
}

func (h *completionContractHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if h.repair.Load() && (!h.waitForObservation || h.observed.Load()) {
		switch name {
		case "record_fact", "report_finding", "prove_goal", "list_facts", "list_goals", "node_detail", "graph_overview":
		default:
			if h.blocked.Add(1) > 2 && h.abort != nil {
				h.abort()
			}
			return true, "결과 저장·종결 복구 단계입니다. 새 명령·요청·의도 생성은 금지됩니다. 이미 관측한 근거만 기록하거나 확인하세요.", nil
		}
	}
	var block bool
	var message string
	var modified []byte
	if h.inner != nil {
		block, message, modified = h.inner.PreToolUse(ctx, name, input)
	}
	if block && h.repair.Load() && h.blocked.Add(1) > 2 && h.abort != nil {
		h.abort()
	}
	if !block && h.waitForObservation {
		switch name {
		case "Bash", "WebFetch", "Read", "Write", "write", "WRITE", "shell_open", "shell_send", "web_search":
			h.observed.Store(true)

		}
	}
	return block, message, modified
}

func (h *completionContractHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
	if !isErr && h.success != nil && h.success() && h.cancel != nil {
		h.cancel()
	}
}

func (h *completionContractHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	var blocking []string
	var msg string
	if h.inner != nil {
		var prevent bool
		prevent, blocking, msg = h.inner.Stop(ctx, messages)
		if prevent {
			return prevent, blocking, msg
		}
	}
	if ctx.Err() != nil || h.needsRepair == nil || !h.needsRepair() || h.attempts.Add(1) > 2 {
		return false, blocking, msg
	}
	h.repair.Store(true)
	if h.waitForObservation && !h.observed.Load() {
		return false, append(blocking, "아직 승인된 최초 실행의 관측이 없습니다. 예고 문장으로 끝내지 말고 의도에 적힌 최초 실행만 실제 호출하세요. 범위·횟수 제한을 지키고, 결과를 얻은 뒤 실제 저장을 하세요. 실행한 척하거나 다른 명령으로 대체하지 마세요."), msg
	}
	return false, append(blocking, "실제 저장 또는 목표 상태 전환이 아직 없습니다. 예고 문장/JSON 예시는 도구 호출이 아닙니다. 이미 관측한 결과만 record_fact로 저장하고 실제 근거가 목표를 충족할 때만 prove_goal을 호출하세요. 관측하지 않은 결과를 만들지 마세요. 실행하지 못했다면 미실행 사실만 기록하세요. 새 명령·웹 요청·재시도·의도 생성은 금지됩니다. 실제 성공 응답을 확인한 뒤 종료하세요."), msg
}
