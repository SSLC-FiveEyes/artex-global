package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestCustomToolReceiptCapturesServerOutcomeAndFingerprints(t *testing.T) {
	definition := &db.Tool{
		Key:         "fiveeyes_fixture",
		Description: "offline fixture",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Agents:      []string{"worker"},
		Enabled:     true,
		Kind:        "script",
		Exec:        json.RawMessage(`{"code":"print('fixture')","timeout_ms":1000}`),
	}
	params := map[string]any{"run_id": "unit-receipt-01", "target": "198.51.100.10"}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{
		TaskID: 42, ScenarioID: "fiveeyes_recon", ScenarioProfileState: "armed", ScenarioProfileSHA256: "profile-fingerprint",
	})
	result, err := executeCustomToolWithReceipt(ctx, definition, params, nil, func() (actool.Result, error) {
		return actool.Text(`{"script_claim":"success"}`), nil
	})
	if err != nil || result.IsError {
		t.Fatalf("receipt wrapper unexpectedly failed: result=%+v err=%v", result, err)
	}
	var envelope customToolReceiptEnvelope
	if err := json.Unmarshal([]byte(result.Flatten()), &envelope); err != nil {
		t.Fatalf("receipt is not JSON: %v; body=%q", err, result.Flatten())
	}
	if envelope.Receipt.Version != customToolReceiptVersion || envelope.Receipt.ReceiptID == "" {
		t.Fatalf("missing receipt identity: %+v", envelope.Receipt)
	}
	if envelope.Receipt.RunID != "unit-receipt-01" || envelope.Receipt.Tool.Key != definition.Key || envelope.Receipt.Tool.Kind != "script" {
		t.Fatalf("wrong receipt attribution: %+v", envelope.Receipt)
	}
	if envelope.Receipt.Runner.Outcome != "completed" || envelope.Receipt.Runner.ResultIsError {
		t.Fatalf("script text must not override completed runner state: %+v", envelope.Receipt.Runner)
	}
	if envelope.Receipt.Scenario.ID != "fiveeyes_recon" || envelope.Receipt.Scenario.ProfileState != "armed" || envelope.Receipt.Scenario.ProfileSHA256 != "profile-fingerprint" {
		t.Fatalf("receipt lost scenario profile attribution: %+v", envelope.Receipt.Scenario)
	}
	if envelope.Receipt.InputSHA256 != customToolValueSHA256(params) || envelope.Receipt.OutputSHA256 != sha256Hex([]byte(envelope.Output)) {
		t.Fatalf("receipt hashes do not bind input/output: %+v", envelope.Receipt)
	}
	if envelope.Receipt.Tool.DefinitionSHA256 != customToolDefinitionSHA256(definition) {
		t.Fatalf("receipt does not bind the executed definition: %+v", envelope.Receipt.Tool)
	}

	changed := *definition
	changed.Exec = json.RawMessage(`{"code":"print('changed')","timeout_ms":1000}`)
	if customToolDefinitionSHA256(&changed) == envelope.Receipt.Tool.DefinitionSHA256 {
		t.Fatal("definition fingerprint did not change when executable code changed")
	}
}

func TestCustomToolReceiptMarksRunnerFailureAndTimeout(t *testing.T) {
	definition := &db.Tool{Key: "fiveeyes_fixture", Kind: "script", Exec: json.RawMessage(`{"code":"pass"}`)}
	failed := actool.Text("script printed a success-looking message")
	failed.IsError = true
	result, err := executeCustomToolWithReceipt(context.Background(), definition, map[string]any{}, nil, func() (actool.Result, error) {
		return failed, nil
	})
	if err != nil || !result.IsError {
		t.Fatalf("failed runner must stay errored: result=%+v err=%v", result, err)
	}
	var failedEnvelope customToolReceiptEnvelope
	if err := json.Unmarshal([]byte(result.Flatten()), &failedEnvelope); err != nil {
		t.Fatal(err)
	}
	if got := failedEnvelope.Receipt.Runner; got.Outcome != "failed" || got.ErrorClass != "tool_error" {
		t.Fatalf("wrong failed-runner receipt: %+v", got)
	}

	timedOutCtx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-timedOutCtx.Done()
	result, err = executeCustomToolWithReceipt(timedOutCtx, definition, map[string]any{}, nil, func() (actool.Result, error) {
		return actool.Text("timed out before target access"), context.DeadlineExceeded
	})
	if err != nil || !result.IsError {
		t.Fatalf("timed-out runner must stay errored: result=%+v err=%v", result, err)
	}
	var timedOutEnvelope customToolReceiptEnvelope
	if err := json.Unmarshal([]byte(result.Flatten()), &timedOutEnvelope); err != nil {
		t.Fatal(err)
	}
	if got := timedOutEnvelope.Receipt.Runner; got.Outcome != "timed_out" || got.ErrorClass != "deadline_exceeded" {
		t.Fatalf("wrong timed-out runner receipt: %+v", got)
	}
}
