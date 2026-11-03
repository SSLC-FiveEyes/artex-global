package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func scenarioProfileFixture(state string, allowed []string) *db.TaskScenarioProfile {
	profile, _ := json.Marshal(map[string]any{
		"version":       1,
		"scenario_id":   "fiveeyes_recon",
		"state":         state,
		"allowed_tools": allowed,
	})
	return &db.TaskScenarioProfile{
		TaskID:             42,
		ScenarioID:         "fiveeyes_recon",
		State:              state,
		Version:            1,
		Profile:            profile,
		ProfileFingerprint: "fixture-fingerprint",
	}
}

func TestScenarioProfileDraftFailsClosedAndArmedUsesExactAllowlist(t *testing.T) {
	draft, err := scenarioPolicyFromProfile(scenarioProfileFixture(db.TaskScenarioProfileDraft, []string{"Read", "fiveeyes_nmap_scan"}))
	if err != nil {
		t.Fatal(err)
	}
	if !draft.Enforced || draft.ProfileState != db.TaskScenarioProfileDraft || len(draft.AllowedTools) != 0 {
		t.Fatalf("draft must be an enforced full stop: %+v", draft)
	}

	armed, err := scenarioPolicyFromProfile(scenarioProfileFixture(db.TaskScenarioProfileArmed, []string{"Read", "record_fact", "fiveeyes_nmap_scan"}))
	if err != nil {
		t.Fatal(err)
	}
	if !armed.Enforced || armed.ProfileState != db.TaskScenarioProfileArmed || !armed.AllowsTool("READ") || !armed.AllowsTool("fiveeyes_nmap_scan") {
		t.Fatalf("armed policy lost allowlist: %+v", armed)
	}
	if !armed.AllowsTool("Bash") || !armed.AllowsWebFetch() || armed.ProfileFingerprint != "fixture-fingerprint" {
		t.Fatalf("armed policy must expose Bash and WebFetch: %+v", armed)
	}
	if draft.AllowsTool("Bash") || draft.AllowsWebFetch() {
		t.Fatal("draft must block Bash and WebFetch")
	}
}

func TestScenarioProfileAllowsBashAndWebFetchAndRejectsMismatchedDocument(t *testing.T) {
	bad := db.TaskScenarioProfileInput{
		ScenarioID: "fiveeyes_recon", State: db.TaskScenarioProfileArmed, Version: 1,
		Profile: json.RawMessage(`{"version":1,"scenario_id":"fiveeyes_recon","state":"armed","allowed_tools":["Bash","WebFetch"]}`),
	}
	if _, err := validateScenarioProfileInput(bad); err != nil {
		t.Fatalf("Bash and WebFetch should be accepted: %v", err)
	}

	mismatch := db.TaskScenarioProfileInput{
		ScenarioID: "fiveeyes_recon", State: db.TaskScenarioProfileDraft, Version: 1,
		Profile: json.RawMessage(`{"version":2,"scenario_id":"fiveeyes_recon","state":"draft","allowed_tools":["Read"]}`),
	}
	if _, err := validateScenarioProfileInput(mismatch); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("embedded version mismatch must be rejected, err=%v", err)
	}

	badAdapter := db.TaskScenarioProfileInput{
		ScenarioID: "fiveeyes_recon", State: db.TaskScenarioProfileArmed, Version: 1,
		Profile: json.RawMessage(`{"version":1,"scenario_id":"fiveeyes_recon","state":"armed","allowed_tools":["curl_wrapper"]}`),
	}
	if _, err := validateScenarioProfileInput(badAdapter); err == nil || !strings.Contains(err.Error(), "bounded fiveeyes_") {
		t.Fatalf("unbounded custom adapter name must be rejected, err=%v", err)
	}
}
