package db

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestTaskScenarioProfileCRUDAndTaskDeleteCascade(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	task, err := d.CreateTask("scenario profile fixture", "store an execution profile", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	input := TaskScenarioProfileInput{
		ScenarioID: " FiveEyes_Recon ",
		State:      "DRAFT",
		Version:    1,
		Profile: json.RawMessage(`{
  "limits": {"max_requests": 1},
  "allowed_tools": ["fiveeyes_nmap_scan", "record_fact"]
}`),
	}
	created, err := d.UpsertTaskScenarioProfile(task.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if created.TaskID != task.ID || created.ScenarioID != "fiveeyes_recon" || created.State != TaskScenarioProfileDraft || created.Version != 1 || len(created.ProfileFingerprint) != 64 {
		t.Fatalf("unexpected stored profile: %+v", created)
	}
	if !json.Valid(created.Profile) || string(created.Profile) != `{"allowed_tools":["fiveeyes_nmap_scan","record_fact"],"limits":{"max_requests":1}}` {
		t.Fatalf("profile was not canonical JSON: %q", created.Profile)
	}

	got, err := d.GetTaskScenarioProfile(task.ID)
	if err != nil || got == nil || got.ProfileFingerprint != created.ProfileFingerprint {
		t.Fatalf("get profile: got=%+v err=%v", got, err)
	}
	if string(got.Profile) != string(created.Profile) {
		t.Fatalf("profile read back from JSONB differs from stored canonical form: %s vs %s", got.Profile, created.Profile)
	}

	updated, err := d.UpsertTaskScenarioProfile(task.ID, TaskScenarioProfileInput{
		ScenarioID: "fiveeyes_recon",
		State:      TaskScenarioProfileArmed,
		Version:    2,
		Profile:    json.RawMessage(`{"allowed_tools":["record_fact"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != TaskScenarioProfileArmed || updated.Version != 2 || updated.ProfileFingerprint == created.ProfileFingerprint {
		t.Fatalf("update did not replace execution contract: before=%+v after=%+v", created, updated)
	}

	deleted, err := d.DeleteTaskScenarioProfile(task.ID)
	if err != nil || !deleted {
		t.Fatalf("delete profile: deleted=%v err=%v", deleted, err)
	}
	if got, err := d.GetTaskScenarioProfile(task.ID); err != nil || got != nil {
		t.Fatalf("profile should be absent after delete: got=%+v err=%v", got, err)
	}

	if _, err := d.UpsertTaskScenarioProfile(task.ID, TaskScenarioProfileInput{
		ScenarioID: "fiveeyes_recon", State: TaskScenarioProfileDraft, Version: 1, Profile: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTask(task.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetTaskScenarioProfile(task.ID); err != nil || got != nil {
		t.Fatalf("task delete must cascade profile: got=%+v err=%v", got, err)
	}
}

func TestNormalizeTaskScenarioProfileRejectsUnsafeShape(t *testing.T) {
	valid := TaskScenarioProfileInput{ScenarioID: "fiveeyes_recon", State: TaskScenarioProfileDraft, Version: 1, Profile: json.RawMessage(`{}`)}
	badInputs := []TaskScenarioProfileInput{
		{ScenarioID: "", State: TaskScenarioProfileDraft, Version: 1, Profile: json.RawMessage(`{}`)},
		{ScenarioID: "bad id", State: TaskScenarioProfileDraft, Version: 1, Profile: json.RawMessage(`{}`)},
		{ScenarioID: valid.ScenarioID, State: "live", Version: 1, Profile: json.RawMessage(`{}`)},
		{ScenarioID: valid.ScenarioID, State: valid.State, Version: 0, Profile: json.RawMessage(`{}`)},
		{ScenarioID: valid.ScenarioID, State: valid.State, Version: 1, Profile: json.RawMessage(`[]`)},
	}
	for _, input := range badInputs {
		if _, _, err := normalizeTaskScenarioProfileInput(input); !errors.Is(err, ErrTaskScenarioProfileInvalid) {
			t.Fatalf("invalid input %+v: err=%v", input, err)
		}
	}
}

func TestTaskScenarioProfileMissingTask(t *testing.T) {
	valid := TaskScenarioProfileInput{ScenarioID: "fiveeyes_recon", State: TaskScenarioProfileDraft, Version: 1, Profile: json.RawMessage(`{}`)}
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping missing-task check", err)
	}
	defer d.Close()
	if _, err := d.UpsertTaskScenarioProfile(1<<62, valid); !errors.Is(err, ErrTaskScenarioProfileTaskNotFound) {
		t.Fatalf("missing task error=%v", err)
	}
}
