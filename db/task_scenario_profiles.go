package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	TaskScenarioProfileDraft = "draft"
	TaskScenarioProfileArmed = "armed"

	MaxTaskScenarioIDRunes      = 96
	MaxTaskScenarioProfileBytes = 128 << 10
)

var (
	ErrTaskScenarioProfileInvalid      = errors.New("invalid task scenario profile")
	ErrTaskScenarioProfileTaskNotFound = errors.New("task not found for scenario profile")
)

var taskScenarioIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// TaskScenarioProfile is the server-stored execution contract associated with
// one task. Profile is raw canonical JSON; the server layer deliberately owns
// its semantic interpretation and turns it into an execution policy.
type TaskScenarioProfile struct {
	TaskID             int64           `json:"task_id"`
	ScenarioID         string          `json:"scenario_id"`
	State              string          `json:"state"`
	Version            int             `json:"version"`
	Profile            json.RawMessage `json:"profile"`
	ProfileFingerprint string          `json:"profile_fingerprint"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// TaskScenarioProfileInput contains only operator-controlled fields. The
// fingerprint is derived by ARTEX from the normalized content, never accepted
// from a caller as a trusted assertion.
type TaskScenarioProfileInput struct {
	ScenarioID string          `json:"scenario_id"`
	State      string          `json:"state"`
	Version    int             `json:"version"`
	Profile    json.RawMessage `json:"profile"`
}

const taskScenarioProfileCols = `task_id, scenario_id, state, version, profile, profile_fingerprint, created_at, updated_at`

func scanTaskScenarioProfile(row interface{ Scan(...any) error }) (*TaskScenarioProfile, error) {
	var profile TaskScenarioProfile
	var raw []byte
	if err := row.Scan(&profile.TaskID, &profile.ScenarioID, &profile.State, &profile.Version, &raw, &profile.ProfileFingerprint, &profile.CreatedAt, &profile.UpdatedAt); err != nil {
		return nil, err
	}
	profile.Profile = append(json.RawMessage(nil), raw...)
	return &profile, nil
}

func normalizeTaskScenarioProfileInput(in TaskScenarioProfileInput) (TaskScenarioProfileInput, string, error) {
	in.ScenarioID = strings.ToLower(strings.TrimSpace(in.ScenarioID))
	in.State = strings.ToLower(strings.TrimSpace(in.State))
	if in.Version <= 0 {
		return in, "", fmt.Errorf("%w: version must be positive", ErrTaskScenarioProfileInvalid)
	}
	if in.ScenarioID == "" || len([]rune(in.ScenarioID)) > MaxTaskScenarioIDRunes || !taskScenarioIDPattern.MatchString(in.ScenarioID) {
		return in, "", fmt.Errorf("%w: scenario_id must use lowercase letters, digits, underscores, or hyphens", ErrTaskScenarioProfileInvalid)
	}
	if in.State != TaskScenarioProfileDraft && in.State != TaskScenarioProfileArmed {
		return in, "", fmt.Errorf("%w: state must be %q or %q", ErrTaskScenarioProfileInvalid, TaskScenarioProfileDraft, TaskScenarioProfileArmed)
	}
	if len(in.Profile) == 0 || len(in.Profile) > MaxTaskScenarioProfileBytes {
		return in, "", fmt.Errorf("%w: profile must be a JSON object no larger than %d bytes", ErrTaskScenarioProfileInvalid, MaxTaskScenarioProfileBytes)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(in.Profile, &obj); err != nil || obj == nil {
		return in, "", fmt.Errorf("%w: profile must be a JSON object", ErrTaskScenarioProfileInvalid)
	}
	canonical, err := json.Marshal(obj)
	if err != nil {
		return in, "", fmt.Errorf("%w: profile cannot be serialized", ErrTaskScenarioProfileInvalid)
	}
	in.Profile = canonical
	fingerprintSource, err := json.Marshal(struct {
		ScenarioID string          `json:"scenario_id"`
		State      string          `json:"state"`
		Version    int             `json:"version"`
		Profile    json.RawMessage `json:"profile"`
	}{
		ScenarioID: in.ScenarioID,
		State:      in.State,
		Version:    in.Version,
		Profile:    in.Profile,
	})
	if err != nil {
		return in, "", fmt.Errorf("%w: fingerprint serialization failed", ErrTaskScenarioProfileInvalid)
	}
	sum := sha256.Sum256(fingerprintSource)
	return in, hex.EncodeToString(sum[:]), nil
}

// UpsertTaskScenarioProfile creates or replaces a task's profile. A task must
// still be live; a deleted task cannot be given a new executable contract.
func (d *DB) UpsertTaskScenarioProfile(taskID int64, in TaskScenarioProfileInput) (*TaskScenarioProfile, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("%w: task id must be positive", ErrTaskScenarioProfileTaskNotFound)
	}
	in, fingerprint, err := normalizeTaskScenarioProfileInput(in)
	if err != nil {
		return nil, err
	}
	profile, err := scanTaskScenarioProfile(d.QueryRow(`
WITH live_task AS (
    SELECT id FROM tasks WHERE id=$1 AND deleted_at IS NULL
), saved AS (
    INSERT INTO task_scenario_profiles(task_id, scenario_id, state, version, profile, profile_fingerprint)
    SELECT id, $2, $3, $4, $5, $6 FROM live_task
    ON CONFLICT (task_id) DO UPDATE
       SET scenario_id=EXCLUDED.scenario_id,
           state=EXCLUDED.state,
           version=EXCLUDED.version,
           profile=EXCLUDED.profile,
           profile_fingerprint=EXCLUDED.profile_fingerprint
    RETURNING `+taskScenarioProfileCols+`
)
SELECT `+taskScenarioProfileCols+` FROM saved`, taskID, in.ScenarioID, in.State, in.Version, in.Profile, fingerprint))
	if err == sql.ErrNoRows {
		return nil, ErrTaskScenarioProfileTaskNotFound
	}
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetTaskScenarioProfile returns nil when a task has no profile.
func (d *DB) GetTaskScenarioProfile(taskID int64) (*TaskScenarioProfile, error) {
	profile, err := scanTaskScenarioProfile(d.QueryRow(`SELECT `+taskScenarioProfileCols+` FROM task_scenario_profiles WHERE task_id=$1`, taskID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// DeleteTaskScenarioProfile detaches a profile without deleting the task. The
// task's hard-delete path also removes it through the foreign-key cascade.
func (d *DB) DeleteTaskScenarioProfile(taskID int64) (bool, error) {
	if taskID <= 0 {
		return false, nil
	}
	result, err := d.Exec(`DELETE FROM task_scenario_profiles WHERE task_id=$1`, taskID)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}
