package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// A task scenario profile is an execution boundary, not a finding, an exploit
// claim, or a SOC result. Network isolation is external to this tool policy.
const maxScenarioAllowedTools = 64

var scenarioToolNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_:-]{0,127}$`)

// Other transports remain excluded; Bash and WebFetch are available when armed.
var forbiddenScenarioTools = map[string]bool{
	"web_fetch":          true,
	"websearch":          true,
	"web_search":         true,
	"skill":              true,
	"search_extra_tools": true,
	"execute_extra_tool": true,
	"shell_open":         true,
	"shell_send":         true,
	"shell_recv":         true,
	"shell_close":        true,
	"shell_list":         true,
}

var safeScenarioBuiltinTools = map[string]bool{
	"bash":                     true,
	"webfetch":                 true,
	"read":                     true,
	"write":                    true,
	"edit":                     true,
	"ls":                       true,
	"sleep":                    true,
	"record_fact":              true,
	"insert_assets":            true,
	"list_assets":              true,
	"list_findings":            true,
	"list_facts":               true,
	"node_detail":              true,
	"graph_overview":           true,
	"get_worker_output":        true,
	"get_worker_trace":         true,
	"search_all_worker_traces": true,
	"list_goals":               true,
	"add_intent":               true,
	"prove_goal":               true,
	"goal_met":                 true,
	"report_finding":           true,
	"expand_digest":            true,
}

type taskScenarioProfileDocument struct {
	Version      *int     `json:"version,omitempty"`
	ScenarioID   string   `json:"scenario_id,omitempty"`
	State        string   `json:"state,omitempty"`
	AllowedTools []string `json:"allowed_tools"`
}

type taskScenarioProfileReq struct {
	ScenarioID string          `json:"scenario_id"`
	State      string          `json:"state"`
	Version    int             `json:"version"`
	Profile    json.RawMessage `json:"profile"`
}

func normalizeScenarioAllowedTools(in []string) ([]string, error) {
	if len(in) == 0 || len(in) > maxScenarioAllowedTools {
		return nil, fmt.Errorf("allowed_tools must contain 1-%d tool names", maxScenarioAllowedTools)
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		name := strings.TrimSpace(raw)
		if !scenarioToolNamePattern.MatchString(name) {
			return nil, fmt.Errorf("invalid allowed tool name %q", raw)
		}
		key := strings.ToLower(name)
		if forbiddenScenarioTools[key] || strings.HasPrefix(key, "mcp__") {
			return nil, fmt.Errorf("general-purpose transport tool %q is not permitted in a scenario profile", name)
		}
		if !safeScenarioBuiltinTools[key] && !strings.HasPrefix(key, "fiveeyes_") {
			return nil, fmt.Errorf("scenario tool %q must be a safe built-in or a bounded fiveeyes_ adapter", name)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate allowed tool %q", name)
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

// validateScenarioProfileInput validates the server-owned meaning of the raw
// profile before it reaches the database. db additionally canonicalizes the
// bytes and derives the fingerprint persisted with the task.
func validateScenarioProfileInput(in db.TaskScenarioProfileInput) ([]string, error) {
	var doc taskScenarioProfileDocument
	if err := json.Unmarshal(in.Profile, &doc); err != nil {
		return nil, fmt.Errorf("profile must be valid JSON: %w", err)
	}
	allowed, err := normalizeScenarioAllowedTools(doc.AllowedTools)
	if err != nil {
		return nil, err
	}
	if doc.Version != nil && *doc.Version != in.Version {
		return nil, errors.New("profile.version must match request version")
	}
	if doc.ScenarioID != "" && !strings.EqualFold(strings.TrimSpace(doc.ScenarioID), strings.TrimSpace(in.ScenarioID)) {
		return nil, errors.New("profile.scenario_id must match request scenario_id")
	}
	if doc.State != "" && !strings.EqualFold(strings.TrimSpace(doc.State), strings.TrimSpace(in.State)) {
		return nil, errors.New("profile.state must match request state")
	}
	return allowed, nil
}

func scenarioPolicyFromProfile(profile *db.TaskScenarioProfile) (agent.ScenarioToolPolicy, error) {
	if profile == nil {
		return agent.ScenarioToolPolicy{}, nil
	}
	allowed, err := validateScenarioProfileInput(db.TaskScenarioProfileInput{
		ScenarioID: profile.ScenarioID,
		State:      profile.State,
		Version:    profile.Version,
		Profile:    profile.Profile,
	})
	if err != nil {
		return agent.ScenarioToolPolicy{}, err
	}
	policy := agent.ScenarioToolPolicy{
		Enforced:           true,
		ScenarioID:         profile.ScenarioID,
		ProfileState:       profile.State,
		ProfileFingerprint: profile.ProfileFingerprint,
	}
	// A draft is intentionally a full stop. Keeping its requested allowlist in
	// storage lets an operator review it, but no task agent receives any tools
	// until the separately saved profile is explicitly armed.
	if profile.State == db.TaskScenarioProfileArmed {
		policy.AllowedTools = append([]string(nil), allowed...)
		for _, name := range []string{"Bash", "WebFetch"} {
			if !policy.AllowsTool(name) {
				policy.AllowedTools = append(policy.AllowedTools, name)
			}
		}
	}
	return policy, nil
}

// taskScenarioToolPolicy is called for every task-agent turn. An unavailable or
// malformed attached profile fails closed; no profile preserves legacy behavior.
func (s *Server) taskScenarioToolPolicy(taskID int64) agent.ScenarioToolPolicy {
	if s == nil || s.m == nil || s.m.pg == nil || taskID <= 0 {
		return agent.ScenarioToolPolicy{}
	}
	profile, err := s.m.pg.GetTaskScenarioProfile(taskID)
	if err != nil {
		log.Printf("[scenario-profile] task %d lookup failed; execution tools are blocked: %v", taskID, err)
		return agent.ScenarioToolPolicy{Enforced: true, ScenarioID: "profile_lookup_error", ProfileState: "invalid"}
	}
	policy, err := scenarioPolicyFromProfile(profile)
	if err != nil {
		id, fp := "invalid_profile", ""
		if profile != nil {
			id, fp = profile.ScenarioID, profile.ProfileFingerprint
		}
		log.Printf("[scenario-profile] task %d profile %q is invalid; execution tools are blocked: %v", taskID, id, err)
		return agent.ScenarioToolPolicy{Enforced: true, ScenarioID: id, ProfileState: "invalid", ProfileFingerprint: fp}
	}
	return policy
}

func (s *Server) taskScenarioProfileGet(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, http.StatusBadRequest, "bad task id")
		return
	}
	profile, err := pg.GetTaskScenarioProfile(taskID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if profile == nil {
		writeErr(w, http.StatusNotFound, "scenario profile not found")
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) taskScenarioProfilePut(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, http.StatusBadRequest, "bad task id")
		return
	}
	var req taskScenarioProfileReq
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	in := db.TaskScenarioProfileInput{
		ScenarioID: req.ScenarioID,
		State:      req.State,
		Version:    req.Version,
		Profile:    req.Profile,
	}
	if _, err := validateScenarioProfileInput(in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	profile, err := pg.UpsertTaskScenarioProfile(taskID, in)
	if errors.Is(err, db.ErrTaskScenarioProfileTaskNotFound) {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if err != nil {
		if errors.Is(err, db.ErrTaskScenarioProfileInvalid) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) taskScenarioProfileDelete(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, ok := pathInt(r, "id")
	if !ok || taskID <= 0 {
		writeErr(w, http.StatusBadRequest, "bad task id")
		return
	}
	deleted, err := pg.DeleteTaskScenarioProfile(taskID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}
