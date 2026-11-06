package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The shared 27-case review set (12 real server receipts + 15 counter-examples)
// and its expected labels, from team-lab/results/2026-11-06-gate-v3-review. Each
// case's Detail is exactly what the gate reads from a scanner tool_result, and
// Input is the paired tool_use body.
type scannerCase struct {
	Name     string `json:"name"`
	Tool     string `json:"tool"`
	Detail   string `json:"detail"`
	Input    string `json:"input"`
	Category string `json:"category"`
}

func loadScannerCases(t *testing.T) []scannerCase {
	t.Helper()
	b, err := os.ReadFile("testdata/scanner_receipts.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cs []scannerCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatalf("decode cases: %v", err)
	}
	if len(cs) != 27 {
		t.Fatalf("expected 27 cases, got %d", len(cs))
	}
	return cs
}

func loadExpectedAccept(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("testdata/scanner_expected.json")
	if err != nil {
		t.Fatalf("read labels: %v", err)
	}
	var rows []struct {
		Name     string `json:"name"`
		Expected bool   `json:"review_expected_accept"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("decode labels: %v", err)
	}
	m := map[string]bool{}
	for _, r := range rows {
		m[r.Name] = r.Expected
	}
	return m
}

// installReviewApprovals loads the operator-approved definition list the review
// fixed, then restores the fail-closed empty default afterwards.
func installReviewApprovals(t *testing.T) {
	t.Helper()
	if err := LoadApprovedScannerDefinitions("testdata/scanner_approved.json"); err != nil {
		t.Fatalf("load approvals: %v", err)
	}
	t.Cleanup(func() { SetApprovedScannerDefinitions(nil) })
}

// TestScannerGateMatches27Cases is the fixed acceptance oracle: the gate's
// accept/reject must equal review_expected_accept for all 12 real receipts and
// 15 counter-examples (bad input hash, wrong target, failed/aggregate-only nmap,
// null/false ffuf fields, empty sqlmap finding block, unapproved hash, …).
func TestScannerGateMatches27Cases(t *testing.T) {
	installReviewApprovals(t)
	expect := loadExpectedAccept(t)
	for _, c := range loadScannerCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			want, ok := expect[c.Name]
			if !ok {
				t.Fatalf("no expected label for %s", c.Name)
			}
			got := len(successfulEvidenceCalls(evidencePair(c.Tool, c.Input, c.Detail))) == 1
			if got != want {
				t.Fatalf("%s (%s): gate accepted=%v, review_expected_accept=%v", c.Name, c.Tool, got, want)
			}
		})
	}
}

// The server runner outcome is authoritative regardless of a valid body: only a
// completed, un-errored run counts.
func TestScannerRunnerOutcomesRejected(t *testing.T) {
	installReviewApprovals(t)
	var base scannerCase
	for _, c := range loadScannerCases(t) {
		if c.Name == "task_scan_nmap_01" {
			base = c
		}
	}
	if base.Name == "" {
		t.Fatal("base fixture missing")
	}
	if len(successfulEvidenceCalls(evidencePair(base.Tool, base.Input, base.Detail))) != 1 {
		t.Fatal("base completed receipt not accepted")
	}
	mutate := func(fn func(runner map[string]any)) string {
		var root map[string]any
		if err := json.Unmarshal([]byte(base.Detail), &root); err != nil {
			t.Fatal(err)
		}
		fn(root["artex_execution_receipt"].(map[string]any)["runner"].(map[string]any))
		b, _ := json.Marshal(root)
		return string(b)
	}
	for _, outcome := range []string{"failed", "timed_out", "cancelled", ""} {
		d := mutate(func(r map[string]any) { r["outcome"] = outcome })
		if len(successfulEvidenceCalls(evidencePair(base.Tool, base.Input, d))) != 0 {
			t.Fatalf("runner outcome %q accepted", outcome)
		}
	}
	d := mutate(func(r map[string]any) { r["result_is_error"] = true })
	if len(successfulEvidenceCalls(evidencePair(base.Tool, base.Input, d))) != 0 {
		t.Fatal("result_is_error runner accepted")
	}
}

func TestApprovedScannerDefinitionsLoader(t *testing.T) {
	t.Cleanup(func() { SetApprovedScannerDefinitions(nil) })
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	goodHash := "cf7574f3907e74f0f895b60d41a8055e62848b14a8431dd9500e4ff8257270c0"

	// Empty path -> fail-closed empty set, no error.
	if err := LoadApprovedScannerDefinitions(""); err != nil {
		t.Fatalf("empty path should not error: %v", err)
	}
	if approvedScannerDefinition("fiveeyes_nmap_scan", goodHash) {
		t.Fatal("empty path should leave approvals empty (fail-closed)")
	}

	// Valid file loads.
	ok := write("ok.json", `{"fiveeyes_nmap_scan":["`+goodHash+`"]}`)
	if err := LoadApprovedScannerDefinitions(ok); err != nil {
		t.Fatalf("valid file: %v", err)
	}
	if !approvedScannerDefinition("fiveeyes_nmap_scan", goodHash) {
		t.Fatal("valid approval not installed")
	}

	// Hard startup errors.
	for name, body := range map[string]string{
		"bad.json":     `{not json`,
		"unknown.json": `{"totally_other_tool":["` + goodHash + `"]}`,
		"short.json":   `{"fiveeyes_nmap_scan":["abc123"]}`,
		"empty.json":   `{"fiveeyes_nmap_scan":[]}`,
	} {
		if err := LoadApprovedScannerDefinitions(write(name, body)); err == nil {
			t.Fatalf("%s should be a startup error", name)
		}
	}
	if err := LoadApprovedScannerDefinitions(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file should be a startup error")
	}
}

func TestScannerExecutionToolRegistration(t *testing.T) {
	for _, n := range []string{"fiveeyes_nmap_scan", "fiveeyes_sqlmap_check", "fiveeyes_ffuf_paths"} {
		if !isExecutionTool(n) || !isScannerTool(n) {
			t.Fatalf("%s should be a registered scanner execution tool", n)
		}
	}
	for _, n := range []string{"fiveeyes_nmap_connection_test", "record_fact", "prove_goal", "scoped_http_observe"} {
		if isExecutionTool(n) {
			t.Fatalf("%s should NOT be an execution tool", n)
		}
	}
}
