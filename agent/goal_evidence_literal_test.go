package agent

import (
	"encoding/json"
	"reflect"
	"testing"
)

func evidencePayload(evidence string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"evidence": evidence, "confidence": "observed"})
	return b
}

func TestEvidenceLiteralsMustComeFromExecution(t *testing.T) {
	echo := successfulEvidenceCalls(evidencePair("Bash", `{"command":"echo ARTEX_REPORT_TEST_SUCCESS"}`, "ARTEX_REPORT_TEST_SUCCESS\n"))
	curl := successfulEvidenceCalls(evidencePair("Bash",
		`{"command":"curl -sI http://192.168.20.10/index.php"}`,
		"HTTP/1.1 200 OK\nServer: Apache/2.4.69 (Debian)\nContent-Type: text/html; charset=UTF-8\n"))
	cases := []struct {
		name     string
		evidence string
		calls    int // 0 = echo, 1 = curl
		missing  []string
	}{
		// Isolated task #5 on 2026-11-03: the command ran, the claimed output did not appear.
		{"task5 paraphrased output", "command: echo ARTEX_REPORT_TEST_SUCCESS output: ARTEX_REPORT_SUCCESS", 0, []string{"ARTEX_REPORT_SUCCESS"}},
		{"exact output", "echo ARTEX_REPORT_TEST_SUCCESS → ARTEX_REPORT_TEST_SUCCESS", 0, nil},
		{"http headers", "curl -sI http://192.168.20.10/index.php → HTTP/1.1 200 OK, Server: Apache/2.4.69", 1, nil},
		{"case differs", "content-type: TEXT/HTML; server apache/2.4.69", 1, nil},
		{"invented version", "curl -sI http://192.168.20.10/index.php → Server: nginx/1.25", 1, []string{"nginx/1.25"}},
		{"invented quoted body", `응답 본문에 "Welcome admin" 표시`, 1, []string{"Welcome admin"}},
		{"korean prose and dates only", "로그인 페이지가 정상 응답함 (2026-11-03 확인)", 1, nil},
		{"plain english words", "server responded normally with headers", 1, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := echo
			if tc.calls == 1 {
				calls = curl
			}
			got := missingEvidenceLiterals(evidencePayload(tc.evidence), calls)
			if !reflect.DeepEqual(got, tc.missing) {
				t.Fatalf("missing=%q want %q", got, tc.missing)
			}
		})
	}
}

func TestEvidenceLiteralCheckSkipsTruncatedOutput(t *testing.T) {
	calls := successfulEvidenceCalls(evidencePair("Bash", `{"command":"cat big.log"}`,
		"head...\n\n... <persisted-output>[Output too large: full 90000 bytes / 900 lines.Full output saved to  cmd-output/x.txt </persisted-output>"))
	if got := missingEvidenceLiterals(evidencePayload("tail shows ERROR_CODE_42"), calls); got != nil {
		t.Fatalf("truncated output must not reject a real observation: %q", got)
	}
}
