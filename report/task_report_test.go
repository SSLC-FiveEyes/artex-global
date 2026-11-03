package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestTaskReportSeparatesActivityAndUnverifiedDetection(t *testing.T) {
	got := Markdown(Input{
		TaskID: "42", Status: "timeout", GeneratedAt: time.Unix(0, 0),
		Facts:      []*db.Node{{ID: 9, State: "confirmed", Payload: json.RawMessage(`{"summary":"응답 확인"}`)}},
		Intents:    []*db.Node{{ID: 10, State: "blocked", Payload: json.RawMessage(`{"summary":"로그인 확인"}`)}},
		Goals:      []*db.Node{{ID: 11, State: "open", Payload: json.RawMessage(`{"summary":"인증 검증"}`)}},
		Activities: []db.Activity{{ID: 7, Kind: "tool_use", Tool: "WebFetch", CreatedAt: time.Unix(0, 0)}, {ID: 8, Kind: "tool_result", Tool: "WebFetch", IsError: true, CreatedAt: time.Unix(1, 0)}},
	})
	for _, want := range []string{"작업 번호**: 42", "timeout", "WebFetch", "오류", "응답 확인", "로그인 확인", "blocked", "인증 검증", "미확인"} {
		if !strings.Contains(got, want) {
			t.Fatalf("report missing %q: %s", want, got)
		}
	}
}
