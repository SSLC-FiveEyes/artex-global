package server

import "testing"

func TestAutoReportRejectsFabricatedEndpointPaths(t *testing.T) {
	source := "요청 URL: http://host.docker.internal:8088/login.php 상태코드 200. GET / 200. /robots.txt 404."
	// /admin.php was never in the record → fabricated.
	if validateAutoReportNarrative("| GET | /admin.php | 200 OK | 관리자 페이지 확인 |", source) == nil {
		t.Fatal("fabricated /admin.php endpoint accepted")
	}
	// /login.php is in the record → allowed.
	if err := validateAutoReportNarrative("GET /login.php 200 로그인 페이지 확인", source); err != nil {
		t.Fatalf("recorded /login.php wrongly rejected: %v", err)
	}
	// No endpoint paths at all → unaffected.
	if err := validateAutoReportNarrative("확인된 취약점 기록 0건. 범위 밖은 미확인.", source); err != nil {
		t.Fatalf("plain report wrongly rejected: %v", err)
	}
}
