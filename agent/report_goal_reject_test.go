package agent

import "testing"

func TestIsReportDeliverableGoal(t *testing.T) {
	reject := []string{
		"완료된 모의해킹 보고서 파일을 작업 폴더에 작성",
		"보안 진단 결과를 Markdown 파일로 저장한다",
		"최종 리포트를 생성하라",
		"Write a penetration test report",
		"작업 결과 report.md 생성",
	}
	for _, s := range reject {
		if !IsReportDeliverableGoal(s) {
			t.Errorf("should be rejected as report deliverable: %q", s)
		}
	}
	keep := []string{
		"대상 웹 애플리케이션의 인증·권한·주입 취약점을 실제 요청으로 시험하고 확인한다",
		"SQL 주입으로 관리자 세션 탈취 가능 여부를 확인",
		"로그인 폼의 인증 우회 가능성을 시험",            // 'report' noun absent
		"취약점 진단 결과를 record_fact로 기록",          // recording findings, no report-file deliverable
	}
	for _, s := range keep {
		if IsReportDeliverableGoal(s) {
			t.Errorf("legit diagnostic goal wrongly flagged: %q", s)
		}
	}
	// The exact failing case from live task #39 must be caught at decomposition.
	if !IsReportDeliverableGoal("완료된 모의해킹 보고서 파일을 작업 폴더에 작성") {
		t.Fatal("task #39 report-as-goal regression")
	}
}
