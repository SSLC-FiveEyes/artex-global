# 시나리오 실행 프로필 예시

이 폴더의 JSON은 ARTEX에 자동 등록·적용되지 않는 **초안**이다. 실제 대상 주소·계정·토큰·인증 비밀값은 포함하지 않으며, 모든 프로필은 `draft` 상태로 둔다.

소스의 향후 API 요청은 아래처럼 바깥 메타데이터와 `profile` 객체를 분리한다. 이 예시는 설명용이며 현재 실행 중인 Mac ARTEX에는 배포되지 않았다.

```json
{
  "scenario_id": "fiveeyes-recon",
  "state": "draft",
  "version": 1,
  "profile": { "...": "recon.example.json의 내용" }
}
```

향후 ARTEX의 작업별 실행 프로필은 다음 정보를 한 묶음으로 고정한다.

- `scenario_id`, `version`, `state`
- worker가 노출받을 수 있는 `allowed_tools`
- 승인 뒤에 채울 `scope`와 요청·시간 한도
- 관제팀에 전달할 `required_evidence`

`armed` 상태가 되려면 별도 검토를 거친 실제 대상·한도·복구 절차와 서버 측 실행 게이트가 필요하다. 예시의 빈 목록이나 `not_configured` 값은 실행 가능 범위가 아니라 **미실행**을 뜻한다.

2026-11-03 사용자 방향 변경: `armed` 작업에는 `Bash`와 `WebFetch`를 자동으로 제공하고 `draft`는 실행을 막는다. 대화형 shell 등 다른 제한은 유지한다. 이는 도구 노출 설정이며 대상·포트·요청 수나 인터넷 접근을 강제 제한하지 않는다. 실제 실행 전 독립된 실습망의 송신 제한, DNS·프록시 우회 및 실제 경로를 검증해야 한다. 대상·계정과 현장 구성은 미정이며 배포·대상 실행은 not_run이다.
