# ARTEX 스캔 도구 연결 예시

2026-10-31 · 멘토 피드백의 1번 스캔 준비 · **2026-11-03 Mac ARTEX에 비활성 등록; 대상 실행은 not_run**

먼저 ARTEX의 현재 도구 목록과 실행 환경에서 기존 Bash·HTTP·브라우저 도구를 확인한다. 저장소 Dockerfile은 nmap을 포함하지만 실제 Windows/Ubuntu 배포 이미지의 설치 여부는 확인하지 않았다. sqlmap은 해당 Dockerfile의 설치 목록에 없다. Kali에 설치된 도구가 ARTEX에서도 자동 사용되지는 않는다.

## 연결 방식

- [nmap 예시](fiveeyes_nmap_scan.example.json): `kind=script`, Python 표준 라이브러리만 사용한다. 승인된 단일 IPv4와 고정 포트 목록을 확인하며 connect scan을 사용한다. 버전 탐지·NSE·대역 탐색은 포함하지 않는다.
- [sqlmap 예시](fiveeyes_sqlmap_check.example.json): 승인된 단일 URL·쿼리 변수의 제한된 boolean SQLi 확인 후보다. sqlmap은 포트 스캐너가 아니라 **실제 입력 공격 요청을 발생시키는 SQLi 도구**다. DB 열거·덤프·OS 명령은 지정하지 않는다. sqlmap 자체의 결과를 취약점 성공의 유일한 근거로 삼지 않는다.

둘 다 `enabled=false`, `agents=[]`이고 코드 안의 승인 대상 목록도 비어 있다. 현재는 호출하더라도 대상 요청 전에 `not_run`으로 종료된다. 이 파일은 자동 등록·실행 설정이 아니다. 승인 범위가 정해진 후 검토된 복사본에서 대상·포트·변수를 운영자가 고정하고 필요한 agent에만 연결한다. 실제 대상·계정은 이 공유 예시에 넣지 않는다.

실제 인터페이스는 `server/customtool.go`의 `customToolReq`, `scriptExec`, `runScriptTool`, `execPython`과 대조했다. JSON의 `key`, `description`, `schema`, `agents`, `enabled`, `kind`, `exec`, `deferred`는 해당 API 요청 필드와 일치한다. `exec.code`는 stdin JSON을 읽고 `exec.timeout_ms`는 서버 실행 제한으로 전달된다. 파일 자동 import 기능을 전제하지 않으며, 도구 편집 화면의 해당 필드에 옮기거나 인증된 관리 API `POST /api/tools/custom`의 요청 본문으로 사용할 수 있는 형식이다. 2026-11-03 Mac ARTEX에 두 예시를 비활성 상태로 등록했으며 대상·에이전트는 비어 있다. Windows VM 등록은 미확인이다.

`shell` 유형은 Bash 설명에 도구 사용 가능성을 알리는 선언이며 별도 호출 도구나 설치 작업을 생성하지 않는다. 예시의 `script` 유형은 별도 도구 호출을 남기고 argv 배열로 프로세스를 실행한다. 등록 화면의 시험 실행도 실제 명령을 실행하므로 승인 전 네트워크 시험에 사용하지 않는다.

## 실행 전 확인과 결과 해석

1. 실행 컨테이너·VM의 Python/nmap/sqlmap 설치 경로와 버전을 먼저 확인한다. 설치가 없으면 멈추며 자동 다운로드하지 않는다.
2. 대상·허용 포트·URL·변수와 시간·중지 조건을 확정한다. nmap은 IP/포트 범위, sqlmap은 URL/변수 범위를 코드 내부에 고정한다. 모델에게 임의 옵션이나 대상 목록을 받지 않는다.
3. pfSense 실제 경유, Snort 인터페이스와 HTTP 가시성, 서버 로그·Splunk 수집을 정상 요청으로 검증한 후 별도 승인된 스캔을 수행한다.
4. nmap의 rate·timeout 및 sqlmap의 delay·timeout은 엄격한 전체 HTTP 요청 수 상한을 보장하지 않는다. sqlmap은 로컬 세션·출력 파일을 생성할 수도 있다. 고정 요청 수가 필요한 실험은 독립 계수·제한 장치와 초기화 절차를 먼저 확인한다.
5. 출력 JSON `status=executed`는 명령이 실행됐다는 뜻이며 성공·취약점 발견·탐지 성공을 의미하지 않는다. `exit_code`, 도구 출력, 독립 네트워크·서버 로그를 확인한다. timeout은 `incomplete`이며 이미 요청이 발생했을 수 있다. 대상 범위 미설정이나 도구 미설치는 `not_run`이다. 이번 소스 보완은 Python 프로세스의 실패·timeout을 `is_error`로 전달한다. Unix에서는 별도 프로세스 그룹을 사용해 Python과 일반 자식 프로세스를 함께 정리한다. Windows 취소는 기본 taskkill /T /F를 사용하며 성공하지 못할 때 직접 프로세스 종료로 돌아가므로 실제 Windows 자식 정리는 추가 검증이 필요하다. 실제 Mac 실행 이미지에 이 변경이 적용되었는지는 별도 확인해야 한다. 도구 실행 성공은 취약점 성공의 증거가 아니므로 JSON 상태와 출력을 읽어 독립 판정한다.
6. `run_id`는 nmap 출력의 메타데이터이며 nmap 패킷에 자동 삽입되지 않는다. nmap은 실제 출발지·대상·포트·시각으로 연결하고 sqlmap은 User-Agent의 실행 ID와 웹 로그도 대조한다. 원본은 Git 제외 `team-lab/results/`·`team-lab/evidence/`에 보존한다.

현재 소스의 일반 Bash 등 다른 도구까지 이 예시의 대상 제한이 적용되는 것은 아니다. 실행 도구·바인딩·네트워크 범위를 함께 확인한다.

참고: [Nmap 성능·시간 옵션](https://nmap.org/book/man-performance.html), [sqlmap 공식 사용법](https://github.com/sqlmapproject/sqlmap/wiki/Usage). 열람일 2026-10-31. 예시의 고정 옵션은 최초 소규모 실험 제안이며 현장 측정으로 확정한 값이 아니다.

## 오프라인 검증과 목표 근거 연결

`python3 team-lab/config/scan-tools/check_offline.py`는 프로세스 실행을 mock으로 대체해 비활성·범위 미설정, 고정 argv, 다른 대상·입력 차단, native 실패 및 timeout 상태를 확인한다. 네트워크 요청이나 nmap/sqlmap 실행을 하지 않는다.

사용자 정의 도구의 trace와 사실은 검토할 수 있지만, 현재 사용자 정의 도구 자체의 결과는 자동 `prove_goal`의 실행 근거로 인정하지 않는다. 도구 이름이나 모델/스크립트가 출력한 성공 JSON만으로 신뢰를 확장하지 않기 위한 경계다. 향후 서버·작업별 실행시점 정의 스냅샷과 엄격한 결과 판정이 준비된 후 연결한다. 증명시점의 현재 카탈로그만 조회하면 실행 후 활성화·삭제·재생성·정의 변경을 과거 실행에 잘못 적용할 수 있어 해당 방식은 채택하지 않았다. 사용자 도구는 보고서의 성공한 `Write`와 실제 Markdown 파일 대조도 대신하지 못한다.
