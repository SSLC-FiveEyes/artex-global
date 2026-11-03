# Victim MFA 변경 묶음

상태: 2026-11-03 읽기 확인에서 기존 MFA 소스가 실제 Victim 작업 트리에 존재했다. 이 폴더의 보완은 실제 Victim 소스에 반영했고 격리 DB와 합성 계정으로 단위·HTTP 검증했다. 기존 실행 사이트에는 배포하거나 MFA를 활성화하지 않았다. 기존 홈페이지와 같은 상대 경로로 파일을 배치한 overlay다. 비밀번호 로그인에 TOTP 소유 요인을 추가하며 OTP를 화면에 표시하지 않는다. `AIRPORT_MFA_ENABLED=0`이 기본값이다.

## 구성과 적용 전제

- `app/auth/mfa.php`: 30초·6자리 SHA-1 TOTP, 현재/이전/다음 구간 허용, 5분 challenge, challenge당 최대 5번 검증, 세션 binding과 계정·비밀번호 재검증. 인증 완료 proof의 최대 수명은 12시간이다.
- `public/login.php`: 기존 화면 유지. 활성화 시 비밀번호 성공은 pending 상태만 생성하고 `/mfa.php`로 이동한다. 계정 secret 누락·설정 오류는 503과 고정 감사 사유로 거부한다.
- `public/mfa.php`: challenge_token+otp+csrf를 POST로 검증한다. 완료 후 세션을 재생성하고 정식 user_id·credential_stamp·mfa_verified를 설정한다. 실패 이유와 HTTP 상태를 감사 로그에 남긴다.
- `config/mfa.env.example`, `config/mfa-secrets.example.json`, `config/compose.mfa.example.yaml`: 비활성 예시와 빈 JSON, Compose 전달용 예시. 환경 파일은 자동 적용되지 않는다. 실제 계정별 TOTP secret과 운영 설정은 이 변경 묶음에 없다.

실제 사용 전 담당자가 충분히 무작위인 계정별 Base32 secret을 별도 생성·등록하고 인증 앱에 안전하게 배포해야 한다. SECRET_FILE은 public 밖에서 PHP worker만 읽도록 관리한다. JSON은 user id 문자열을 키, secret을 값으로 하는 객체다. 활성화되면 로그인하는 모든 계정에 등록이 필요하다. 실제 secret 파일은 Git 제외·비공개 경로에만 두며 로그·발표자료에 넣지 않는다. 이 묶음은 등록 UI나 계정 복구·기기 변경 정책을 구현하지 않는다.

TOTP 재사용 방지는 `storage/mfa-replay`의 계정+secret별 기록을 `flock`으로 잠근 뒤 마지막 성공 구간을 기록한다. 단일 서버의 로컬 영속 저장소를 전제로 하며 여러 서버나 NFS 환경에는 공동 원자적 저장소가 필요하다. 성공 후 같은 코드를 새 세션에서 다시 사용하면 거부되므로 다음 코드가 표시될 때까지 기다려야 한다. challenge별 실패 제한은 전역 IP·계정별 속도 제한을 대신하지 않는다.

## bootstrap 필수 후크

1. `app/bootstrap.php`에서 세션 모듈 뒤에 `app/auth/mfa.php`를 require한다.
2. `user()`가 DB 계정과 credential stamp를 확인한 다음, `mfa_enabled()`이고 `!mfa_session_verified($_SESSION,$u,time())`인 경우 정식 인증을 인정하지 않는다. 기존 password-only 세션의 `user_id`, `credential_stamp`, `mfa_verified`를 제거하고 `$u=false`로 설정한다. 이미 `mfa_pending`이 있으면 보존해 확인 화면이 계속 동작해야 한다. 인증 앱 미등록 사용자를 password-only로 예외 승격하지 않는다.
3. 완료 proof 키는 `mfa_verified={user_id,credential_stamp,verified_at,method:'totp'}`다. `mfa_mark_verified`를 완료 직후에만 호출한다. 비밀번호 변경 후 기존 proof는 무효이며 다시 로그인해야 한다.
4. `current_user_id()`를 직접 인증 근거로 쓰는 별도 호출자가 생기지 않도록 확인한다. 현재 앱의 웹 보호 경로는 bootstrap `user()`와 `login_required()`를 쓴다.

감사 이벤트는 `mfa_challenge`와 `mfa_verify`. reason은 password_verified / configuration_unavailable / csrf_rejected / invalid_or_used / expired / session_mismatch / account_changed / attempt_limit / invalid_otp / otp_reused / verified 등 코드에 고정된 값만 쓴다. 토큰·OTP·secret을 audit에 전달하지 않는다. 탐지 룰은 사용자 후속 지시에 따라 이번 범위에서 제외한다.

## 검증

PHP가 있는 환경에서 `php tests/mfa_domain.php`는 DB·HTTP 없이 RFC 6238 공개 벡터, TTL·세션·challenge 소비·다른 세션의 OTP 재사용 거부·계정 변경·시도 제한·replay 저장 오류를 검사한다. 임시 replay 파일만 만들고 제거한다. 2026-11-03 격리 환경의 PHP에서 38개 검사와 HTTP 정상·거부 사례를 통과했다. 실제 적용 전 PHP 문법 검사와 이 검사, 보호 경로·CSRF·로그인·기존 회원 기능의 격리 통합 검증이 필요하다. 설치·서비스 기동·대상 요청은 수행하지 않았다.

## 2026-11-03 보완과 통합 순서

- MFA 활성 시 생성된 pending 상태가 남아 있는 채 비활성으로 전환하고 로그인하면 기존 current_user_id()가 계속 미인증으로 취급하는 결함을 수정했다. 비활성 로그인은 `mfa_password_only_session()`을 통해 pending/proof를 제거한다. 이 함수는 MFA가 켜져 있으면 사용 자체를 거부한다.
- 같은 Base32 secret을 소문자로 표기해도 기존 OTP 재사용 기록을 공유하도록 키를 정규화했다. 잘못된 pending 구조는 고정 사유로 거부하고, 완료 proof는 정식 user_id와 일치하며 pending이 없을 때만 인정한다.
- 현재 Victim compose.yaml은 MFA 환경 변수를 web 컨테이너에 전달하지 않는다. `.env`에 추가하는 것만으로 활성화되지 않으며 `config/compose.mfa.example.yaml`을 기본 compose와 함께 적용하거나 기본 web.environment에 같은 항목을 넣어야 한다. 이 예시는 storage 볼륨을 기존 compose에서 상속한다.
- `scripts/setup.py`는 DB 환경 파일과 기존 저장소 폴더만 준비한다. MFA 등록 secret이나 인증 앱 설정을 만들지 않는다. 담당자가 계정별 secret을 `storage/private/mfa-secrets.json` 등에 별도 준비하고 PHP worker만 읽을 수 있도록 권한을 정해야 한다. 기존 계정의 등록이 완료되기 전에는 MFA를 켜지 않는다.
- 실제 통합 시 login.php와 모듈을 함께 갱신한다. user()/current_user_id() 보호 후크와 password-change의 재로그인 동작, 정상·실패·다른 세션·재사용·직접 보호 경로 접근, 감사 로그에 비밀값이 없는지를 격리 검증한다. 실제 DB migration은 MFA 자체에는 필요 없다.

추가 회귀: 비활성 모드 전환, 활성 모드에서 password-only helper 거부, Base32 대소문자와 OTP 재사용, 잘못된 pending 구조, 완료 proof와 pending의 혼재. 2026-11-03 이 에이전트에서 호스트 PHP가 없고 Docker 소켓도 접근 거부여서 실행하지 못했다. 검증되지 않은 상태를 통과로 표시하지 않는다.
