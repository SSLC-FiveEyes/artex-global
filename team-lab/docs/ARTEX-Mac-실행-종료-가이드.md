# ARTEX Mac 실행·종료 가이드

기준일: 2026-10-29 · Asia/Seoul

현재 Mac에 설치한 ARTEX를 직접 켜고 끄는 방법이다. 아래 명령은 Mac의 **터미널** 앱에서 실행한다. `⌘ + Space`를 누르고 ‘터미널’을 검색하면 된다.

## 1. 현재 구성

| 구성요소 | 실행 위치와 역할 |
| --- | --- |
| Docker Desktop | ARTEX와 PostgreSQL을 실행하는 앱 |
| ARTEX | Docker 프로젝트 `artex-team`의 웹 화면과 실행 도구 |
| PostgreSQL | 같은 프로젝트에서 대화·설정·작업 기록을 저장하는 DB |
| Ollama | Mac에서 직접 실행하는 로컬 모델 서버 |
| Qwen | Ollama가 불러오는 `Qwen3.5 9B Q4_K_M`, 문맥 32K 모델 |

- ARTEX 접속: <http://127.0.0.1:8787>
- 로그인 사용자 이름: `ARTEX`
- 로그인 정보 파일: `/Users/iseunghyeon/rookies_final/artex-global/team-lab/.secrets/artex-login.txt`
- Ollama 모델 별칭: `artex-qwen35-9b-q4km-32k-tools`
- ARTEX 배포 버전: `v0.3.15-global.1+completion.20261029.3` · 로컬 저장/종결 보완 이미지

비밀번호는 위 로컬 파일에서 확인한다. 이 문서에는 비밀번호·API 키·초기 설정 토큰을 적지 않는다.

**Docker의 ARTEX·DB와 Mac의 Ollama는 따로 켜고 끈다.**

## 2. 켜는 방법

### 2-1. Docker와 Ollama 앱 실행

터미널에 아래 명령을 붙여 넣는다.

```bash
open -a Docker
open -a Ollama
```

Docker Desktop의 엔진이 실행 준비를 마칠 때까지 기다린다. 앱 창이 열린 직후에는 준비 중일 수 있다.

### 2-2. ARTEX와 DB 실행

아래 블록 전체를 복사해 실행한다. 경로를 전부 적었으므로 터미널의 현재 폴더와 관계없이 사용할 수 있다.

```bash
docker compose \
  --env-file /Users/iseunghyeon/rookies_final/artex-global/team-lab/config/artex.mac.env \
  -f /Users/iseunghyeon/rookies_final/artex-global/team-lab/config/compose.mac.local.yaml \
  up -d --wait
```

이 명령은 PostgreSQL과 ARTEX를 실행하고 정상 상태를 기다린다. 이미 같은 설정으로 실행 중이면 그대로 유지한다. `-d`는 터미널을 닫아도 백그라운드에서 계속 실행한다는 뜻이다.

현재 구성은 위 로컬 Compose 파일과 환경 파일을 함께 사용한다. 루트 폴더에서 옵션 없이 `docker compose up`을 실행하면 다른 Compose 구성을 사용하므로, 이 문서의 명령을 그대로 사용한다.

### 2-3. 브라우저에서 접속

[ARTEX 열기](http://127.0.0.1:8787)

모델과 32K 설정은 저장돼 있다. Ollama가 실행 중이면 ARTEX의 첫 모델 요청 때 Qwen을 메모리에 불러온다. 한동안 사용하지 않아 모델이 메모리에서 해제돼도 다음 요청 때 다시 불러온다.

## 3. 끄는 방법

### 3-1. 진행 중인 작업과 대화 정리

1. ARTEX의 **작업** 메뉴에서 실행 중인 작업을 **일시정지**한다.
2. 대화가 응답 중이면 입력창 옆 **현재 실행 중지(■)** 버튼으로 해당 대화를 중지한다.
3. 작업과 대화의 실행 상태를 확인한 다음 서버를 끈다.

작업의 ‘일시정지’와 대화의 ‘현재 실행 중지’는 적용 범위가 다르다. **대화 중지만으로 작업 전체의 planner·worker가 멈추지는 않는다.**

ARTEX는 다시 시작할 때 저장된 미완료 작업을 복원한다. 작업을 일시정지하지 않고 서버만 끄면 다음 기동 때 작업이 이어질 수 있다. 시간 제한이 있는 작업은 일시정지 중에도 마감 시각이 지나갈 수 있으므로, 다시 켠 뒤 상태를 확인한다.

### 3-2. ARTEX와 DB 정지

```bash
docker compose \
  --env-file /Users/iseunghyeon/rookies_final/artex-global/team-lab/config/artex.mac.env \
  -f /Users/iseunghyeon/rookies_final/artex-global/team-lab/config/compose.mac.local.yaml \
  stop -t 30
```

`stop`은 컨테이너를 정지하고 대화·설정·DB 기록을 보존한다. `-t 30`은 종료를 위한 대기 시간을 최대 30초로 지정한다. 다음에 켤 때는 2절의 실행 명령을 다시 사용한다.

이 단계에서는 Docker Desktop과 Mac의 Ollama 앱이 계속 실행될 수 있다.

### 3-3. Mac 메모리도 확보하려면 앱 종료

ARTEX와 DB를 정지한 다음, 필요에 따라 앱을 종료한다.

- **Ollama:** Ollama 앱의 메뉴에서 **Quit Ollama / 종료**를 선택한다.
- **Docker Desktop:** Docker 메뉴에서 **Quit Docker Desktop**을 선택한다. 다른 Docker 프로젝트도 함께 종료된다.

브라우저 탭을 닫는 것만으로 ARTEX가 꺼지지는 않는다. Docker·Ollama도 창 닫기와 앱 종료를 구분한다.

두 컨테이너에는 `restart: unless-stopped`가 설정돼 있다. Docker 앱만 종료하면 다음 Docker 실행 때 컨테이너가 다시 켜질 수 있다. **꺼진 상태로 두려면 3-2의 정지를 먼저 실행한다.**

## 4. 실행 상태 확인

### ARTEX와 DB 상태

```bash
docker compose \
  --env-file /Users/iseunghyeon/rookies_final/artex-global/team-lab/config/artex.mac.env \
  -f /Users/iseunghyeon/rookies_final/artex-global/team-lab/config/compose.mac.local.yaml \
  ps -a
```

| 컨테이너 이름 | 정상 실행 시 확인할 표시 |
| --- | --- |
| `artex-team-artex-1` | `Up`, `healthy` |
| `artex-team-postgres-1` | `Up`, `healthy` |

`Exited`는 정지 상태다. 켠 직후 `health: starting`이 보이면 잠시 기다린 뒤 다시 확인한다.

### Ollama와 모델 상태

설치된 모델 목록:

```bash
ollama list
```

현재 메모리에 올라온 모델 목록:

```bash
ollama ps
```

`ollama ps`의 모델 목록이 비어 있어도 유휴 자동 해제 상태일 수 있다. 서버가 실행 중이면 다음 모델 요청 때 다시 불러온다. `could not connect` 같은 연결 오류가 나오면 Ollama 앱의 실행 상태를 확인한다.

모델 메모리만 비우고 Ollama 서버는 유지하고 싶다면, ARTEX의 실행 작업·대화를 먼저 정리한 뒤 다음 명령을 사용한다.

```bash
ollama stop artex-qwen35-9b-q4km-32k-tools
```

이 명령은 모델을 메모리에서 해제한다. 다운로드한 모델 파일은 유지되며 다음 요청 때 다시 로드된다.

## 5. Docker 화면의 버튼으로 제어

터미널 대신 Docker Desktop에서도 제어할 수 있다.

1. Docker Desktop을 열고 **Containers**로 이동한다.
2. 프로젝트 **`artex-team`**을 찾는다.
3. 프로젝트 행의 **시작(▶)** 또는 **정지(■)** 버튼을 사용한다.
4. 펼쳐서 ARTEX와 PostgreSQL 두 컨테이너의 상태를 확인한다.

프로젝트 전체를 제어하면 두 컨테이너를 함께 관리할 수 있다. 시작 순서와 정상 상태 대기는 2-2의 Compose 명령으로 확인하는 방법을 권장한다. Ollama 앱은 별도로 실행한다.

정지 전의 작업 일시정지는 **ARTEX 웹 화면**에서 한다. Docker 화면의 정지·일시정지 버튼은 ARTEX 작업의 일시정지 상태를 저장하는 기능이 아니다.

## 6. 자주 만나는 상황

| 상황 | 확인할 내용 |
| --- | --- |
| `Cannot connect to the Docker daemon` | Docker Desktop을 열고 엔진 준비가 끝난 뒤 다시 실행한다. |
| `docker: command not found` | 현재 Mac의 Docker 실행 파일은 `/Users/iseunghyeon/.docker/bin/docker`다. 명령 첫 단어 `docker`를 이 전체 경로로 바꿔 실행할 수 있다. |
| `ollama: command not found` | 현재 Mac의 Ollama 실행 파일은 `/opt/homebrew/bin/ollama`다. 명령 첫 단어 `ollama`를 이 전체 경로로 바꿀 수 있다. |
| 필수 환경 변수나 설정 파일 오류 | `--env-file`과 `-f` 경로를 포함한 전체 명령을 사용했는지 확인한다. 환경 파일은 Git에서 제외되므로 다른 컴퓨터에 저장소만 복사하면 생기지 않는다. |
| 브라우저에서 접속이 안 됨 | 4절에서 두 컨테이너 상태를 확인하고 <http://127.0.0.1:8787>로 접속한다. |
| 화면은 열리는데 모델이 응답하지 않음 | Ollama 앱 실행 여부와 ARTEX의 LLM 설정을 확인한다. 현재 모델 별칭은 `artex-qwen35-9b-q4km-32k-tools`다. |
| 첫 응답이 느림 | 모델 로드와 ARTEX 기본 지시문·도구 설명 처리 시간이 포함된다. 첫 인사 시험은 약 34초 걸렸으며, 모든 요청에 같은 시간이 걸린다는 뜻은 아니다. |
| 껐다 켠 뒤 작업이 이어짐 | 서버 종료 전에 해당 작업을 일시정지했는지 확인한다. |

## 7. 기록을 보존하는 운영 기준

- 평소 종료에는 이 문서의 `stop` 명령을 사용한다.
- 대화·설정·작업 기록은 DB 볼륨 `artex-team_pgdata`, 파일 데이터는 `artex-team_appdata`에 보관한다.
- `down -v`나 Docker의 볼륨 삭제는 기록을 지울 수 있으므로 일상적인 종료에 사용하지 않는다.
- 정지는 백업과 다르다. 별도 백업·복구 절차는 아직 검증하지 않았다.

## 8. 근거와 확인 범위

현재 로컬 Compose·설치된 CLI 도움말·ARTEX의 작업 복원 코드를 기준으로 작성했다. 기존 구축과 연결 확인 결과를 반영했으며, 이 문서를 작성하면서 서비스를 실제로 정지하거나 재기동하지 않았다.

- [로컬 실행 Compose](/Users/iseunghyeon/rookies_final/artex-global/team-lab/config/compose.mac.local.yaml)
- [팀 자료 시작점](/Users/iseunghyeon/rookies_final/artex-global/team-lab/README.md)
- [Docker Compose stop 공식 문서](https://docs.docker.com/reference/cli/docker/compose/stop/)
- [Docker Desktop Containers 공식 안내](https://docs.docker.com/desktop/use-desktop/container/)
- [Ollama FAQ: 모델 로드 상태와 메모리 유지](https://docs.ollama.com/faq)
