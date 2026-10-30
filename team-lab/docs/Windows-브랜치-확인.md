# Windows에서 로컬 수정 브랜치 확인

이 브랜치는 저장·종결 보완과 팀 준비 자료를 공유하는 실험본이다. main과 별개이며 안정판·완성된 자율 진단으로 취급하지 않는다.

## 가져오기

처음 가져오는 경우 PowerShell에서:

```powershell
git clone --branch codex/artex-local-repairs https://github.com/SSLC-FiveEyes/artex-global.git
cd artex-global
```

이미 복사한 저장소에서는 로컬 변경을 먼저 확인한 뒤:

```powershell
git status
git fetch origin
git switch --track origin/codex/artex-local-repairs
```

이미 같은 브랜치를 만든 경우에는 해당 브랜치로 이동한 뒤 `git pull --ff-only`를 사용한다. 기존 로컬 변경을 강제로 덮어쓰지 않는다.

## 포함 범위와 알려진 문제

- 저장을 하지 않고 끝내는 worker의 제한된 복구, 목표 증명 후 종료 처리.
- 실제 도구 실행 근거와 저장된 Markdown 보고서 확인.
- 팀 문서·설정 예시·시나리오 초안·검사 코드.
- 과거 블랙박스 전용 모드와 GET30 전용 모드는 제거됐다. 이전 표식으로 요청 제한이 강제되지 않는다.
- #35에서 복구 단계의 추가 요청 차단을 대상 서버 차단으로 오해했고, planner가 쓴 보고서와 worker 사실을 연결하지 못했다. 두 문제는 아직 남아 있다.
- 전체 DB 연결 검사는 수정 전에도 실패 항목이 있었다. 관련 검사14개 통과를 전체 검사 성공으로 확대하지 않는다.

## 수정 코드를 실행하려면

저장소를 받는 것만으로 기존 Docker 컨테이너가 수정되지는 않는다. 루트 `docker-compose.yml`은 기본적으로 이미 배포된 이미지를 가져온다. Mac의 `artex-local:cleanup-20261030-r1` 이미지는 이 저장소에 업로드되지 않는다.

Windows에서 직접 빌드하려면 `go.mod` 기준 Go 1.26.3과 프런트엔드 빌드용 Node/npm이 필요하다. PostgreSQL·Ollama·모델·실제 설정은 별도로 준비한다. 준비된 환경에서 PowerShell 빌드 명령은 다음과 같다.

```powershell
Push-Location web
npm ci --include=dev
npm run build:static
Pop-Location
New-Item -ItemType Directory -Force server/webui/dist | Out-Null
Copy-Item -Path web/out/* -Destination server/webui/dist -Recurse -Force
$env:CGO_ENABLED = "0"
go build -tags embedui -o artex.exe ./cmd/artex
```

새 빌드 전 `server/webui/dist`에 이전 프런트엔드 산출물이 있으면 따로 보관하거나 정리하여 오래된 파일이 섞이지 않게 한다. `embedui` 태그 없이 빌드하면 대시보드가 내장되지 않는다. 백엔드 설정·실행 절차는 루트 README.ko.md의 소스 빌드 안내를 따른다. 프로그램 실행은 설정 완료 후 `start.bat`를 사용한다.

이 안내의 PowerShell 명령을 실제 Windows에서 실행해 검증한 것은 아니다. 2026-10-30 Linux 컨테이너에서 `GOOS=windows GOARCH=amd64 CGO_ENABLED=0` 및 `-tags embedui`로 백엔드 교차 컴파일을 확인했다. 실제 Windows 실행·PowerShell 프런트엔드 빌드는 미검증이다.

## 포함되지 않는 항목

Mac의 인증정보·실사용 설정·DB·작업 이력·모델 가중치·Docker 이미지·응답 원본·백업은 전송되지 않는다. 예시 프로파일 일부는 초기 Qwen 후보를 담은 역사적 준비안이므로 현재 GPT-OSS 설정으로 오해하지 않는다. 대상의 `host.docker.internal:8088`은 실행 PC의 서비스 주소다. Windows에 대상을 옮기지 않았다면 같은 서비스가 자동으로 생기지 않는다.
