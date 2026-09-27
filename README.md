# passive-scan_v9_pub

수집량보다 **근거 보존 · 변경 탐지 · 다음 수동 점검**에 초점을 맞춘 웹 정찰 도구입니다.
v8(`ohjun1998/passive-scan_v8_pub`, 검토 커밋 `56fe674`)의 데이터 전달 문제를 바탕으로
파이프라인을 Python/SQLite 중심으로 재구성했습니다. 기존 v8 저장소를 변경하지 않습니다.

## 빠른 시작

Python 3.10 이상에서 저장소 루트에서 실행합니다.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp config.example.json config.json
# config.json의 scope를 본인 점검 대상에 맞게 수정
python -m recon run --mode offline --import urls:examples/urls.txt
```

결과: `reports/index.html`, `report.xlsx`, `report.json`, `postman.json`.
원본 이력: `state/recon.db`. 보고서를 다시 만들어도 검토 상태는 DB에 남습니다.
CLI 공통 옵션 `--config`, `--state`, `--output`은 `run`/`report`/`review` 앞에 둡니다.

## 실행 모드

| 모드 | 동작 | 외부 요청 |
|---|---|---|
| `offline` | 로컬 파일 가져오기, 분류, 리포트 | 없음. 단, `--ai`를 명시하면 AI 요청 발생 |
| `collect` | Subfinder, GAU, Waybackurls | 외부 데이터 제공자 요청; 대상 프로빙 없음 |
| `probe` | 범위 내 HTML 링크 수집, JS 버전 분석, GET 응답 확인 | 대상 요청 발생 |
| `browser` | probe + 제한된 Chromium 스크린샷 | 대상 요청 발생; 모든 HTTP 요청에 동일 예산 적용 |

```bash
# Go 도구 설치(첫 실행 버전 해석, 이후 state/tools.lock.json 버전 재사용)
bash scripts/install_tools.sh
export PATH="$(go env GOPATH)/bin:$HOME/.local/bin:$PATH"

# JS 비밀정보 탐지기를 사용할 경우: Linux amd64용 공식 릴리스/체크섬 검증
bash scripts/install_trufflehog.sh

python -m recon run --mode collect
python -m recon run --mode probe --collect

# 브라우저 기능은 별도 설치
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
python -m recon run --mode browser --collect
```

스캔 대상은 코드에 하드코딩하지 않습니다. `*.example.com`은 하위 호스트만 허용합니다.
apex도 포함하려면 `example.com`을 별도로 지정하세요. 외부 리다이렉트는 자동 추적하지 않습니다.
POST/PATCH 등 가져온 요청은 보관·내보내기만 하며 자동 실행하지 않습니다.

## v8 문제에 대한 대응

| v8에서 확인한 문제 | v9 구현 |
|---|---|
| Katana 결과가 후속 프로빙에서 누락 | `--katana` 및 v8 폴더 가져오기에서 공통 엔드포인트 DB로 통합 |
| 서로 다른 API가 디렉터리 기준으로 합쳐지고 5개 이후 삭제 | 원본 URL·메서드별 보존, 전체 경로 패턴은 별도 컬럼 |
| JS basename 충돌, 쿼리 제거 | URL SHA-256 + 콘텐츠 SHA-256 파일명, 쿼리 보존 |
| 비밀정보를 URL로 취급 | `findings` 테이블로 분리, 마스킹/HMAC 지문만 기록 |
| 실패와 미점검을 Dead로 표시 | not_probed / excluded / deferred / timeout / dns_error / tls_error / observed 등 구분 |
| 이력 텍스트와 DB가 연결되지 않음 | 단일 SQLite 상태 + 암호화 상태 복원 |
| 다운로드 성공을 분석 완료로 간주 | 다운로드·분석 완료 상태 분리, 분석 실패 시 다음 실행 재시도 |
| URL만 보고 AI 취약점 확률 부여 | 로컬 규칙 점수 + 선택적 AI 수동 검토 가이드, 확률 표현 제거 |

## 입력 가져오기

```bash
python -m recon run --import har:traffic.har --import burp:history.xml
python -m recon run --import openapi:openapi.json
python -m recon run --import urls:urls.txt
python -m recon run --import v8:old_results
python -m recon run --katana katana.jsonl
```

- HAR: 메서드, 쿼리·본문 필드 이름, 인증 헤더 존재 여부, 응답 JSON 필드 이름.
- Burp: HTTP history에서 XML로 저장한 요청. base64 포함/미포함 지원.
- OpenAPI 3: 절대 server URL, 경로/메서드/직접 선언 파라미터·본문 필드.
- Katana: plain URL 또는 JSONL의 `request.endpoint`/`request.method`.
- v8 폴더: GAU·Waybackurls·Katana 텍스트만 가져옵니다. 원본 JS URL 매핑이 없는 LinkFinder와
  비밀값 텍스트는 잘못된 URL로 복원하지 않습니다. v8 DB를 자동 덮어쓰거나 이전하지 않습니다.

실제 요청 본문·쿠키·인증 헤더 값은 가져오지 않습니다. URL 원본은 로컬 DB에 보존되므로
쿼리에 민감값이 있을 수 있습니다. 공유 리포트에서는 알려진 민감 쿼리 키를 마스킹하지만,
모든 임의 경로의 개인정보까지 자동 식별하는 것은 아닙니다.

## JS와 변경 이력

동일 JS URL이라도 콘텐츠 해시가 바뀌면 재분석합니다. ETag/Last-Modified가 있으면
조건부 요청을 사용합니다. JS 원본은 `state/js/`에 남아 조사 근거로 사용할 수 있습니다.
다운로드 응답이 HTML이거나 제한 크기를 넘으면 분석하지 않습니다.

상대 `fetch()` 경로는 JS 파일 디렉터리가 아니라 발견 HTML 페이지의 base URL을 이용합니다.
페이지 문맥이 없는 상대 경로는 강제로 절대 URL로 만들지 않습니다. `/api/...`는 JS origin 기반
**후보**이며 실제 API base URL이 다를 수 있음을 기록합니다.

상태 코드·본문 지문·제목·Content-Type·Location·Server 변화가 `changes`에 남습니다.
일반 프로빙에서 상태 코드 변화는 예산이 남아 있으면 한 번 재확인하고 `confirmed`에 표시합니다.
크롤러 관찰 변화·본문 변화는 확인되지 않은 변경으로 남습니다. 관찰되지 않았다고 삭제로 판정하지 않습니다.
응답 군집은 공백을 정규화한 정확 해시 기반입니다. 동적 nonce 제거·유사도 군집은 포함하지 않습니다.

## 수동 점검과 Postman

```bash
python -m recon review ENDPOINT_ID --status investigating --owner analyst --note '계정 간 소유권 확인 필요'
python -m recon report
```

리포트의 ID를 사용합니다. 상태는 `unreviewed`, `investigating`, `false_positive`, `reported`.
Postman은 실제로 관찰/선언된 메서드만 내보냅니다. UNKNOWN 메서드는 목록에는 남지만
GET으로 추정해 내보내지 않습니다. 본문 값은 placeholder이며 중첩 구조는 평탄한 필드로
표시되므로 실제 요청은 사용자가 조립해야 합니다. 자동 로그인·계정 전환·권한 우회는 실행하지 않습니다.

## AI 분석

기본값은 외부 AI 전송 없이 규칙 기반 우선순위를 계산합니다.
외부 분석을 원하면 `config.json`의 `ai.model`에 사용 가능한 Gemini 모델을 지정하고:

```bash
export GEMINI_API_KEY='본인의 키'
python -m recon run --mode offline --import har:traffic.har --ai
```

도메인·쿼리 값·원문 응답·쿠키·비밀값·메모를 제외하고 ID, 경로 패턴, 메서드, 상태, 기능 태그만
전송합니다. 경로 자체에 민감정보가 있을 수 있으므로 대상 정책에 맞게 사용하세요.
모델의 반환 ID·점수·필드 타입을 검증해 `reports/ai_review.json`에 저장합니다.
AI 판단은 취약점 확정이 아닙니다. 모델을 자동 변경하지 않습니다.

## GitHub Actions

새 저장소에 코드 업로드 시 `ci.yml`은 오프라인 회귀 테스트만 실행합니다.
`scan.yml`은 **수동 실행 전용**이며 자동 스케줄을 등록하지 않습니다.

Repository Settings → Secrets and variables → Actions:

| Secret | 내용 |
|---|---|
| `RECON_CONFIG` | 본인 범위로 수정한 config.json 전체 |
| `REPORT_PASSWORD` | 상태와 리포트 GPG 암호화 비밀번호 |
| `DISCORD_WEBHOOK_URL` | 알림을 선택했을 때만 필요 |

`Recon v9` → Run workflow → mode 선택. 동일 브랜치 동시 실행은 직렬화합니다.
고정 20노드 대신 하나의 요청 조정기를 사용해 호스트별 합산 예산을 적용합니다.
이 버전은 대규모 분산 실행보다 데이터 정확성과 부하 통제를 우선합니다.

상태는 암호화한 Actions cache로 이어집니다. cache가 삭제/만료되면 누적 이력이 초기화될 수 있으므로
완료 시 함께 업로드하는 `state.tar.gz.gpg`를 보관하세요. artifact 보존 기간은 30일입니다.
암호를 바꿀 때는 기존 암호화 상태를 이전 암호로 복호화한 뒤 다시 암호화해야 합니다.

```bash
# 다운로드한 리포트 복호화: gpg가 비밀번호를 물어봅니다.
gpg --output reports.tar.gz --decrypt reports.tar.gz.gpg
tar -xzf reports.tar.gz
```

도구 설치 실패는 workflow 실패로 표시하고, 파이프라인 중 선택적 도구 누락/실패는 `partial`과
Pipeline 시트에 남깁니다. 비밀정보 검증은 기본 비활성입니다. `--verify-secrets`는 공급자 API에
별도 요청하며 대상 호스트 예산 밖에서 실행됩니다. workflow에서는 이 옵션을 사용하지 않습니다.
Discord에는 개수 요약만 보내며 URL·비밀정보·첨부파일은 전송하지 않습니다.

## 설치·검증 범위와 한계

```bash
python -m unittest discover -s tests -v
python -m compileall -q recon scripts
bash -n scripts/*.sh
```

테스트는 로컬 fixture, mock, loopback HTTP 서버만 사용합니다. 실제 외부 대상 스캔,
로그인 세션, 외부 도구 전체 설치, Gemini API, Chromium 및 GitHub Actions 실행은 별도 환경 검증이 필요합니다.
Go 도구는 첫 설치에 현재 버전을 해석한 뒤 잠급니다. 엄격한 재현성이 필요하면 검토한
`state/tools.lock.json`을 유지하세요. Python·브라우저·TruffleHog는 명시 버전이며 최신성 보장은 아닙니다.

OpenAPI 외부 `$ref`와 완전한 JSON Schema 해석, JS 런타임 데이터 흐름 추적, 자동 계정 간 권한 검증,
실시간 기술 스택 DB, 검색엔진 Dorking/Wayback 최초 발견일 조회는 이 릴리스에 포함하지 않았습니다.
브라우저는 GET·스코프·예산 제한과 쿠키 제거 때문에 로그인/외부 CDN 의존 화면이 불완전할 수 있습니다.
완전한 페이지 재현과 정확한 인가 검토에는 가져온 실제 요청을 함께 사용하세요.

## 새 GitHub 저장소 게시

GitHub CLI 로그인 후 저장소 루트에서:

```bash
bash scripts/publish.sh
```

`ohjun1998/passive-scan_v9_pub` 공개 저장소를 만들고 코드를 push합니다. 기존 저장소를 덮어쓰지 않습니다.
이미 같은 이름의 저장소가 있으면 스크립트가 중단됩니다. 대상 데이터·DB·설정·키는 `.gitignore`로 제외됩니다.
