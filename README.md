# dah-sentinel-content

Microsoft Sentinel **Detection-as-Code** 저장소.
워크스페이스 `dah-data-law` (RG `dah-data-rg`, koreacentral) 의 모든 SOC 콘텐츠를 GitOps로 관리한다.

> **워크스페이스**: `dah-data-law` (customerId `71a8f26e-2f37-4dc7-a172-dfb0df11d74a`)
> **데이터 소스 저장소**: [`s1ns3nz0/uav-sim-env`](https://github.com/s1ns3nz0/uav-sim-env)
> **테이블 스키마 (필수 참조)**: [`uav-sim-env/docs/sentinel-schemas.md`](https://github.com/s1ns3nz0/uav-sim-env/blob/main/docs/sentinel-schemas.md)

---

## 디렉토리 구조

| 폴더 | 용도 |
|---|---|
| `AnalyticsRules/`   | Scheduled / NRT / Microsoft Security 룰 (탐지) |
| `HuntingQueries/`   | 능동 헌팅 KQL (수동 또는 부분 자동) |
| `Workbooks/`        | 시각화 대시보드 (JSON) |
| `Playbooks/`        | Logic Apps 자동 대응 (ARM 템플릿) |
| `Parsers/`          | KQL `function` 정의 (saved searches) |
| `Watchlists/`       | 룩업 데이터 (csv) |
| `AutomationRules/`  | 인시던트 트리거 룰 |

Sentinel 저장소 커넥터는 `main` 브랜치 push 시 위 폴더를 자동 동기화한다.

---

## Sentinel 측 연동 (GitOps)

Azure Portal에서:

1. `dah-data-law` 워크스페이스 → **Sentinel** → **Configuration → Repositories**
2. **Add new** → GitHub
3. 저장소: `s1ns3nz0/dah-sentinel-content`
4. 브랜치: `main`
5. **Smart deployment** = ON (수정된 파일만)
6. 부여할 콘텐츠 종류 선택 (전부 ON)

→ GitHub Actions workflow 자동 생성 (`.github/workflows/sentinel-deploy-*.yml`).
이후 `main` push 마다 자동 배포.

---

## 브랜치 전략

GitHub Flow 변형. **`main`은 항상 배포 가능 상태**.

### 브랜치 종류

| 브랜치 | 용도 | 수명 |
|---|---|---|
| `main` | 프로덕션 — Sentinel에 자동 배포되는 단일 트렁크 | 영구 |
| `feat/<scenario>-<short>` | 새 룰 / 헌팅 쿼리 / 워크북 추가 | PR 머지 후 삭제 |
| `fix/<rule-id>` | 기존 룰 false positive / 임계 조정 | PR 머지 후 삭제 |
| `chore/<task>` | 디렉토리 정리, 템플릿 갱신 등 | PR 머지 후 삭제 |
| `hotfix/<scenario>` | 운영 중 긴급 룰 비활성/수정 | 빠른 머지 |

### 브랜치 이름 예시

- `feat/S1-gnss-spoof-ekf-residual`
- `feat/A4-mavlink-cmd-injection`
- `fix/dah-S4-1-lower-threshold`
- `chore/update-watchlist-operators`
- `hotfix/S1-disable-during-maintenance`

### 워크플로우

```
main (보호됨)
  ├─ feat/S1-gnss-spoof   ←  김수지 작업 시작
  │     │
  │     │  commit, commit, commit
  │     │
  │     └── PR open  →  양진수/황준식 리뷰  →  squash & merge
  │
  └─ (main 갱신)  →  Sentinel auto deploy
```

### 보호 규칙 (포털에서 설정)

`main` 브랜치:
- ✅ Require pull request before merging
- ✅ Require approvals: **1명** (작은 팀이라 1)
- ✅ Dismiss stale reviews on new commits
- ✅ Require status checks (Sentinel deploy preview)
- ✅ Linear history (squash 또는 rebase only)
- ❌ Allow force push (절대 금지)
- ❌ Allow deletion (절대 금지)

> Repo Settings → Branches → Add rule → branch name pattern `main`

### 머지 정책

- **Squash and merge** 기본 — 깨끗한 main 히스토리
- 머지 메시지 = PR 제목 (Conventional Commits 양식 유지)
- 머지 후 feature 브랜치 자동 삭제 (Repo Settings → "Automatically delete head branches")

---

## Commit 메시지 양식

[Conventional Commits 1.0](https://www.conventionalcommits.org/ko/v1.0.0/) 준수.

### 형식

```
<type>(<scope>): <subject>

<body>

<footer>
```

### type

| type | 의미 |
|---|---|
| `feat` | 새 룰 / 새 헌팅 쿼리 / 새 워크북 추가 |
| `fix` | 기존 룰 임계·KQL·entity 매핑 수정 (FP/FN) |
| `tune` | 임계값만 변경 (룰 로직 동일) |
| `chore` | 디렉토리/템플릿/문서 외 정리 |
| `docs` | README / 가이드 갱신 |
| `refactor` | KQL 리팩토링 (동작 동등) |
| `test` | 룰 검증 시나리오 추가 |
| `ci` | `.github/workflows/` 변경 |
| `revert` | 직전 커밋 되돌림 |

### scope

시나리오 코드 + 룰 영역. 자주 쓰는 값:

| scope | 의미 |
|---|---|
| `S1` `S3` `S4` | 노션 시나리오 코드 |
| `A4` | MAVLink 인젝션 |
| `IT` | Insider Threat |
| `JAM` | 재밍 |
| `OP` | Operator (인증/세션) |
| `OSCAL` | 컴플라이언스 증거 |
| `hunting` | 헌팅 쿼리 작업 |
| `workbook` | 워크북 |
| `playbook` | 자동대응 |
| `watchlist` | 룩업 데이터 |
| `parser` | KQL function |
| `template` | 템플릿 디렉토리 |

### subject

- 명령형 + 한국어 OK
- 50자 이내 권장, 최대 72자
- 마침표 X

### body (선택)

- "왜" 위주. 코드 변화는 diff로 보임
- 룰 임계는 어떤 데이터/실험 근거인지
- false positive 사례 인용
- 줄당 72자 이내

### footer

| 키 | 의미 |
|---|---|
| `Refs: #N` | 이슈 / Notion 페이지 링크 |
| `Tested-by:` | 김동언 등 검증자 |
| `Reviewed-by:` | 리뷰어 |
| `BREAKING CHANGE:` | 룰 ID/스키마 변경 |

### 예시

```
feat(S1): GNSS 스푸핑 EKF 잔차 급증 탐지 룰 추가

UAVTelemetry_CL의 EKF_STATUS_REPORT 메시지에서 PosHorizVariance 또는
VelocityVariance가 0.5를 초과하면 5분 윈도우로 알람.

임계 0.5는 SITL 정상 비행 P99 (0.02) 대비 25배 → 보수적 시작값.
김동언이 GPS 스푸핑 공격 발생시키면 0.6~1.2까지 튐 확인 후 조정 가능.

Refs: notion/SOC-S1
Tested-by: 김동언
```

```
fix(A4): MAVLink ARM 인젝션 룰의 SourceSystemId 비교 오류 수정

ActionName 필터에서 ack_arm_disarm까지 포함되어 차량 응답도 알람으로
잡히던 FP. ack_* prefix 제외 조건 추가.

Refs: incident-2026-06-20
```

```
tune(S4): preflight 실패 임계를 5분 3회 → 2회로 강화

실제 공격자 시도 패턴 관찰 결과 3회 이전에 패턴 완성됨.
```

```
chore(template): scheduled rule 템플릿에 entityMappings 추가

룰 작성자가 매번 깜빡하는 entityMappings 필드를 템플릿에 포함.
```

### PR 제목 = squash 머지 후 main 커밋 메시지

PR 제목도 동일 양식. 머지 시 squash 메시지로 사용됨.

---

## 룰 작성 컨벤션

- 파일 이름: `<scenario-id>-<short-name>.yaml`
  - 예: `S1-gnss-spoof-ekf-residual.yaml`, `S4-firmware-signature-mismatch.yaml`
- 룰 ID: `dah-<scenario>-<n>` (UUID 대신 사람-친화 ID)
- `displayName`: 한국어 + 시나리오 코드. 예: `[S1] GNSS 스푸핑 — EKF 잔차 급증`
- `tactics` / `techniques`: MITRE ATT&CK 또는 MITRE FiGHT 매핑 명시
- `severity`: Low / Medium / High / Informational
- `query`: 단일 KQL. `lookbackPeriod` `queryFrequency` 명시.

샘플 룰 한 개를 `AnalyticsRules/_template/` 에 두고 시작.

---

## 시나리오 ↔ 우선 룰

| 시나리오 | 입력 테이블 (uav-sim-env) | 룰 파일 |
|---|---|---|
| **S1 GNSS 스푸핑** | `UAVTelemetry_CL` EKF_STATUS_REPORT | `AnalyticsRules/S1-gnss-spoof-ekf-residual.yaml` |
| **S3 SATCOM MITM** | (Phase 2 — BVLOS 추가 후) | — |
| **S4 펌웨어/공급망** | `UAVPgse_CL`, `UAVServiceAudit_CL` | `AnalyticsRules/S4-firmware-signature-mismatch.yaml` |
| **A4 MAVLink 인젝션** | `UAVOperator_CL`, `UAVDatalinkConn_CL` | `AnalyticsRules/A4-unauthorized-mavlink-command.yaml` |
| **인사이드 위협 (2PR)** | `UAVMissionPlan_CL`, `UAVWeapon_CL` | `AnalyticsRules/IT-two-person-rule-violation.yaml` |
| **재밍 (링크 열화)** | `UAVDatalink_CL` | `AnalyticsRules/JAM-packet-drop-spike.yaml` |
| **세션 도용** | `UAVOpAudit_CL` | `AnalyticsRules/OP-session-ip-mismatch.yaml` |
| **태세 기반 동적 임계** | (모든 표) | `AnalyticsRules/_template/posture-aware-rule.yaml` |

---

## 작성자 분담

- **김수지**: AnalyticsRules / HuntingQueries / Watchlists
- **양진수**: Playbooks (인시던트 → ServiceNow 비슷한 자동화), Workbooks (OSCAL 증거 시각화)
- **황준식**: pollack-ai 에이전트가 받는 인시던트 흐름 검증
- **김동언**: Red team이 발생시킨 이벤트로 룰 동작 검증

---

## 참조

- [Microsoft Sentinel Repositories docs](https://learn.microsoft.com/azure/sentinel/ci-cd)
- [pySigma → KQL 변환기](https://github.com/SigmaHQ/pySigma)
- [Azure-Sentinel community repo](https://github.com/Azure/Azure-Sentinel) — Microsoft 공식 콘텐츠 (참고용)
- [uav-sim-env Sentinel 스키마 cheat sheet](https://github.com/s1ns3nz0/uav-sim-env/blob/main/docs/sentinel-schemas.md)
