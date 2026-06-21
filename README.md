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
