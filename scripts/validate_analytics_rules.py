#!/usr/bin/env python3
"""Sentinel AnalyticsRules 스키마 사전검증 — advisory(비차단), 경량 자체기준.

실측으로 확정된 10가지 Sentinel ARM 스키마 규칙(S1~S126 재정렬 + S127~S129 저작 중
실제로 걸렸던 것들)을 새/변경 룰에 대해 사전 체크한다. GitHub Action 실배포(~40분) 전에
초 단위로 흔한 실수를 잡아낸다. 근거(ground truth)는 마이크로소프트 공식 스키마 문서가
아니라 **이미 성공적으로 배포된 나머지 룰들 자체**다 — 기존 룰들이 실제로 이 필드들을
어떻게 채웠는지 보고, 새 룰이 그 패턴에서 벗어나면 경고한다(self-referential validation).

10번째 규칙(S129 배포 실패로 발견, 2026-07): techniques[]/subTechniques[]는 Enterprise
ATT&CK ID(T1xxx)만 허용 — ICS 전용 ID(T0xxx)를 넣으면 "No valid tactic corresponding to
the technique..." BadRequest로 배포 자체가 실패한다. ICS ID는 description 텍스트로만
언급할 것(기존 158개 룰 전부 이 컨벤션을 따름).

주의: 이건 advisory(경고만, 머지 안 막음)다 — 새로 만든 검증기 자체가 아직 우리 데이터에
한 번도 안 돌려봤으니, 자기 오탐부터 확인하는 기간이 필요하다는 게 도입 결정 취지였다.
KQL 문법/의미론 자체는 검증하지 않는다(그건 az monitor log-analytics query 직접 실행이나
az rest PUT으로 확인 — README/CONTRIBUTING 참고).

실행: python scripts/validate_analytics_rules.py [--dir AnalyticsRules]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_TACTIC_RE = re.compile(r"^[A-Z][a-zA-Z]*$")
_TECHNIQUE_RE = re.compile(r"^(AML\.)?T\d{4}$")  # 상위 기법만(하위는 subTechniques 로).
_SUBTECHNIQUE_RE = re.compile(r"^(AML\.)?T\d{4}\.\d{3}$")
_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")
_MAX_CUSTOM_DETAIL_KEY = 20
_MAX_DESC_PLACEHOLDERS = 3
_MIN_ENTITY_MAPPINGS, _MAX_ENTITY_MAPPINGS = 1, 10


class Finding:
    def __init__(self, path: Path, rule: str, message: str) -> None:
        self.path = path
        self.rule = rule
        self.message = message

    def __str__(self) -> str:
        return f"[{self.rule}] {self.path.name}: {self.message}"


def _load(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data["resources"][0]["properties"]
    except (json.JSONDecodeError, KeyError, IndexError, OSError):
        return None


def _projected_columns(query: str) -> set[str]:
    """쿼리의 마지막 project 절에서 출력 컬럼(별칭 포함)을 best-effort 로 추출한다.

    완전한 KQL 파서가 아니다 — `| project X, Y = expr, ...` 형태의 마지막 project 절만
    본다. 실패해도(추출 0건) False Positive 방지를 위해 해당 검사(5/7)는 건너뛴다.
    """
    # project 절은 여러 줄에 걸칠 수 있음(DOTALL) — 다음 줄 시작 `|` 전까지 캡처.
    projects = re.findall(
        r"\|\s*project(?:-away|-keep|-rename)?\s+(.*?)(?=\n\s*\||\Z)", query, re.DOTALL
    )
    if not projects:
        return set()
    last = projects[-1]
    cols: set[str] = set()
    for part in last.split(","):
        part = part.strip()
        name = part.split("=")[0].strip() if "=" in part else part
        if name:
            cols.add(name)
    return cols


def build_known_good(rules_dir: Path) -> tuple[set[str], dict[str, set[str]]]:
    """기존 배포 룰 전체에서 known_techniques + technique->tactics 역맵을 구축한다."""
    known_techniques: set[str] = set()
    technique_tactics: dict[str, set[str]] = {}
    for path in sorted(rules_dir.glob("*.json")):
        props = _load(path)
        if not props:
            continue
        tactics = set(props.get("tactics") or [])
        for t in (props.get("techniques") or []):
            known_techniques.add(t)
            technique_tactics.setdefault(t, set()).update(tactics)
    return known_techniques, technique_tactics


def check_rule(
    path: Path, known_techniques: set[str], technique_tactics: dict[str, set[str]]
) -> list[Finding]:
    findings: list[Finding] = []
    props = _load(path)
    if props is None:
        findings.append(Finding(path, "parse", "JSON 파싱 실패 또는 예상 구조(resources[0].properties) 아님"))
        return findings

    tactics = props.get("tactics") or []
    techniques = props.get("techniques") or []
    sub_techniques = props.get("subTechniques") or []
    query = props.get("query", "")

    # 1. tactics PascalCase, 공백 없음.
    for t in tactics:
        if not _TACTIC_RE.match(t):
            findings.append(Finding(path, "tactic-format", f"tactics 값이 PascalCase 아님: {t!r}"))

    # 2. techniques 는 상위 기법만 — 하위(.NNN)는 subTechniques 로.
    # 2b. techniques/subTechniques 는 Enterprise ATT&CK(T1xxx)만 — ICS(T0xxx)는 Sentinel
    #     API가 거부한다(2026-07 S129 배포 실패로 실측). ICS ID는 description 텍스트로만.
    for t in techniques:
        if _SUBTECHNIQUE_RE.match(t):
            findings.append(
                Finding(path, "technique-parent-only", f"{t!r}는 하위기법 — subTechniques 로 옮길 것")
            )
        elif not _TECHNIQUE_RE.match(t):
            findings.append(Finding(path, "technique-format", f"techniques 형식 이상: {t!r}"))
        elif t.startswith("T0"):
            findings.append(
                Finding(path, "ics-technique-rejected",
                        f"{t!r}는 ICS 전용 ID — Sentinel techniques[] 필드는 Enterprise(T1xxx)만 허용"
                        "(배포 실패함, description 텍스트로만 언급할 것)")
            )
    for st in sub_techniques:
        if not _SUBTECHNIQUE_RE.match(st):
            findings.append(Finding(path, "subtechnique-format", f"subTechniques 형식 이상: {st!r}"))
        elif st.startswith("T0"):
            findings.append(
                Finding(path, "ics-technique-rejected",
                        f"{st!r}는 ICS 전용 ID — Sentinel subTechniques[] 필드는 Enterprise(T1xxx)만 허용")
            )

    # 3/4. 기존에 검증된 기법인지 + tactics 와 최소 1개 매칭되는지(과거 이력 기준).
    for t in techniques:
        if not _TECHNIQUE_RE.match(t):
            continue
        if t not in known_techniques:
            findings.append(
                Finding(path, "novel-technique", f"{t!r}는 기존 배포 룰에 없던 신규 기법 — 수동 확인 권장")
            )
            continue
        prior_tactics = technique_tactics.get(t, set())
        if prior_tactics and not (set(tactics) & prior_tactics):
            findings.append(
                Finding(
                    path, "tactic-technique-mismatch",
                    f"{t!r}는 기존엔 {sorted(prior_tactics)}와 짝지어졌는데 이 룰은 {tactics}",
                )
            )

    # 5/7. alertDetailsOverride / customDetails 값이 실제 project 컬럼과 일치하는지(best-effort).
    projected = _projected_columns(query)
    if projected:
        override = props.get("alertDetailsOverride") or {}
        for key, val in override.items():
            for ph in _PLACEHOLDER_RE.findall(str(val)):
                if ph not in projected:
                    findings.append(
                        Finding(path, "alert-details-placeholder",
                                f"alertDetailsOverride.{key} 의 {{{{{ph}}}}}가 project 컬럼에 없음")
                    )
        for key, val in (props.get("customDetails") or {}).items():
            if isinstance(val, str) and val not in projected:
                findings.append(
                    Finding(path, "custom-details-column", f"customDetails.{key} 값 {val!r}이 project 컬럼에 없음")
                )

    # 6. alertDescriptionFormat 플레이스홀더 최대 3개.
    fmt = props.get("alertDescriptionFormat")
    if isinstance(fmt, str):
        n = len(_PLACEHOLDER_RE.findall(fmt))
        if n > _MAX_DESC_PLACEHOLDERS:
            findings.append(
                Finding(path, "description-format-placeholders", f"플레이스홀더 {n}개(최대 {_MAX_DESC_PLACEHOLDERS})")
            )

    # 8. customDetails key 20자 이하.
    for key in (props.get("customDetails") or {}):
        if len(key) > _MAX_CUSTOM_DETAIL_KEY:
            findings.append(
                Finding(path, "custom-details-key-length", f"customDetails key {key!r} {len(key)}자(최대 {_MAX_CUSTOM_DETAIL_KEY})")
            )

    # 9. entityMappings 1~10개.
    em = props.get("entityMappings")
    if em is not None:
        n = len(em)
        if not (_MIN_ENTITY_MAPPINGS <= n <= _MAX_ENTITY_MAPPINGS):
            findings.append(
                Finding(path, "entity-mappings-count", f"entityMappings {n}개(허용 {_MIN_ENTITY_MAPPINGS}~{_MAX_ENTITY_MAPPINGS})")
            )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=Path("AnalyticsRules"))
    parser.add_argument(
        "--fail-on-findings", action="store_true",
        help="설정 시 findings 있으면 exit 1(기본은 advisory — 항상 exit 0)",
    )
    args = parser.parse_args()

    if not args.dir.is_dir():
        print(f"[경고] {args.dir} 없음 — 검사 스킵")
        return 0

    known_techniques, technique_tactics = build_known_good(args.dir)
    all_findings: list[Finding] = []
    for path in sorted(args.dir.glob("*.json")):
        all_findings.extend(check_rule(path, known_techniques, technique_tactics))

    if not all_findings:
        print(f"✅ {args.dir}: 전 규칙 통과(10종 자체기준 검사)")
        return 0

    print(f"⚠️  {args.dir}: {len(all_findings)}건 발견(advisory — 머지는 안 막음)\n")
    for f in all_findings:
        print(f"  {f}")

    return 1 if args.fail_on_findings else 0


if __name__ == "__main__":
    sys.exit(main())
