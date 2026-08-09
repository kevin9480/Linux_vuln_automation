import sys
import subprocess
import json
import shutil
from pathlib import Path
from datetime import datetime


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_TEMPLATES_DIR = SCRIPT_DIR.parent / "nuclei-templates"

def emit_json(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False))


def emit_scan_meta(code: str, item: str, severity: str, status: str, reason: str, **extra) -> None:
    payload = {
        "source": "nuclei",
        "record_type": "scan_meta",
        "code": code,
        "item": item,
        "severity": severity,
        "status": status,
        "reason": reason,
    }
    payload.update(extra)
    emit_json(payload)


def count_template_files(template_root: Path) -> int:
    if not template_root.exists():
        return 0
    return sum(1 for p in template_root.rglob("*") if p.suffix in {".yaml", ".yml"})


def run_nuclei(target_ip, templates_dir: Path):
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        raise RuntimeError("Nuclei not found in PATH")

    cmd = [
        nuclei_path,
        "-u", target_ip,
        "-t", str(templates_dir),
        "-j",
        "-silent",
        "-rate-limit", "50",
        "-timeout", "10"
    ]

    findings = []
    error_message = ""

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore"
        ) as process:

            for line in process.stdout:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            process.wait()

            if process.returncode != 0:
                error_output = process.stderr.read().strip()
                if error_output:
                    error_message = error_output
                else:
                    error_message = f"nuclei exited with non-zero code: {process.returncode}"

        return findings, error_message

    except Exception as e:
        return [], str(e)

def map_severity(nuclei_severity):
    """
    뉴클리 심각도 -> 대시보드 심각도로 매핑(상,중,하)
    """
    s = nuclei_severity.lower()
    if s in ["critical", "high"]:
        return "상"
    elif s in ["medium"]:
        return "중"
    else:
        # low, info, unknown
        return "하"

def main():
    if len(sys.argv) < 2:
        print("Usage: python nuclei_check.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    templates_dir = DEFAULT_TEMPLATES_DIR
    if len(sys.argv) >= 3:
        templates_dir = Path(sys.argv[2]).expanduser().resolve()

    started_at = datetime.now()
    template_count = count_template_files(templates_dir)

    if not templates_dir.exists():
        emit_scan_meta(
            code="NUC-ERR-TEMPLATES",
            item="Nuclei 템플릿 경로 확인",
            severity="하",
            status="점검불가",
            reason=f"템플릿 경로가 존재하지 않습니다: {templates_dir}",
            templates_dir=str(templates_dir),
            templates_count=0,
            target=target_ip,
        )
        sys.exit(1)

    nuclei_results, run_error = run_nuclei(target_ip, templates_dir)

    if run_error:
        finished_at = datetime.now()
        emit_scan_meta(
            code="NUC-ERR-RUN",
            item="Nuclei 실행 실패",
            severity="하",
            status="점검불가",
            reason=run_error,
            templates_dir=str(templates_dir),
            templates_count=template_count,
            target=target_ip,
            started_at=started_at.isoformat(),
            finished_at=finished_at.isoformat(),
            duration_sec=round((finished_at - started_at).total_seconds(), 2),
        )
        return

    if not nuclei_results:
        finished_at = datetime.now()
        emit_scan_meta(
            code="NUC-NO-FINDING",
            item="Nuclei 탐지 결과",
            severity="하",
            status="양호",
            reason="탐지된 취약점이 없습니다.",
            templates_dir=str(templates_dir),
            templates_count=template_count,
            target=target_ip,
            started_at=started_at.isoformat(),
            finished_at=finished_at.isoformat(),
            duration_sec=round((finished_at - started_at).total_seconds(), 2),
        )
        return

    finding_count = 0
    for res in nuclei_results:
        template_id = res.get("template-id", "NUCLEI-UNKNOWN")
        info = res.get("info", {}) #Nuclei 결과 json의 메타데이터 객체
        #객체1)
        name = info.get("name", template_id)
        #객체2)
        severity_raw = info.get("severity", "info")
        severity = map_severity(severity_raw)

        matcher_name = res.get("matcher-name", "")
        #객체3)
        classification = info.get("classification", {})
        cve_list = classification.get("cve-id", [])
        cvss_score = classification.get("cvss-score", "N/A")

        # CVE 우선 사용
        if cve_list:
            code = cve_list[0]
        else:
            code = f"NUC-{template_id.upper()}"

        reason = f"Nuclei Detection: {name}"
        if matcher_name:
            reason += f" ({matcher_name})"

        output = {
            "source": "nuclei",
            "record_type": "finding",
            "code": code,
            "item": name,
            "severity": severity,
            "severity_raw": severity_raw,
            "cvss_score": cvss_score,
            "status": "취약",
            "reason": reason,
            "template_id": template_id,
            "template_path": res.get("template-path", ""),
            "matched_at": res.get("matched-at", "")
        }
        finding_count += 1
        emit_json(output)

    finished_at = datetime.now()
    emit_scan_meta(
        code="NUC-SCAN-END",
        item="Nuclei 템플릿 스캔 완료",
        severity="하",
        status="정보",
        reason=f"총 {finding_count}건의 탐지가 발생했습니다.",
        templates_dir=str(templates_dir),
        templates_count=template_count,
        finding_count=finding_count,
        target=target_ip,
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        duration_sec=round((finished_at - started_at).total_seconds(), 2),
    )

if __name__ == "__main__":
    main()
