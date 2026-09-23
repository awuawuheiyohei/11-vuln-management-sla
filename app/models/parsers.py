"""
Vulnerability Scanner Parsers — 归一化为 NormalizedVulnerability
- Trivy JSON
- Nessus JSON
- Generic (CIS-style)
"""
import re
import json
import hashlib
from typing import List, Dict, Any, Optional


# ============================================
# 归一化字段
# ============================================
def normalize(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """归一化为标准字段 — 供 risk engine 使用"""
    return {
        "cve_id": parsed.get("cve_id") or parsed.get("CVE") or "",
        "title": parsed.get("title") or parsed.get("name") or parsed.get("plugin_name") or "Unknown",
        "description": parsed.get("description") or parsed.get("desc") or "",
        "cvss_base": float(parsed.get("cvss_base") or parsed.get("cvss") or parsed.get("CVSS_base_score") or 0.0),
        "epss_score": float(parsed.get("epss_score") or parsed.get("epss") or 0.0),
        "is_cisa_kev": bool(parsed.get("is_cisa_kev") or parsed.get("in_kev") or False),
        "source": parsed.get("source", "MANUAL"),
        "remediation_advice": parsed.get("remediation") or parsed.get("fix") or parsed.get("solution") or "",
        "raw_payload_hash": hashlib.sha256(
            json.dumps(parsed, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest(),
    }


# ============================================
# Trivy JSON Parser
# ============================================
def parse_trivy(payload: Dict[str, Any], asset_id: str) -> List[Dict[str, Any]]:
    """
    Trivy 报告格式：
    {
      "Results": [
        {"Target": "ubuntu:22.04", "Vulnerabilities": [
          {"VulnerabilityID": "CVE-2024-...", "PkgName": "openssl", "InstalledVersion": "...",
           "Severity": "CRITICAL", "CVSS": {"nvd": {"V3Score": 9.8}}, "Title": "...", "Description": "..."}
        ]}
      ]
    }
    """
    results = []
    for r in payload.get("Results", []):
        for v in r.get("Vulnerabilities", []) or []:
            cvss = 0.0
            cvss_obj = v.get("CVSS") or {}
            # 优先取 nvd V3 score
            for source_key in ["nvd", "redhat", "ghsa"]:
                if source_key in cvss_obj:
                    s = cvss_obj[source_key].get("V3Score") or cvss_obj[source_key].get("V2Score")
                    if s:
                        cvss = float(s)
                        break
            results.append(normalize({
                "cve_id": v.get("VulnerabilityID"),
                "title": v.get("Title") or v.get("VulnerabilityID"),
                "description": v.get("Description", ""),
                "cvss_base": cvss,
                "source": "TRIVY",
                "remediation": v.get("FixedVersion", "Update to fixed version"),
                "asset_id": asset_id,
                "_severity": v.get("Severity", ""),
            }))
    return results


# ============================================
# Nessus JSON Parser (v2 export)
# ============================================
def parse_nessus(payload: Dict[str, Any], asset_id: str) -> List[Dict[str, Any]]:
    """
    Nessus v2 导出格式：
    {
      "Report": {
        "ReportHost": [
          {"hostname": "...", "ReportItem": [
            {"pluginID": "123", "pluginName": "...", "cvss_base_score": 7.5, "description": "...",
             "solution": "...", "cve": "CVE-2017-..."}
          ]}
        ]
      }
    }
    """
    results = []
    report = payload.get("Report") or {}
    for host in report.get("ReportHost", []) or []:
        items = host.get("ReportItem", [])
        if isinstance(items, dict):
            items = [items]
        for item in items:
            cvss = float(item.get("cvss_base_score") or item.get("cvss3_base_score") or 0.0)
            cve = item.get("cve", "")
            if not cve and item.get("see_also"):
                m = re.search(r"CVE-\d{4}-\d+", item.get("see_also", ""))
                if m:
                    cve = m.group(0)
            results.append(normalize({
                "cve_id": cve,
                "title": item.get("plugin_name") or item.get("pluginID"),
                "description": item.get("description", ""),
                "cvss_base": cvss,
                "source": "NESSUS",
                "remediation": item.get("solution", ""),
                "asset_id": asset_id,
                "_severity": item.get("severity", ""),  # Nessus: 0=Info 1=Low 2=Med 3=High 4=Critical
            }))
    return results


# ============================================
# Generic JSON (CIS / manual)
# ============================================
def parse_generic(payload: Dict[str, Any], asset_id: str) -> List[Dict[str, Any]]:
    """通用解析：list of dicts 或单个 dict"""
    items = payload if isinstance(payload, list) else payload.get("vulnerabilities", [payload])
    results = []
    for v in items:
        results.append(normalize({
            "cve_id": v.get("cve_id"),
            "title": v.get("title") or v.get("name"),
            "description": v.get("description", ""),
            "cvss_base": v.get("cvss_base", 0.0),
            "epss_score": v.get("epss_score", 0.0),
            "is_cisa_kev": v.get("is_cisa_kev", False),
            "source": v.get("source", "MANUAL"),
            "remediation": v.get("remediation_advice", ""),
            "asset_id": asset_id,
        }))
    return results


def parse_scan(source: str, payload: Dict[str, Any], asset_id: str) -> List[Dict[str, Any]]:
    """统一入口"""
    s = source.upper()
    if s == "TRIVY":
        return parse_trivy(payload, asset_id)
    if s == "NESSUS":
        return parse_nessus(payload, asset_id)
    return parse_generic(payload, asset_id)
