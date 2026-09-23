"""Seed assets + vulnerabilities + SLAs + risk exceptions"""
import json
import hashlib
from datetime import date, timedelta
from typing import List, Dict, Any

from .db import get_conn, init_db
from .risk_engine import (
    composite_score, determine_severity, compute_sla,
    evaluate_sla_status, TIER_WEIGHTS, SLA_DAYS,
)


# ============================================
# 资产种子（10 条）
# ============================================
DEFAULT_ASSETS = [
    {"asset_id": "AST-001", "asset_name": "Payment API Server", "asset_type": "SERVER", "environment": "PROD",
     "tier": "TIER_1_CRITICAL", "owner_team": "Payments", "criticality_weight": 1.5},
    {"asset_id": "AST-002", "asset_name": "Customer PII Database", "asset_type": "DATABASE", "environment": "PROD",
     "tier": "TIER_1_CRITICAL", "owner_team": "Data", "criticality_weight": 1.5},
    {"asset_id": "AST-003", "asset_name": "Booking Web App", "asset_type": "WEBAPP", "environment": "PROD",
     "tier": "TIER_2_PROD", "owner_team": "Web", "criticality_weight": 1.0},
    {"asset_id": "AST-004", "asset_name": "Internal CRM", "asset_type": "SAAS", "environment": "PROD",
     "tier": "TIER_2_PROD", "owner_team": "SalesOps", "criticality_weight": 1.0},
    {"asset_id": "AST-005", "asset_name": "Auth Service", "asset_type": "SERVER", "environment": "PROD",
     "tier": "TIER_1_CRITICAL", "owner_team": "Platform", "criticality_weight": 1.5},
    {"asset_id": "AST-006", "asset_name": "Container Image: web-frontend", "asset_type": "IMAGE", "environment": "PROD",
     "tier": "TIER_2_PROD", "owner_team": "Web", "criticality_weight": 1.0},
    {"asset_id": "AST-007", "asset_name": "Container Image: api-gateway", "asset_type": "IMAGE", "environment": "PROD",
     "tier": "TIER_1_CRITICAL", "owner_team": "Platform", "criticality_weight": 1.5},
    {"asset_id": "AST-008", "asset_name": "Staging API", "asset_type": "SERVER", "environment": "STAGING",
     "tier": "TIER_3_NONPROD", "owner_team": "DevOps", "criticality_weight": 0.6},
    {"asset_id": "AST-009", "asset_name": "Dev Web App", "asset_type": "WEBAPP", "environment": "DEV",
     "tier": "TIER_3_NONPROD", "owner_team": "Web", "criticality_weight": 0.6},
    {"asset_id": "AST-010", "asset_name": "Logstash ES", "asset_type": "DATABASE", "environment": "PROD",
     "tier": "TIER_2_PROD", "owner_team": "SecOps", "criticality_weight": 1.0},
]


# ============================================
# 漏洞种子（50 条混合真实 CVE）
# ============================================
def _make_vulns() -> List[Dict[str, Any]]:
    """生成 50 条 mock 漏洞"""
    today = date.today()
    samples = [
        # CRITICAL KEV (强制升级) — 3 条
        ("CVE-2024-3094", "XZ Utils Backdoor", "Malicious code in xz-utils 5.6.0/5.6.1", 10.0, 0.97, True, "AST-002", -3, "RESOLVED"),
        ("CVE-2023-44487", "HTTP/2 Rapid Reset DoS", "nginx HTTP/2 protocol DoS", 7.5, 0.91, True, "AST-001", 1, "IN_PROGRESS"),
        ("CVE-2024-21412", "Microsoft Outlook MonikerLink", "RCE via crafted URL", 9.8, 0.96, True, "AST-004", 0, "OPEN"),
        # CRITICAL no KEV — 5 条
        ("CVE-2023-50164", "Apache Struts File Upload RCE", "Unrestricted file upload", 9.8, 0.71, False, "AST-001", 2, "IN_PROGRESS"),
        ("CVE-2022-22965", "Spring4Shell RCE", "Spring Framework RCE via data binding", 9.8, 0.84, False, "AST-003", 5, "OPEN"),
        ("CVE-2021-44228", "Log4Shell RCE", "Log4j JNDI lookup RCE", 10.0, 0.92, False, "AST-005", -2, "OPEN"),
        ("CVE-2024-1086", "Linux Kernel netfilter UAF", "Kernel privilege escalation", 7.8, 0.65, False, "AST-002", 4, "OPEN"),
        ("CVE-2022-1388", "F5 BIG-IP iControl REST Auth Bypass", "Auth bypass → admin", 9.8, 0.43, False, "AST-001", 1, "OPEN"),
        # HIGH — 10 条
        ("CVE-2024-21626", "runc fd leak Container Escape", "Container escape via leaked fd", 8.6, 0.51, False, "AST-007", 5, "OPEN"),
        ("CVE-2023-36884", "Microsoft Office Search Path RCE", "RCE via crafted Office doc", 8.8, 0.42, False, "AST-004", 12, "OPEN"),
        ("CVE-2023-23397", "Outlook NTLM Credential Theft", "NTLM creds via PidLidReminderFileParameter", 9.8, 0.93, False, "AST-004", 10, "OPEN"),
        ("CVE-2024-23897", "Jenkins CLI Arbitrary File Read", "Arbitrary file read via CLI args", 9.8, 0.58, False, "AST-005", 8, "OPEN"),
        ("CVE-2022-26134", "Confluence OGNL Injection RCE", "Unauthenticated OGNL injection", 9.8, 0.78, False, "AST-008", 6, "IN_PROGRESS"),
        ("CVE-2023-22515", "Confluence Privilege Escalation", "Broken access control → admin", 9.8, 0.62, False, "AST-008", 9, "OPEN"),
        ("CVE-2021-34527", "Windows PrintNightmare RCE", "Windows Print Spooler RCE", 8.8, 0.88, False, "AST-004", 14, "OPEN"),
        ("CVE-2022-41040", "Exchange ProxyNotShell SSRF", "Exchange server-side request forgery", 8.8, 0.61, False, "AST-005", 11, "OPEN"),
        ("CVE-2023-4863", "libwebp Heap Overflow", "libwebp heap buffer overflow", 8.8, 0.72, False, "AST-006", 7, "OPEN"),
        ("CVE-2024-26234", "Windows CSC Service Elevation", "CSC service privilege escalation", 7.8, 0.32, False, "AST-004", 13, "OPEN"),
        # MEDIUM — 15 条
        ("CVE-2023-38545", "curl SOCKS5 Heap Overflow", "curl SOCKS5 handshake overflow", 7.5, 0.31, False, "AST-001", 18, "OPEN"),
        ("CVE-2024-0204", "Fortra GoAnywhere MFT Auth Bypass", "Admin auth bypass", 9.8, 0.45, False, "AST-005", 20, "OPEN"),
        ("CVE-2023-5009", "GitLab Pipeline RCE", "Pipeline variable RCE", 9.6, 0.34, False, "AST-008", 22, "OPEN"),
        ("CVE-2022-3786", "OpenSSL X.509 Buffer Overflow", "X.509 email address overflow", 7.5, 0.28, False, "AST-005", 25, "OPEN"),
        ("CVE-2023-31199", "Curl HTTP/2 HPACK Integer Overflow", "HTTP/2 HPACK overflow", 6.5, 0.18, False, "AST-001", 28, "OPEN"),
        ("CVE-2024-2879", "GLPI SQL Injection", "GLPI SQL injection via ajax", 6.5, 0.12, False, "AST-009", 20, "OPEN"),
        ("CVE-2023-22518", "Confluence Improper Auth (rejected patch)", "Bypass of CVE-2023-22515 fix", 9.1, 0.38, False, "AST-008", 24, "OPEN"),
        ("CVE-2024-6387", "OpenSSH regreSSHion", "Signal handler race condition", 8.1, 0.22, False, "AST-005", 26, "OPEN"),
        ("CVE-2024-4577", "PHP CGI Argument Injection", "PHP CGI argument injection (Windows)", 9.8, 0.41, False, "AST-003", 21, "OPEN"),
        ("CVE-2023-44487", "HTTP/2 Rapid Reset (recur on AST-003)", "nginx HTTP/2 protocol DoS", 7.5, 0.91, False, "AST-003", 15, "RESOLVED"),
        ("CVE-2023-50164", "Struts RCE (recur on AST-008)", "Struts RCE on staging", 9.8, 0.71, False, "AST-008", 27, "OPEN"),
        ("CVE-2024-21762", "Fortinet FortiOS Out-of-bounds Write", "SSL VPN pre-auth RCE", 9.6, 0.48, False, "AST-005", 23, "OPEN"),
        ("CVE-2024-23204", "WebKit Type Confusion", "WebKit type confusion RCE", 8.8, 0.27, False, "AST-003", 26, "OPEN"),
        ("CVE-2022-47966", "ManageEngine SAML SSO RCE", "ManageEngine SAML SSO RCE", 9.8, 0.62, False, "AST-005", 19, "OPEN"),
        ("CVE-2023-2868", "Barracuda ESG RCE", "ESG remote command injection", 9.8, 0.74, False, "AST-005", 17, "OPEN"),
        ("CVE-2023-7028", "GitLab Account Takeover", "User password reset via email", 10.0, 0.56, False, "AST-008", 30, "OPEN"),
        # LOW — 12 条
        ("CVE-2023-45853", "Zyxel NAS Authentication Bypass", "Authentication bypass", 6.5, 0.15, False, "AST-010", 45, "OPEN"),
        ("CVE-2024-21762", "Fortinet FortiOS SSL VPN XSS", "XSS in SSL VPN portal", 5.4, 0.08, False, "AST-005", 60, "OPEN"),
        ("CVE-2023-50387", "BIND KeyTrap DoS", "DNSSEC KeyTrap denial of service", 7.5, 0.14, False, "AST-010", 50, "OPEN"),
        ("CVE-2024-23222", "WebKit Use-after-free", "WebKit UAF RCE", 8.8, 0.19, False, "AST-003", 55, "OPEN"),
        ("CVE-2022-22978", "Spring Framework RCE (rejected fix)", "Bypass of Spring4Shell fix", 9.8, 0.31, False, "AST-008", 70, "OPEN"),
        ("CVE-2023-24023", "Bluetooth BLUFFS Impersonation", "Bluetooth session key attack", 6.8, 0.11, False, "AST-001", 80, "OPEN"),
        ("CVE-2024-23204", "WebKit (recur AST-006)", "WebKit type confusion in container", 8.8, 0.27, False, "AST-006", 65, "OPEN"),
        ("CVE-2023-44487", "HTTP/2 (recur AST-009)", "HTTP/2 DoS on dev env", 7.5, 0.91, False, "AST-009", 75, "RESOLVED"),
        ("CVE-2023-25690", "Apache HTTPd mod_proxy RCE", "HTTP Request Smuggling → RCE", 9.8, 0.45, False, "AST-008", 85, "OPEN"),
        ("CVE-2022-30190", "Follina MSDT RCE", "MS Office MSDT URI handler RCE", 7.8, 0.66, False, "AST-004", 78, "OPEN"),
        ("CVE-2024-0204", "Fortra GoAnywhere (recur AST-008)", "Auth bypass on staging", 9.8, 0.45, False, "AST-008", 88, "OPEN"),
        ("CVE-2021-26855", "Exchange ProxyLogon SSRF", "Exchange server SSRF", 9.8, 0.86, False, "AST-005", 90, "OPEN"),
    ]
    vulns = []
    today = date.today()
    for i, (cve, title, desc, cvss, epss, kev, asset_id, days_from_due, status) in enumerate(samples, 1):
        # 找到 asset
        asset = next(a for a in DEFAULT_ASSETS if a["asset_id"] == asset_id)
        tier = asset["tier"]
        aw = asset["criticality_weight"]
        severity = determine_severity(cvss, epss, kev, aw)
        score = composite_score(cvss, epss, aw)

        # discovered_at: 算 SLA days，再从 due_date 推回 discovered
        sla_days = SLA_DAYS[severity]
        due = today + timedelta(days=days_from_due)
        discovered = due - timedelta(days=sla_days)

        vulns.append({
            "vuln_id": f"VUL-{i:04d}",
            "cve_id": cve,
            "title": title,
            "description": desc,
            "asset_id": asset_id,
            "asset_tier": tier,
            "cvss_base": cvss,
            "epss_score": epss,
            "is_cisa_kev": kev,
            "severity": severity,
            "composite_score": score,
            "status": status,
            "assigned_team": asset["owner_team"],
            "discovered_at": discovered.isoformat(),
            "due_date": due.isoformat(),
            "resolved_at": (date.today() - timedelta(days=1)).isoformat() if status == "RESOLVED" else None,
            "source": ["TRIVY", "NESSUS", "MANUAL"][i % 3],
            "remediation_advice": f"Update {cve} per vendor advisory. See NVD reference.",
            "raw_payload_hash": hashlib.sha256((cve + str(cvss)).encode()).hexdigest(),
        })
    return vulns


# ============================================
# Seed 入口
# ============================================
def seed_assets(verbose=False):
    init_db()
    conn = get_conn()
    conn.execute("DELETE FROM sla_tracking")
    conn.execute("DELETE FROM risk_exceptions")
    conn.execute("DELETE FROM vulnerabilities")
    conn.execute("DELETE FROM assets")
    conn.execute("DELETE FROM audit_trail")

    for a in DEFAULT_ASSETS:
        conn.execute(
            """INSERT INTO assets (asset_id, asset_name, asset_type, environment, tier, owner_team, criticality_weight)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (a["asset_id"], a["asset_name"], a["asset_type"], a["environment"],
             a["tier"], a["owner_team"], a["criticality_weight"])
        )
    conn.commit()
    if verbose:
        print(f"[+] Seeded {len(DEFAULT_ASSETS)} assets")
    return len(DEFAULT_ASSETS)


def seed_vulnerabilities(verbose=False):
    conn = get_conn()
    vulns = _make_vulns()
    today = date.today()
    inserted = 0
    for v in vulns:
        # 检查 CVE 唯一
        if conn.execute("SELECT 1 FROM vulnerabilities WHERE vuln_id=?", (v["vuln_id"],)).fetchone():
            continue
        conn.execute(
            """INSERT INTO vulnerabilities
               (vuln_id, cve_id, title, description, asset_id, asset_tier,
                cvss_base, epss_score, is_cisa_kev, severity, composite_score,
                status, assigned_team, discovered_at, due_date, resolved_at,
                source, remediation_advice, raw_payload_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (v["vuln_id"], v["cve_id"], v["title"], v["description"], v["asset_id"], v["asset_tier"],
             v["cvss_base"], v["epss_score"], int(v["is_cisa_kev"]), v["severity"], v["composite_score"],
             v["status"], v["assigned_team"], v["discovered_at"], v["due_date"], v["resolved_at"],
             v["source"], v["remediation_advice"], v["raw_payload_hash"])
        )
        # SLA tracking
        due_date_obj = date.fromisoformat(v["due_date"])
        sla_status = evaluate_sla_status(due_date_obj, today)
        conn.execute(
            """INSERT INTO sla_tracking (sla_id, vuln_id, severity, sla_days, discovered_at, due_date, days_remaining, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (f"SLA-{v['vuln_id']}", v["vuln_id"], v["severity"], SLA_DAYS[v["severity"]],
             v["discovered_at"], v["due_date"], sla_status["days_remaining"], sla_status["status"])
        )
        inserted += 1
    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted} vulnerabilities + SLAs")
    return inserted


def seed_risk_exceptions(verbose=False):
    """Seed 2 风险例外"""
    conn = get_conn()
    examples = [
        {
            "exception_id": "EXC-0001",
            "vuln_id": "VUL-0021",  # 假设一个 MEDIUM 漏洞
            "requested_by": "DevOps Team",
            "approved_by": "CISO",
            "justification": "Spring Framework 升级会破坏现有的 AspectJ 织入 — 需 6 周重写 + 充分回归测试",
            "compensating_controls": '["WAF rule blocking exploit pattern", "Network segmentation isolated the vulnerable endpoint", "Enhanced SIEM monitoring on this host"]',
            "exception_until": (date.today() + timedelta(days=90)).isoformat(),
            "status": "APPROVED",
        },
        {
            "exception_id": "EXC-0002",
            "vuln_id": "VUL-0030",
            "requested_by": "SalesOps",
            "approved_by": "GRC Lead",
            "justification": "CRM SaaS vendor patch 在 2 月 5 日发布 — 接受风险等待补丁",
            "compensating_controls": '["Vendor patch SLA documented", "MFA enforced on all CRM admin accounts", "Quarterly access review"]',
            "exception_until": (date.today() + timedelta(days=30)).isoformat(),
            "status": "PENDING",
        },
    ]
    inserted = 0
    for e in examples:
        # 检查 vuln 是否存在
        if not conn.execute("SELECT 1 FROM vulnerabilities WHERE vuln_id=?", (e["vuln_id"],)).fetchone():
            continue
        conn.execute(
            """INSERT INTO risk_exceptions
               (exception_id, vuln_id, requested_by, approved_by, justification,
                compensating_controls, exception_until, status, decided_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (e["exception_id"], e["vuln_id"], e["requested_by"], e["approved_by"], e["justification"],
             e["compensating_controls"], e["exception_until"], e["status"],
             date.today().isoformat() if e["status"] != "PENDING" else None)
        )
        inserted += 1
    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted} risk exceptions")
    return inserted


def seed_all(verbose=False):
    n_a = seed_assets(verbose=verbose)
    n_v = seed_vulnerabilities(verbose=verbose)
    n_e = seed_risk_exceptions(verbose=verbose)
    return {"assets": n_a, "vulnerabilities": n_v, "risk_exceptions": n_e}


if __name__ == "__main__":
    print(seed_all(verbose=True))
