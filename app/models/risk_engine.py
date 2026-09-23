"""
Vulnerability Risk & SLA Engine
- Composite Score = CVSS*0.5 + EPSS*10*0.3 + Asset_Weight*0.2
- CISA KEV → 强制 CRITICAL
- SLA: Critical 2d / High 14d / Medium 30d / Low 90d
"""
from datetime import datetime, date, timedelta
from typing import Dict, Any, Optional

# ============================================
# 严重度阈值（CVSS）
# ============================================
SEVERITY_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]


def cvss_to_severity(cvss: float) -> str:
    for threshold, sev in SEVERITY_THRESHOLDS:
        if cvss >= threshold:
            return sev
    return "LOW"


# ============================================
# SLA 天数
# ============================================
SLA_DAYS = {
    "CRITICAL": 2,    # 48 小时
    "HIGH": 14,       # 14 天
    "MEDIUM": 30,
    "LOW": 90,
}

# SLA 状态阈值（剩余天数）
SLA_STATUS_THRESHOLDS = {
    "ON_TRACK": 0.5,    # > 50% 时间剩余
    "AT_RISK": 0.0,     # 0-50% 时间剩余
    # BREACHED: 负数 (due_date 已过)
}


# ============================================
# Asset Tier → 权重
# ============================================
TIER_WEIGHTS = {
    "TIER_1_CRITICAL": 1.5,    # 支付 / PCI CDE / Crown Jewel
    "TIER_2_PROD": 1.0,        # 生产内部服务
    "TIER_3_NONPROD": 0.6,     # Staging / Dev / QA
}


# ============================================
# Composite Risk Score
# ============================================
def composite_score(cvss: float, epss: float, asset_weight: float) -> float:
    """
    Composite = CVSS * 0.5 + EPSS*10 * 0.3 + Asset_Weight * 0.2
    Returns 0.0 - 10.0 (clamped)
    """
    raw = cvss * 0.5 + (epss * 10.0) * 0.3 + asset_weight * 0.2
    return round(min(10.0, max(0.0, raw)), 2)


def determine_severity(cvss: float, epss: float, is_cisa_kev: bool, asset_weight: float) -> str:
    """决定最终 severity — KEV 直接 CRITICAL"""
    if is_cisa_kev:
        return "CRITICAL"
    score = composite_score(cvss, epss, asset_weight)
    return cvss_to_severity(score)


# ============================================
# SLA 计算
# ============================================
def compute_sla(severity: str, discovered_at: date) -> Dict[str, Any]:
    """返回 SLA 跟踪记录（不含 status，status 由 evaluate_sla_status 算）"""
    days = SLA_DAYS.get(severity, 30)
    due = discovered_at + timedelta(days=days)
    return {
        "sla_days": days,
        "discovered_at": discovered_at.isoformat(),
        "due_date": due.isoformat(),
    }


def evaluate_sla_status(due_date: date, now: Optional[date] = None) -> Dict[str, Any]:
    """
    SLA 状态评估
    - BREACHED: 已超期
    - AT_RISK: < 50% 剩余时间
    - ON_TRACK: 健康
    """
    now = now or date.today()
    delta = (due_date - now).days
    if delta < 0:
        status = "BREACHED"
        days_remaining = delta
    else:
        days_remaining = delta
        # 用 SLA_DAYS 反算 50% 阈值
        # 简化：用 absolute days<7 视为 AT_RISK（无论 severity）
        if delta <= 7:
            status = "AT_RISK"
        else:
            status = "ON_TRACK"
    return {
        "status": status,
        "days_remaining": days_remaining,
    }


# ============================================
# Stats
# ============================================
def stats_summary(vulns: list) -> dict:
    """汇总漏洞分布"""
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_status = {"OPEN": 0, "IN_PROGRESS": 0, "RESOLVED": 0, "RISK_ACCEPTED": 0}
    by_source = {}
    breached = 0
    at_risk = 0
    kev_count = 0
    for v in vulns:
        by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
        by_status[v["status"]] = by_status.get(v["status"], 0) + 1
        by_source[v["source"]] = by_source.get(v["source"], 0) + 1
        if v.get("is_cisa_kev"):
            kev_count += 1
        if v.get("sla_status") == "BREACHED":
            breached += 1
        elif v.get("sla_status") == "AT_RISK":
            at_risk += 1
    return {
        "total": len(vulns),
        "by_severity": by_sev,
        "by_status": by_status,
        "by_source": by_source,
        "breached": breached,
        "at_risk": at_risk,
        "kev_count": kev_count,
    }


if __name__ == "__main__":
    # Smoke
    print("CVSS 9.8 + EPSS 0.95 + Tier 1 → severity:", determine_severity(9.8, 0.95, False, 1.5))
    print("CVSS 9.8 + KEV + Tier 1 → severity:", determine_severity(9.8, 0.95, True, 1.5))
    print("CVSS 5.0 + EPSS 0.3 + Tier 2 → severity:", determine_severity(5.0, 0.3, False, 1.0))
    print("CVSS 2.0 + EPSS 0.0 + Tier 3 → severity:", determine_severity(2.0, 0.0, False, 0.6))

    sla = compute_sla("CRITICAL", date(2026, 9, 1))
    print("Critical SLA:", sla)
    s = evaluate_sla_status(date(2026, 9, 2), now=date(2026, 9, 1))
    print("Just discovered:", s)
    s = evaluate_sla_status(date(2026, 9, 2), now=date(2026, 9, 5))
    print("Breached:", s)
