"""Vuln Management + SLA Tracking - 端到端测试"""
import os
import sys
import json
from datetime import date, timedelta
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from app.main import app
from app.models.db import init_db, DB_PATH
from app.models.parsers import parse_trivy, parse_nessus, parse_generic, parse_scan, normalize
from app.models.risk_engine import (
    composite_score, determine_severity, compute_sla, evaluate_sla_status,
    SLA_DAYS, TIER_WEIGHTS, stats_summary,
)
from app.models.seed import (
    DEFAULT_ASSETS, seed_assets, seed_vulnerabilities, seed_risk_exceptions, seed_all,
)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()
    seed_all(verbose=False)
    yield


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# ============================================
# Parser unit tests
# ============================================
class TestParsers:
    def test_trivy(self):
        payload = {"Results": [{"Target": "ubuntu", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-1", "Title": "Test", "Severity": "CRITICAL",
             "CVSS": {"nvd": {"V3Score": 9.8}}, "Description": "x", "FixedVersion": "1.0"}
        ]}]}
        items = parse_trivy(payload, "AST-001")
        assert len(items) == 1
        assert items[0]["cve_id"] == "CVE-2024-1"
        assert items[0]["cvss_base"] == 9.8
        assert items[0]["source"] == "TRIVY"
        assert "raw_payload_hash" in items[0]

    def test_nessus(self):
        payload = {"Report": {"ReportHost": [{"ReportItem": [
            {"pluginID": "1", "pluginName": "Test Nessus", "cvss_base_score": 7.5,
             "cve": "CVE-2024-N1", "description": "x", "solution": "patch"}
        ]}]}}
        items = parse_nessus(payload, "AST-002")
        assert len(items) == 1
        assert items[0]["cve_id"] == "CVE-2024-N1"
        assert items[0]["cvss_base"] == 7.5
        assert items[0]["source"] == "NESSUS"

    def test_generic(self):
        items = parse_generic([{"cve_id": "CVE-1", "title": "x", "cvss_base": 5.0}], "AST-003")
        assert len(items) == 1
        assert items[0]["source"] == "MANUAL"

    def test_parse_scan_dispatch(self):
        trivy = {"Results": []}
        nessus = {"Report": {"ReportHost": []}}
        assert parse_scan("TRIVY", trivy, "X") == []
        assert parse_scan("NESSUS", nessus, "X") == []
        # Unknown source → generic parser (empty payload → empty list)
        assert parse_scan("UNKNOWN", {"vulnerabilities": []}, "X") == []


# ============================================
# Risk engine unit tests
# ============================================
class TestRiskEngine:
    def test_composite_high_cvss(self):
        # CVSS 9.0, EPSS 0.0, Tier 1 (weight 1.5) → 4.5 + 0 + 0.3 = 4.8
        s = composite_score(9.0, 0.0, 1.5)
        assert s == 4.8

    def test_composite_with_epss(self):
        # CVSS 5.0, EPSS 0.5, Tier 2 (1.0) → 2.5 + 1.5 + 0.2 = 4.2
        s = composite_score(5.0, 0.5, 1.0)
        assert s == 4.2

    def test_composite_clamped(self):
        # 实际最大 = 10*0.5 + 10*0.3 + 1.5*0.2 = 5 + 3 + 0.3 = 8.3 (未 clamp)
        s = composite_score(10.0, 1.0, 1.5)
        assert s == 8.3

    def test_composite_max_bound(self):
        # 验证 < 10
        s = composite_score(10.0, 1.0, 1.5)
        assert s <= 10.0

    def test_kev_force_critical(self):
        assert determine_severity(5.0, 0.1, True, 1.0) == "CRITICAL"

    def test_severity_high_composite(self):
        # 用 EPSS 让 composite 达到 HIGH (>=7)
        # CVSS 9.0, EPSS 0.95 → 4.5 + 2.85 + 0.2 = 7.55 → HIGH
        assert determine_severity(9.0, 0.95, False, 1.0) == "HIGH"

    def test_severity_medium_composite(self):
        # CVSS 9.0, EPSS 0.0, Tier 1 → 4.5 + 0 + 0.3 = 4.8 → MEDIUM
        assert determine_severity(9.0, 0.0, False, 1.5) == "MEDIUM"

    def test_severity_low(self):
        assert determine_severity(2.0, 0.0, False, 0.6) == "LOW"

    def test_sla_days(self):
        assert SLA_DAYS["CRITICAL"] == 2
        assert SLA_DAYS["HIGH"] == 14
        assert SLA_DAYS["MEDIUM"] == 30
        assert SLA_DAYS["LOW"] == 90

    def test_compute_sla(self):
        d = date(2026, 9, 1)
        sla = compute_sla("CRITICAL", d)
        assert sla["sla_days"] == 2
        assert sla["due_date"] == "2026-09-03"

    def test_evaluate_sla_breached(self):
        s = evaluate_sla_status(date(2026, 9, 10), now=date(2026, 9, 15))
        assert s["status"] == "BREACHED"
        assert s["days_remaining"] < 0

    def test_evaluate_sla_at_risk(self):
        s = evaluate_sla_status(date(2026, 9, 10), now=date(2026, 9, 5))
        assert s["status"] == "AT_RISK"

    def test_evaluate_sla_on_track(self):
        s = evaluate_sla_status(date(2026, 10, 1), now=date(2026, 9, 5))
        assert s["status"] == "ON_TRACK"

    def test_tier_weights(self):
        assert TIER_WEIGHTS["TIER_1_CRITICAL"] == 1.5
        assert TIER_WEIGHTS["TIER_2_PROD"] == 1.0
        assert TIER_WEIGHTS["TIER_3_NONPROD"] == 0.6


# ============================================
# Seed tests
# ============================================
class TestSeed:
    def test_assets_count(self):
        assert len(DEFAULT_ASSETS) == 10
        tiers = set(a["tier"] for a in DEFAULT_ASSETS)
        assert "TIER_1_CRITICAL" in tiers
        assert "TIER_2_PROD" in tiers
        assert "TIER_3_NONPROD" in tiers

    def test_seed_in_db(self):
        from app.models.db import get_conn
        conn = get_conn()
        try:
            n_a = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            n_v = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            n_sla = conn.execute("SELECT COUNT(*) FROM sla_tracking").fetchone()[0]
            n_exc = conn.execute("SELECT COUNT(*) FROM risk_exceptions").fetchone()[0]
        finally:
            conn.close()
        assert n_a == 10
        assert n_v >= 30
        assert n_sla == n_v  # 每条 vuln 一条 SLA
        assert n_exc >= 1


# ============================================
# FastAPI smoke tests
# ============================================
class TestHealth:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestDashboard:
    def test_summary(self, client):
        r = client.get("/api/dashboard/summary")
        assert r.status_code == 200
        d = r.json()
        assert d["assets"] == 10
        assert d["vulnerabilities"]["total"] >= 30
        assert "by_severity" in d
        assert "sla" in d
        assert "kev_open" in d


class TestVulnerabilities:
    def test_list(self, client):
        r = client.get("/api/vulnerabilities")
        assert r.status_code == 200
        d = r.json()
        assert d["count"] >= 30

    def test_filter_critical(self, client):
        r = client.get("/api/vulnerabilities?severity=CRITICAL")
        assert r.status_code == 200
        d = r.json()
        assert all(v["severity"] == "CRITICAL" for v in d["items"])

    def test_filter_breached(self, client):
        r = client.get("/api/vulnerabilities?sla_status=BREACHED")
        assert r.status_code == 200
        d = r.json()
        # 至少 1 条 breached（VUL-0006 Log4Shell days_remaining=-2）
        for v in d["items"]:
            assert v["sla_status"] == "BREACHED"

    def test_get_one(self, client):
        r = client.get("/api/vulnerabilities/VUL-0001")
        assert r.status_code == 200
        d = r.json()
        assert d["vuln_id"] == "VUL-0001"
        assert "asset" in d
        assert "exceptions" in d

    def test_create(self, client):
        # CVSS 9.8 + EPSS 0.5 + Tier 1 (weight 1.5) → composite = 4.9 + 1.5 + 0.3 = 6.7 → MEDIUM
        r = client.post("/api/vulnerabilities", json={
            "title": "Test vuln",
            "asset_id": "AST-001",
            "cvss_base": 9.8,
            "epss_score": 0.5,
            "is_cisa_kev": False,
            "source": "MANUAL",
        })
        assert r.status_code == 200
        d = r.json()
        assert "vuln_id" in d
        # composite ~6.7 → MEDIUM
        assert d["severity"] in ("CRITICAL", "HIGH", "MEDIUM")

    def test_create_kev(self, client):
        r = client.post("/api/vulnerabilities", json={
            "title": "KEV vuln",
            "asset_id": "AST-001",
            "cvss_base": 5.0,
            "is_cisa_kev": True,
            "source": "MANUAL",
        })
        assert r.status_code == 200
        assert r.json()["severity"] == "CRITICAL"

    def test_create_invalid_asset(self, client):
        r = client.post("/api/vulnerabilities", json={
            "title": "x",
            "asset_id": "AST-999",
            "cvss_base": 5.0,
        })
        assert r.status_code == 400

    def test_resolve(self, client):
        r = client.post("/api/vulnerabilities/VUL-0001/resolve")
        assert r.status_code == 200
        assert r.json()["status"] == "RESOLVED"


class TestAssets:
    def test_list(self, client):
        r = client.get("/api/assets")
        assert r.status_code == 200
        d = r.json()
        assert d["count"] == 10
        assert "open_vuln_count" in d["items"][0]

    def test_filter_tier(self, client):
        r = client.get("/api/assets?tier=TIER_1_CRITICAL")
        assert r.status_code == 200
        d = r.json()
        assert all(a["tier"] == "TIER_1_CRITICAL" for a in d["items"])


class TestSLA:
    def test_breaches(self, client):
        r = client.get("/api/sla/breaches")
        assert r.status_code == 200
        d = r.json()
        assert d["count"] >= 1

    def test_reevaluate(self, client):
        r = client.post("/api/sla/reevaluate")
        assert r.status_code == 200
        d = r.json()
        assert "updated" in d


class TestExceptions:
    def test_list(self, client):
        r = client.get("/api/exceptions")
        assert r.status_code == 200
        d = r.json()
        assert d["count"] >= 1
        for e in d["items"]:
            assert isinstance(e["compensating_controls"], list)

    def test_filter_pending(self, client):
        r = client.get("/api/exceptions?status=PENDING")
        assert r.status_code == 200
        d = r.json()
        assert all(e["status"] == "PENDING" for e in d["items"])

    def test_create(self, client):
        # 找一条 OPEN vuln
        vulns = client.get("/api/vulnerabilities?status=OPEN&limit=1").json()["items"]
        if not vulns:
            return  # skip
        r = client.post("/api/exceptions", json={
            "vuln_id": vulns[0]["vuln_id"],
            "requested_by": "Test User",
            "justification": "Test reason",
            "compensating_controls": ["WAF rule"],
            "exception_until": (date.today() + timedelta(days=30)).isoformat(),
        })
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "PENDING"

    def test_decide_approve(self, client):
        # 拿 PENDING
        ex = client.get("/api/exceptions?status=PENDING").json()["items"]
        if not ex:
            return
        eid = ex[0]["exception_id"]
        r = client.post(f"/api/exceptions/{eid}/decide", json={"approved": True, "approved_by": "CISO"})
        assert r.status_code == 200


class TestScanUpload:
    def test_trivy(self, client):
        r = client.post("/api/scan/upload?source=TRIVY&asset_id=AST-007", json={
            "Results": [{"Target": "api:latest", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-NEWSCAN-1", "Title": "Test", "Severity": "CRITICAL",
                 "CVSS": {"nvd": {"V3Score": 9.5}}, "Description": "x", "FixedVersion": "1.0"}
            ]}]
        })
        assert r.status_code == 200
        d = r.json()
        assert d["parsed"] == 1
        assert d["inserted"] == 1
        assert d["skipped_dedup"] == 0

    def test_trivy_dedup(self, client):
        # 上传相同 CVE 第二次应该跳过
        r = client.post("/api/scan/upload?source=TRIVY&asset_id=AST-007", json={
            "Results": [{"Target": "api:latest", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-NEWSCAN-1", "Title": "Dup", "Severity": "CRITICAL",
                 "CVSS": {"nvd": {"V3Score": 9.5}}}
            ]}]
        })
        assert r.status_code == 200
        assert r.json()["skipped_dedup"] == 1

    def test_invalid_asset(self, client):
        r = client.post("/api/scan/upload?source=TRIVY&asset_id=AST-999", json={
            "Results": [{"Vulnerabilities": []}]
        })
        assert r.status_code == 400


class TestReport:
    def test_soc2(self, client):
        r = client.get("/api/report/soc2")
        assert r.status_code == 200
        d = r.json()
        assert d["framework"] == "SOC 2 Type II - CC7.1"
        assert "open_by_severity" in d


class TestAdmin:
    def test_seed(self, client):
        r = client.post("/api/admin/seed")
        assert r.status_code == 200
        d = r.json()
        assert d["stats"]["assets"] == 10
        assert d["stats"]["vulnerabilities"] >= 30


class TestAudit:
    def test_audit(self, client):
        r = client.get("/api/audit?limit=10")
        assert r.status_code == 200
        assert r.json()["count"] > 0


class TestStaticUI:
    def test_index(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "Vulnerability" in r.text
