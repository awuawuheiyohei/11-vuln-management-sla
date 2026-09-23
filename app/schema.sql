-- Vulnerability Management + SLA Tracking - SQLite schema (v1.0)
-- 依据 Security_and_GRC_14_Projects_Plan #11 PRD

-- ============================================
-- 资产 (Asset) — 关键度 + 所属 owner
-- ============================================
CREATE TABLE IF NOT EXISTS assets (
    asset_id         TEXT PRIMARY KEY,                  -- AST-001
    asset_name       TEXT NOT NULL,
    asset_type       TEXT NOT NULL,                     -- SERVER/CONTAINER/WEBAPP/DATABASE/SAAS/IMAGE
    environment      TEXT NOT NULL DEFAULT 'PROD',     -- PROD/STAGING/DEV
    tier             TEXT NOT NULL,                     -- TIER_1_CRITICAL / TIER_2_PROD / TIER_3_NONPROD
    owner_team       TEXT NOT NULL DEFAULT 'DevOps',
    criticality_weight REAL NOT NULL DEFAULT 1.0,       -- 0.6 / 1.0 / 1.5
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_asset_tier ON assets(tier);
CREATE INDEX IF NOT EXISTS idx_asset_team ON assets(owner_team);

-- ============================================
-- 漏洞 (Vulnerability) — 归一化
-- ============================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id          TEXT PRIMARY KEY,                  -- VUL-0001
    cve_id           TEXT,                              -- CVE-2024-12345
    title            TEXT NOT NULL,
    description      TEXT,
    asset_id         TEXT NOT NULL,
    asset_tier       TEXT NOT NULL,
    cvss_base        REAL NOT NULL,
    epss_score       REAL NOT NULL DEFAULT 0.0,
    is_cisa_kev      INTEGER NOT NULL DEFAULT 0,
    severity         TEXT NOT NULL,                     -- CRITICAL/HIGH/MEDIUM/LOW
    composite_score  REAL NOT NULL,
    status           TEXT NOT NULL DEFAULT 'OPEN',     -- OPEN/IN_PROGRESS/RESOLVED/RISK_ACCEPTED
    assigned_team    TEXT NOT NULL DEFAULT 'DevOps',
    discovered_at    TEXT NOT NULL DEFAULT (datetime('now')),
    due_date         TEXT NOT NULL,
    resolved_at      TEXT,
    source           TEXT NOT NULL,                     -- TRIVY/NESSUS/NIKTO/MANUAL
    remediation_advice TEXT,
    raw_payload_hash TEXT,                              -- SHA-256 of raw scanner output (no payload stored)
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vuln_due ON vulnerabilities(due_date);
CREATE INDEX IF NOT EXISTS idx_vuln_asset ON vulnerabilities(asset_id);
CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);

-- ============================================
-- SLA 追踪 (sla_tracking)
-- ============================================
CREATE TABLE IF NOT EXISTS sla_tracking (
    sla_id           TEXT PRIMARY KEY,                  -- SLA-{vuln_id}
    vuln_id          TEXT NOT NULL,
    severity         TEXT NOT NULL,
    sla_days         INTEGER NOT NULL,
    discovered_at    TEXT NOT NULL,
    due_date         TEXT NOT NULL,
    days_remaining   INTEGER NOT NULL,                  -- 负数 = overdue
    status           TEXT NOT NULL,                     -- ON_TRACK / AT_RISK / BREACHED / RESOLVED
    last_evaluated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_sla_status ON sla_tracking(status);
CREATE INDEX IF NOT EXISTS idx_sla_due ON sla_tracking(due_date);

-- ============================================
-- 风险例外 (risk_exceptions)
-- ============================================
CREATE TABLE IF NOT EXISTS risk_exceptions (
    exception_id     TEXT PRIMARY KEY,
    vuln_id          TEXT NOT NULL,
    requested_by     TEXT NOT NULL,
    approved_by      TEXT,
    justification    TEXT NOT NULL,
    compensating_controls TEXT,                          -- JSON array
    exception_until  TEXT NOT NULL,                     -- ISO date — 到期自动重审
    status           TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING/APPROVED/REJECTED/EXPIRED
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    decided_at       TEXT,
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_exc_status ON risk_exceptions(status);
CREATE INDEX IF NOT EXISTS idx_exc_until ON risk_exceptions(exception_until);

-- ============================================
-- 审计 trail
-- ============================================
CREATE TABLE IF NOT EXISTS audit_trail (
    audit_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    entity_type   TEXT,
    entity_id     TEXT,
    details       TEXT,
    occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
