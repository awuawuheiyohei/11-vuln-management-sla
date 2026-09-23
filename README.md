# Vulnerability Management + SLA Tracking

> **一句话**：CVSS + EPSS + CISA KEV 加权风险评分 + SLA 追踪 + 风险例外闭环
> 对齐 **Senior Cyber Security Analyst** 漏洞全生命周期处置职责 + **ISO 27001 A.12.6.1 / SOC 2 CC7.1 / PCI DSS Req 6.3**。

---

## ✨ 状态

**v0.1 完成**（2026-09-23）— 端到端实跑：**45/45 tests PASS**

| 模块 | 完成度 | 备注 |
|---|---|---|
| 4 张表 schema | ✅ | vulnerabilities / assets / sla_tracking / risk_exceptions / audit |
| 3 类 Scanner Parser | ✅ | Trivy + Nessus + Generic |
| Composite Risk 引擎 | ✅ | CVSS*0.5 + EPSS*10*0.3 + Asset_Weight*0.2 |
| CISA KEV 强制升级 | ✅ | is_cisa_kev=True → 直接 CRITICAL |
| SLA 计算 | ✅ | Critical 2d / High 14d / Medium 30d / Low 90d |
| SLA 状态评估 | ✅ | ON_TRACK / AT_RISK / BREACHED / RESOLVED |
| 风险例外流程 | ✅ | PENDING → APPROVED/REJECTED（含补偿措施 + 到期日） |
| Trivy/Nessus 扫描上传 | ✅ | 自动归一化 + CVE 去重 |
| SOC 2 CC7.1 报告 | ✅ | 按团队 × 严重度统计 |
| FastAPI 11 endpoints | ✅ | |
| Vanilla JS Dashboard 6 tab | ✅ | 0 CDN |
| 端到端测试 | ✅ | **45/45 PASS** |
| GitHub public | ✅ | `awuawuheiyohei/11-vuln-management-sla` |

## 📁 项目结构

```
11-vuln-management-sla/
├── README.md
├── pyproject.toml
├── main.py                     # CLI 入口
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI app
│   ├── schema.sql             # 4 张表
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py          # 11 endpoints
│   └── models/
│       ├── __init__.py
│       ├── db.py              # SQLite + WAL
│       ├── parsers.py         # Trivy/Nessus/Generic
│       ├── risk_engine.py     # Composite + SLA
│       └── seed.py            # 10 assets + 46 vulns + 2 exceptions
├── static/
│   └── index.html             # Dashboard 6 tab
├── tests/
│   └── test_routes.py         # 45 tests
└── docs/
    └── PRD.md
```

## 🚀 快速开始

```bash
cd /Users/jiangwenrui/Downloads/mass/11-vuln-management-sla
pip install fastapi uvicorn

python main.py serve
# 浏览器: http://localhost:5038/

pytest tests/ -v
```

## 🔑 核心 API

| Endpoint | 方法 | 说明 |
|---|---|---|
| `/health` | GET | 健康检查 |
| `/api/dashboard/summary` | GET | SLA breached/at_risk + KEV open + by severity |
| `/api/vulnerabilities` | GET / POST | 漏洞清单 (filter: severity/status/sla_status) |
| `/api/vulnerabilities/{id}` | GET | 漏洞详情（含 asset + exceptions join） |
| `/api/vulnerabilities/{id}/resolve` | POST | 标记 RESOLVED |
| `/api/assets` | GET | 资产清单（含 open_vuln_count） |
| `/api/sla/breaches` | GET | SLA 临期/超期清单 |
| `/api/sla/reevaluate` | POST | 每日 SLA 状态重算 |
| `/api/exceptions` | GET / POST | 风险例外列表 + 创建 |
| `/api/exceptions/{id}/decide` | POST | APPROVE/REJECT（approved=true → vuln 标 RISK_ACCEPTED） |
| `/api/scan/upload` | POST | 上传 Trivy/Nessus JSON → 解析 + 入库 + 去重 |
| `/api/report/soc2` | GET | SOC 2 CC7.1 报告 |
| `/api/audit` | GET | 审计 trail |
| `/api/admin/seed` | POST | 重置 |

## 📊 Composite Risk Score

```
Composite = CVSS * 0.5 + (EPSS * 10) * 0.3 + Asset_Weight * 0.2
其中 Asset_Weight = TIER_1_CRITICAL=1.5 / TIER_2_PROD=1.0 / TIER_3_NONPROD=0.6
最终 Severity = composite_score 映射（>=9 CRITICAL / >=7 HIGH / >=4 MEDIUM / <4 LOW）
CISA KEV → 直接 CRITICAL（覆盖 composite）
```

## 📊 SLA 评估

| Severity | SLA Days | AT_RISK 阈值 | 来源 |
|---|---|---|---|
| CRITICAL | 2 天（48h） | ≤7 天剩余 | PCI DSS Req 6.3 / NIST CSF RS.MI-3 |
| HIGH | 14 天 | ≤7 天剩余 | SOC 2 CC7.1 |
| MEDIUM | 30 天 | ≤7 天剩余 | |
| LOW | 90 天 | ≤7 天剩余 | |

状态：`ON_TRACK` / `AT_RISK` / `BREACHED` / `RESOLVED`

## 📊 Dashboard 6 Tab

1. **🚨 SLA 预警** — BREACHED + AT_RISK 漏洞清单（含 KEV 标记）
2. **📋 漏洞清单** — 按 severity/status 过滤
3. **🖥️ 资产** — 10 资产按 tier 过滤，open vuln 计数
4. **📝 风险例外** — PENDING/APPROVED/REJECTED 审批流
5. **📤 扫描上传** — 粘贴 Trivy/Nessus JSON → 解析入库
6. **📊 SOC 2 报告** — 自动生成 CC7.1 控制报告

## 🧪 测试覆盖（45/45 PASS）

- Parsers (Trivy/Nessus/Generic): 5 个
- Risk engine (composite / KEV / SLA / eval): 13 个
- Seed data + DB state: 2 个
- FastAPI routes: 25 个
  - Dashboard / Vulnerabilities CRUD / Assets / SLA / Exceptions / Scan / Report / Audit
- 关键场景：
  - KEV 自动升级 CRITICAL
  - Trivy JSON 解析 + CVE 去重
  - SLA 自动计算 + 状态评估
  - 风险例外 APPROVE → vuln RISK_ACCEPTED

## 📝 PRD 来源

本项目基于 `/Users/jiangwenrui/Downloads/mass/Interview/Security_and_GRC_14_Projects_Plan/11_Vulnerability_Management_Lifecycle_and_SLA.md` 完整规划。

## 📄 License

MIT — 自由使用、修改、二次分发。
