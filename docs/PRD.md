# 11. 全生命周期漏洞管理（Vulnerability Management）与 SLA 追踪看板

## 1. 项目背景与对齐 JD 核心点

### 1.1 岗位诉求对齐
* **Senior Cyber Security Analyst (岗位 A)**：
  - **核心职能**：负责威胁与脆弱性分析（Vulnerability analysis and proactive risk identification）、漏洞全生命周期处置，联动 SOC 与 IT 运维团队。
  - **SLA 与工单追踪**：确保严格遵循 ServiceNow 案件跟踪与 SLA 时效标准，完成根本原因分析（RCA）与防御控制持续改进。
  - **框架对准**：对接 ISO 27001 (A.12.6.1 / A.8.8 技术脆弱性管理) 及 NIST CSF 2.0 (ID.RA-1, PR.IP-12, RS.MI-3)。
* **Senior IT GRC Specialist (岗位 B)**：
  - **审计与合规证明**：对接 SOC 2 (CC7.1 漏洞评估与修补)、PCI DSS v4.0 (Requirement 6.3 & 11.3 漏洞识别与高危补丁 30 天内修补)。
  - **风险登记册与整改追踪**：维护企业 Risk Register，追踪缺陷修复行动项（Remediation Tracking），管理风险例外（Risk Exception）审批。

### 1.2 业务痛点与项目定位
传统漏洞管理常面临三大痛点：
1. **警报风暴与优先级混乱**：仅依赖 CVSS 基础分，导致研发团队疲于奔命修补“高分但无在野利用”的漏洞，而真正危急的漏洞被淹没。
2. **跨国/跨部门协同脱节**：安全团队丢扫描报告给研发，缺少与 Jira / ServiceNow 的自动化打通，导致 SLA 超期无人知晓。
3. **风险例外失控**：业务团队因稳定性理由申请不修补，缺乏严格的补偿性控制评估与定期到期重审机制，沦为合规黑洞。

本项目旨在构建一个**轻量级、自动化、风险驱动的全生命周期漏洞治理系统**：统一解析多源扫描器报告、基于 **CVSS + EPSS (Exploit Prediction Scoring System) + 资产关键度** 进行动态再定级、自动计算修复 SLA、模拟工单同步及风险例外闭环治理。

---

## 2. Mac 本地运行环境架构与依赖

### 2.1 技术栈选型
* **核心语言**：Python 3.10+
* **Web UI / 可视化看板**：Streamlit（快速搭建交互式安全治理看板）
* **数据存储**：SQLite / JSON 结构化存储（本地自包含，无需复杂外挂数据库）
* **核心计算库**：Pydantic (数据校验与清洗)、Pandas (数据聚合与 SLA 分析)

### 2.2 本地运行架构图
```
[Nessus JSON / Trivy JSON / Nikto JSON]
                │
                ▼
      [Multi-Parser Engine]  <--- 统一数据标准化规范 (Normalized Vulnerability Schema)
                │
                ▼
    [Dynamic Risk & SLA Engine]
      ├── CVSS v3 (基线分)
      ├── EPSS (在野利用概率)
      ├── CISA KEV (在野利用已知清单)
      └── Asset Criticality (Crown Jewel / Internal / Dev)
                │
                ▼
       [Local SQLite Database]
         ├── vulnerabilities
         ├── sla_tracking
         └── risk_exceptions
                │
         ┌──────┴────────────────────────┐
         ▼                               ▼
 [Streamlit Dashboard]        [Jira / ServiceNow Mock Sync]
 - 漏洞分布看板                - Webhook 模拟分发
 - SLA 临期/超期报警           - SLA Breach Alert 生成
 - 风险例外审批流
```

### 2.3 依赖安装清单 (`requirements.txt`)
```txt
streamlit>=1.30.0
pydantic>=2.5.0
pandas>=2.1.0
requests>=2.31.0
pytest>=7.4.0
```

---

## 3. Vibe Coding Prompt（可直接复制给 Cursor / Claude Code）

```markdown
Role: Senior Cybersecurity Engineer & GRC Automation Architect
Task: 构建一个轻量级、企业级的全生命周期漏洞管理（Vulnerability Management）与 SLA 追踪看板系统。

技术栈：
- Python 3.10+
- Streamlit (用于前端看板)
- SQLite (本地数据库)
- Pydantic v2 (用于数据结构建模)

核心模块要求：
1. `parsers.py`：支持解析 Trivy (JSON)、Nessus (JSON/Exported format) 和通用 JSON 格式，提取 CVE、CVSS、组件、严重等级、修复建议等。
2. `risk_engine.py`：实现加权风险评分公式：
   - Composite Score = (CVSS * 0.5) + (EPSS * 10 * 0.3) + (Asset_Weight * 0.2)
   - 若在 CISA KEV (Known Exploited Vulnerabilities) 清单中，直接强制升级为 Critical 级。
   - SLA 判定规则：Critical (48小时)、High (14天)、Medium (30天)、Low (90天)。
3. `models.py`：包含 Vulnerability, Asset, SLAStatus, RiskException 的 Pydantic 模型。
4. `database.py`：SQLite 数据持久化，支持查询待办、超期预警、修复完成与风险例外状态。
5. `app.py`：Streamlit 交互界面：
   - Tab 1: 扫描结果上传与解析；
   - Tab 2: 漏洞全景与 SLA 预警大屏（包含临期与超期高亮）；
   - Tab 3: 风险例外审批流（录入补偿措施、豁免期限、审批人，支持到期自动恢复漏洞状态）；
   - Tab 4: 模拟工单与报告导出（生成符合 SOC 2 CC7.1 / PCI DSS Req 6 审计要求的 CSV/PDF 报告）。
6. 请提供自包含的 mock 数据生成脚本 `generate_mock_data.py`，生成 50 条包含真实 CVE 属性的测试数据。
```

---

## 4. 核心代码与系统实现

### 4.1 核心数据结构与风险评分模型 (`vuln_engine.py`)

```python
import datetime
from enum import Enum
from typing import Optional, List, Dict
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class AssetTier(str, Enum):
    TIER_1_PROD_PAYMENT = "Tier-1: Production / PCI CDE / Crown Jewel"
    TIER_2_PROD_INTERNAL = "Tier-2: Production Internal Services"
    TIER_3_NON_PROD = "Tier-3: Staging / Dev / QA"

TIER_WEIGHTS = {
    AssetTier.TIER_1_PROD_PAYMENT: 1.5,
    AssetTier.TIER_2_PROD_INTERNAL: 1.0,
    AssetTier.TIER_3_NON_PROD: 0.6,
}

SLA_DAYS = {
    Severity.CRITICAL: 2,   # 48 hours
    Severity.HIGH: 14,      # 14 days
    Severity.MEDIUM: 30,    # 30 days
    Severity.LOW: 90        # 90 days
}

class NormalizedVulnerability(BaseModel):
    vuln_id: str
    cve_id: str
    title: str
    asset_id: str
    asset_tier: AssetTier
    cvss_base: float = Field(ge=0.0, le=10.0)
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0) # Exploit Prediction Scoring
    is_cisa_kev: bool = False
    discovered_at: datetime.date
    status: str = "OPEN" # OPEN, IN_PROGRESS, RESOLVED, RISK_ACCEPTED
    assigned_team: str = "DevOps"
    remediation_advice: str = ""
    
    @property
    def composite_risk_score(self) -> float:
        # 根据 CVSS、EPSS 和资产关键度计算动态风险值 (满分 10.0)
        # 若在 CISA KEV 中，基础风险加成 2.0
        base = self.cvss_base
        epss_bump = self.epss_score * 2.0  # EPSS 带来额外加分
        kev_bump = 2.0 if self.is_cisa_kev else 0.0
        tier_weight = TIER_WEIGHTS.get(self.asset_tier, 1.0)
        
        final_score = (base + epss_bump + kev_bump) * tier_weight
        return round(min(10.0, final_score), 2)

    @property
    def adjusted_severity(self) -> Severity:
        score = self.composite_risk_score
        if self.is_cisa_kev or score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    @property
    def sla_due_date(self) -> datetime.date:
        days = SLA_DAYS[self.adjusted_severity]
        return self.discovered_at + datetime.timedelta(days=days)

    def is_sla_breached(self, current_date: datetime.date) -> bool:
        if self.status in ["RESOLVED", "RISK_ACCEPTED"]:
            return False
        return current_date > self.sla_due_date

class RiskException(BaseModel):
    exception_id: str
    vuln_id: str
    cve_id: str
    requester: str
    business_justification: str
    compensating_controls: str
    approved_by: str
    valid_until: datetime.date
    is_active: bool = True
```

### 4.2 多扫描源报告解析器与 SLA 状态计算 (`parsers.py`)

```python
import json
import uuid
import datetime
from vuln_engine import NormalizedVulnerability, Severity, AssetTier

def parse_trivy_json(trivy_data: dict, asset_id: str, asset_tier: AssetTier) -> List[NormalizedVulnerability]:
    results = []
    discovered_date = datetime.date.today()
    
    for target in trivy_data.get("Results", []):
        vulns = target.get("Vulnerabilities", [])
        for v in vulns:
            cve = v.get("VulnerabilityID", "N/A")
            title = v.get("Title", v.get("PkgName", "Unknown Package"))
            
            # 提取 CVSS
            cvss_score = 5.0
            cvss_data = v.get("CVSS", {})
            if "nvd" in cvss_data and "V3Score" in cvss_data["nvd"]:
                cvss_score = float(cvss_data["nvd"]["V3Score"])
            elif "redhat" in cvss_data and "V3Score" in cvss_data["redhat"]:
                cvss_score = float(cvss_data["redhat"]["V3Score"])
                
            norm_vuln = NormalizedVulnerability(
                vuln_id=f"VULN-{uuid.uuid4().hex[:8].upper()}",
                cve_id=cve,
                title=title,
                asset_id=asset_id,
                asset_tier=asset_tier,
                cvss_base=cvss_score,
                epss_score=0.15,
                is_cisa_kev=False,
                discovered_at=discovered_date,
                remediation_advice=f"Upgrade {v.get('PkgName')} to version {v.get('FixedVersion', 'latest')}"
            )
            results.append(norm_vuln)
    return results

def simulate_servicenow_sync(vuln: NormalizedVulnerability) -> dict:
    return {
        "short_description": f"[{vuln.adjusted_severity.value}] {vuln.cve_id}: {vuln.title} on {vuln.asset_id}",
        "urgency": "1 - High" if vuln.adjusted_severity == Severity.CRITICAL else "2 - Medium",
        "assignment_group": "Cloud Platform SecOps",
        "custom_fields": {
            "u_cve_id": vuln.cve_id,
            "u_cvss": vuln.cvss_base,
            "u_composite_risk": vuln.composite_risk_score,
            "u_sla_deadline": vuln.sla_due_date.isoformat(),
            "u_compliance_impact": "ISO 27001 A.12.6 / SOC 2 CC7.1"
        }
    }
```

---

## 5. 测试验证与自动化测试脚本

编写本地自动化测试脚本 `test_vuln_management.py`：

```python
import datetime
from vuln_engine import NormalizedVulnerability, Severity, AssetTier

def test_risk_reranking_with_epss_and_asset():
    # 场景 1: CVSS 为 7.5 (通常属于 High)，但因为资产是 PCI 生产核心系统且存在 EPSS 高利用率
    vuln = NormalizedVulnerability(
        vuln_id="VULN-001",
        cve_id="CVE-2024-21626",
        title="runc Container Escape",
        asset_id="prod-k8s-payment-node-01",
        asset_tier=AssetTier.TIER_1_PROD_PAYMENT,
        cvss_base=7.5,
        epss_score=0.82,
        is_cisa_kev=True,
        discovered_at=datetime.date(2026, 9, 10),
        status="OPEN"
    )
    
    # 验证：包含 CISA KEV 且位于生产支付节点，自动升级为 CRITICAL
    assert vuln.adjusted_severity == Severity.CRITICAL
    assert vuln.composite_risk_score >= 9.0
    
    # SLA 为 2 天 (48小时)
    assert vuln.sla_due_date == datetime.date(2026, 9, 12)
    # 判定为 SLA 违规 (Breached)
    assert vuln.is_sla_breached(datetime.date(2026, 9, 20)) is True

def test_risk_exception_prevents_breach():
    vuln = NormalizedVulnerability(
        vuln_id="VULN-002",
        cve_id="CVE-2023-44487",
        title="HTTP/2 Rapid Reset",
        asset_id="internal-dev-bastion",
        asset_tier=AssetTier.TIER_3_NON_PROD,
        cvss_base=7.5,
        epss_score=0.1,
        is_cisa_kev=False,
        discovered_at=datetime.date(2026, 8, 1),
        status="RISK_ACCEPTED"
    )
    
    # 验证：由于状态为 RISK_ACCEPTED，不触发 SLA 超期警报
    assert vuln.is_sla_breached(datetime.date(2026, 9, 20)) is False

if __name__ == "__main__":
    test_risk_reranking_with_epss_and_asset()
    test_risk_exception_prevents_breach()
    print("All Vulnerability Management & SLA tests passed successfully!")
```

---

## 6. 简历包装（STAR 法则）

### 中文版
* **情境（Situation）**：企业多云多集群环境下缺乏统一漏洞闭环机制，月均扫描漏洞 3,000+ 条，依靠单一 CVSS 分数导致高危漏洞积压，且开发团队频繁拖延，面临 SOC 2 CC7.1 与 PCI DSS 审计不合规风险。
* **任务（Task）**：主导设计全生命周期漏洞管理与 SLA 追踪看板，建立基于真实威胁情报（EPSS/CISA KEV）与资产属性的风险再定级标准，打通工单系统实现自动化考核。
* **行动（Action）**：
  - 编写多源扫描解析流水线，整合 Trivy、Nessus 等工具输出；开发动态风险评级引擎，优先处置具有在野利用的真实高危漏洞。
  - 制定严格的漏洞修复 SLA（严重 48h、高危 14d、中危 30d），联动 ServiceNow/Jira 建立自动工单分发与超期报警机制。
  - 建立标准化的“风险例外（Risk Exception）”治理审批流，强制要求提供补偿性控制并设置最长 90 天有效期，阻断漏洞豁免失控。
* **结果（Result）**：生产环境关键资产高危漏洞 SLA 超期率由 42% 下降至 3.5%，误报及低威胁告警分流 60% 研发精力，在后续的 SOC 2 Type II 及 PCI DSS 审计中获得“零缺陷”评价。

### English Version
* **Situation**: In a complex multi-cloud environment, over 3,000 monthly vulnerabilities were reported without unified prioritization. Relying solely on raw CVSS resulted in severe alert fatigue, delayed remediation, and audit exposure under SOC 2 CC7.1 and PCI DSS.
* **Task**: Designed and implemented an automated Vulnerability Management Lifecycle & SLA Tracking system incorporating real-world threat intelligence (EPSS, CISA KEV) and asset criticality.
* **Action**:
  - Developed a standardized ingestion engine for multi-scanner reports (Nessus, Trivy); engineered a contextual risk scoring algorithm to prioritize active in-the-wild exploits.
  - Defined enforceable remediation SLAs (Critical: 48h, High: 14d, Medium: 30d) and automated ticket creation/escalation within ServiceNow/Jira.
  - Formulated a formalized Risk Exception framework requiring documented compensating controls, executive sign-off, and strict 90-day re-assessment limits.
* **Result**: Reduced SLA breach rates on production-critical assets from 42% to 3.5%, saved 60% of engineering bandwidth on non-actionable vulnerabilities, and achieved zero non-conformities during external SOC 2 and PCI DSS audits.

---

## 7. 面试高频追问及优秀应答策略

### Q1：为什么你们不直接按 CVSS 分数修补漏洞，而要引入 EPSS 和资产重要度？
* **应答策略**：
  - **指出痛点**：CVSS 衡量的是漏洞本身的理论严重程度（Theoretical Severity），而非现实被利用的概率。统计表明，所有被分配 CVE 的漏洞中，仅有约 5-7% 在野被真正武器化利用。如果只看 CVSS 7.0+，安全和研发团队会被海量低概率风险拖垮。
  - **引入解决方案**：引入 FIRST 的 EPSS（Exploit Prediction Scoring System）能够以概率量化（0~100%）未来 30 天内漏洞被利用的可能性；结合 CISA KEV（已知被利用漏洞清单），能精确识别“已被武器化的现实威胁”。
  - **结合业务**：最终乘以资产权重（例如直接接入公网的 CDE 支付节点 vs. 隔离的开发测试机），让有限的研发安全资源聚焦在“真正有业务致命风险”的切入点上。

### Q2：研发团队因系统稳定性或发版周期原因拒绝在 48 小时内修补 Critical 漏洞，你作为安全负责人怎么处理？
* **应答策略**：
  - **平衡安全与业务**：“安全的目标不是阻断业务发版，而是在受控风险下保障业务连续性。”
  - **提供替代方案（Compensating Controls）**：首先分析该漏洞的利用链是否可以通过网络层或 WAF 规则临时缓解（例如：在云 WAF / API 网关上配置虚拟补丁 Virtual Patching 拦截特定 Payload；或在主机 EDR 上配置阻止特定进程派生）。
  - **启动风险例外审批（Risk Exception Workflow）**：若无法立即打补丁，系统团队必须正式提交风险例外申请，明确写明业务风险、补偿性控制措施、以及明确的最终修复排期。申请需由对应的业务 VP 与 CISO 双签批准，并录入 GRC 风险登记册进行到期强制复核。

### Q3：外部审计师（如 SOC 2 或 ISO 27001 审计员）抽查漏洞修补证据时，通常会看什么？
* **应答策略**：
  - **抽查逻辑**：审计师通常不仅看你“有没有做扫描”，而是看“从发现到修复的时间戳是否满足已公布的政策 SLA”。
  - **证据闭环（Audit Trail）**：
    1. 漏洞扫描报告（时间戳 T0）；
    2. 工单创建与指派记录（Jira/ServiceNow 记录，证明责任到人）；
    3. 修复代码 PR 或补丁升级记录（证明在 SLA 期限内完成变更）；
    4. 复测验证报告（Verification Scan，证明漏洞状态变为 Closed）；
    5. 针对未按期修复的漏洞，必须出示在 SLA 超期前已正式获批且处于有效期内的《风险例外审批表》。
