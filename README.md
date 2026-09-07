# SM-Audit-Log-Center

统一审计与日志中心：事件接入、检索、SM3 完整性链、异常检测与合规报表。

## 本地运行

```powershell
git clone https://github.com/luoshitianchen/SM-Audit-Log-Center.git
cd SM-Audit-Log-Center
py -3.11 -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8320
```

访问：`http://127.0.0.1:8320/`

## 企业能力

- 事件接入（SM3 完整性 + 链式哈希，防篡改）
- 完整性校验与篡改检测（`GET /api/audit/verify`）
- 检索过滤（按服务 / 动作 / 操作者 / 时间）
- 合规报表（`GET /api/audit/stats`）
- 异常检测与告警（未知服务 / 完整性不符 / 高频突发 / 事件重放）
- 告警推送联动企业通知中心
- `/health` 健康探针、`/readyz` 就绪探针
- `/api/overview` 业务概览、`/api/ops/metrics` 运维指标、`/metrics` Prometheus 指标
- `/api/integration/manifest` 服务契约、`/api/security/baseline` 安全基线
- 国密 SM3 / SM4-CBC（带 SM3 MAC 完整性校验，防密文篡改）
- 安全响应头、CSP、TrustedHost、限流、请求体限制、内部写入令牌
- Docker 只读文件系统、能力剥离、进程限制
- GitHub Actions CI 与安全扫描（pip-audit / bandit / ruff / SBOM / gitleaks）

## 异常检测与告警（安全运营）

接入审计事件时自动执行检测规则，命中即生成告警并纳入台账：

| 规则 | 级别 | 说明 |
|---|---|---|
| `unknown_service` | high | 未登记/未纳管服务上报，疑似伪造 |
| `integrity_mismatch` | high | 事件完整性摘要与重算不符，疑似篡改 |
| `rate_burst` | medium | 同一操作者在窗口内高频写入，疑似滥用/暴力 |
| `replay_duplicate` | medium | 重复事件 ID，疑似重放攻击 |

端点：

- `GET /api/audit/anomalies`：实时异常概览（未处置告警数、规则/服务分布、最近告警）
- `GET /api/audit/alerts`：告警台账（按状态 / 级别 / 服务过滤 + 分页）
- `GET /api/audit/alerts/{alert_id}`：告警详情
- `POST /api/audit/alerts/{alert_id}/ack`：确认告警并留痕（`note`）

阈值可通过环境变量配置：`SM_ALERT_KNOWN_SERVICES`（服务白名单，逗号分隔）、`SM_ALERT_RATE_BURST_WINDOW`（秒）、`SM_ALERT_RATE_BURST_THRESHOLD`（条数）。

### 告警推送（联动企业通知中心）

- 配置 `SM_NOTIFICATION_CENTER_URL` 后，告警产生即异步推送至通知中心 `POST /api/notifications/alert`（携带 `X-Internal-Token`），自动进入 `security-alert` 渠道台账并即时投递。
- 未配置该变量时行为不变（仅本地告警台账，不影响写入性能）。

## 安全说明

- SM4 密钥仅允许通过环境变量 `SM4_KEY_HEX`（或企业 KMS/HSM）注入，禁止写入代码或数据库。
- 生产环境（`SM_ENV=production`）未配置任何凭据时，受保护接口一律拒绝（fail-closed）。
- 写接口必须携带 `X-Internal-Token`（对应 `SM_INTERNAL_API_KEY`）。

## 质量门禁

```powershell
.\quality.ps1
```

## 企业维护资料

- [安全基线](SECURITY_BASELINE.md)
- [运维与可观测性](OPERATIONS.md)
- [应急响应手册](INCIDENT_RESPONSE.md)
- [生产部署检查清单](DEPLOYMENT_CHECKLIST.md)
- [变更记录](CHANGELOG.md)
- [版本号](VERSION)
