# Changelog

## 2.1.0 - 2026-09-01

- 新增异常检测与告警层（安全运营）：
  - 未知服务上报检测（未纳管/疑似伪造，high）。
  - 事件完整性摘要与重算不符检测（疑似篡改，high）。
  - 同一操作者窗口内高频写入检测（疑似滥用/暴力，medium）。
  - 重复事件 ID 检测（疑似重放攻击，medium）。
- 新增端点：`GET /api/audit/anomalies`、`GET /api/audit/alerts`、`GET /api/audit/alerts/{id}`、`POST /api/audit/alerts/{id}/ack`。
- 告警阈值可通过 `SM_ALERT_KNOWN_SERVICES` / `SM_ALERT_RATE_BURST_WINDOW` / `SM_ALERT_RATE_BURST_THRESHOLD` 环境变量配置；告警支持确认（acknowledged）留痕闭环。
- `/api/audit/stats` 增加 `alerts.open` 统计；`/api/overview` 增加 `open_alerts`。
- 新增 5 个领域测试，测试套件 13 用例全部通过。

## 2.0.0 - 2026-08-31

- 落地真实领域能力：统一审计与日志中心：事件接入、检索、SM3 完整性链与合规报表。
- 抽取共享企业基础层 `app/base.py`：安全中间件、限流、请求体限制、国密 SM3/SM4-CBC（带 SM3 MAC 完整性校验）、JWT、审计转发与指标统一承载。
- 修复安全缺陷：SM4 密钥不再明文落库（仅环境变量/KMS 注入）；密文增加完整性 MAC；生产环境未配置凭据时 fail-closed。
- 统一版本到 2.0.0，消除代码 / VERSION 文件 / 服务目录三处版本漂移。
- 强化 CI：新增 ruff、覆盖率门禁（≥70%）与编译检查。
- 新增 SECURITY.md、.env.example、requirements-dev.txt 与统一运维文档。

## 1.1.0

- 统一企业级安全基线文档。
- 增加可观测性与运维检查说明。
- 增加依赖锁定快照，降低部署环境漂移风险。

## 1.0.0

- 初始化企业服务骨架。
- 提供健康检查、就绪检查、基础业务接口与安全响应头。
