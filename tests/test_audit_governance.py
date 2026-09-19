"""审计中心业务深化测试：归档/导出/保留策略全生命周期。"""
from __future__ import annotations

H = {"X-Internal-Token": "test-internal-key-12345"}
BAD = {"X-Internal-Token": "wrong"}


# ═══════════════════════════════════════════════════════════
# 审计归档
# ═══════════════════════════════════════════════════════════

class TestAuditArchive:
    async def test_create_archive_success(self, client):
        resp = await client.post("/api/audit/archives", json={
            "archive_name": "arch-2026-09", "period": "2026-09",
            "record_count": 1200, "storage_uri": "s3://audit/2026-09.tar.gz",
            "note": "月度归档",
        }, headers=H)
        assert resp.status_code == 201
        data = resp.json()
        assert data["archive_name"] == "arch-2026-09"
        assert data["status"] == "in_progress"
        assert data["record_count"] == 1200

    async def test_create_archive_duplicate_name(self, client):
        payload = {"archive_name": "arch-dup", "period": "2026-09"}
        first = await client.post("/api/audit/archives", json=payload, headers=H)
        assert first.status_code == 201
        second = await client.post("/api/audit/archives", json=payload, headers=H)
        assert second.status_code == 409

    async def test_create_archive_requires_token(self, client):
        resp = await client.post("/api/audit/archives", json={
            "archive_name": "arch-notoken", "period": "2026-09",
        })
        assert resp.status_code in (401, 403)

    async def test_create_archive_invalid_period(self, client):
        resp = await client.post("/api/audit/archives", json={
            "archive_name": "arch-bad", "period": "09-2026",
        }, headers=H)
        assert resp.status_code == 422

    async def test_list_archives_filter_and_keyword(self, client):
        await client.post("/api/audit/archives", json={
            "archive_name": "arch-search", "period": "2026-08", "note": "季度归档任务",
        }, headers=H)
        resp = await client.get("/api/audit/archives?period=2026-08&keyword=季度", headers=H)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert data["items"][0]["period"] == "2026-08"

    async def test_finish_archive_completed(self, client):
        create = await client.post("/api/audit/archives", json={
            "archive_name": "arch-done", "period": "2026-07",
        }, headers=H)
        archive_id = create.json()["id"]
        resp = await client.post(f"/api/audit/archives/{archive_id}/finish", json={
            "status": "completed", "record_count": 500, "storage_uri": "s3://x/ok",
        }, headers=H)
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"
        assert resp.json()["record_count"] == 500

    async def test_finish_archive_already_terminal_rejected(self, client):
        create = await client.post("/api/audit/archives", json={
            "archive_name": "arch-term", "period": "2026-06",
        }, headers=H)
        archive_id = create.json()["id"]
        await client.post(f"/api/audit/archives/{archive_id}/finish", json={
            "status": "completed",
        }, headers=H)
        resp = await client.post(f"/api/audit/archives/{archive_id}/finish", json={
            "status": "failed",
        }, headers=H)
        assert resp.status_code == 409

    async def test_get_archive_not_found(self, client):
        resp = await client.get("/api/audit/archives/nonexistent", headers=H)
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════
# 审计导出任务
# ═══════════════════════════════════════════════════════════

class TestAuditExport:
    async def test_create_export_success(self, client):
        resp = await client.post("/api/audit/exports", json={
            "export_format": "csv", "query_filter": "action=user.login",
            "requested_by": "auditor",
        }, headers=H)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "pending"
        assert data["export_format"] == "csv"
        assert data["requested_by"] == "auditor"

    async def test_export_state_machine_pending_to_running(self, client):
        create = await client.post("/api/audit/exports", json={
            "export_format": "json", "query_filter": "period=2026",
        }, headers=H)
        export_id = create.json()["id"]
        resp = await client.patch(f"/api/audit/exports/{export_id}/progress", json={
            "status": "running",
        }, headers=H)
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"

    async def test_export_state_machine_running_to_completed(self, client):
        create = await client.post("/api/audit/exports", json={
            "export_format": "csv",
        }, headers=H)
        export_id = create.json()["id"]
        await client.patch(f"/api/audit/exports/{export_id}/progress", json={
            "status": "running",
        }, headers=H)
        resp = await client.patch(f"/api/audit/exports/{export_id}/progress", json={
            "status": "completed", "file_uri": "/tmp/out.csv", "row_count": 42,
        }, headers=H)
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"
        assert resp.json()["row_count"] == 42
        assert resp.json()["finished_at"] is not None

    async def test_export_invalid_transition_rejected(self, client):
        create = await client.post("/api/audit/exports", json={
            "export_format": "csv",
        }, headers=H)
        export_id = create.json()["id"]
        # pending 直接到 completed 不允许
        resp = await client.patch(f"/api/audit/exports/{export_id}/progress", json={
            "status": "completed",
        }, headers=H)
        assert resp.status_code == 409

    async def test_export_failed_with_error(self, client):
        create = await client.post("/api/audit/exports", json={
            "export_format": "csv",
        }, headers=H)
        export_id = create.json()["id"]
        await client.patch(f"/api/audit/exports/{export_id}/progress", json={
            "status": "running",
        }, headers=H)
        resp = await client.patch(f"/api/audit/exports/{export_id}/progress", json={
            "status": "failed", "error": "磁盘已满",
        }, headers=H)
        assert resp.status_code == 200
        assert resp.json()["status"] == "failed"
        assert "磁盘" in resp.json()["error"]

    async def test_list_exports_filter_and_keyword(self, client):
        await client.post("/api/audit/exports", json={
            "export_format": "json", "query_filter": "action=admin",
            "requested_by": "ops-team",
        }, headers=H)
        resp = await client.get("/api/audit/exports?keyword=admin", headers=H)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    async def test_get_export_not_found(self, client):
        resp = await client.get("/api/audit/exports/nonexistent", headers=H)
        assert resp.status_code == 404

    async def test_create_export_bad_format_rejected(self, client):
        resp = await client.post("/api/audit/exports", json={
            "export_format": "xml",
        }, headers=H)
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════
# 审计保留策略
# ═══════════════════════════════════════════════════════════

class TestRetentionPolicy:
    async def test_create_policy_success(self, client):
        resp = await client.post("/api/audit/retention-policies", json={
            "name": "pci-policy", "action_prefix": "payment.",
            "retention_days": 180, "is_enabled": True,
            "description": "PCI 事件保留半年",
        }, headers=H)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "pci-policy"
        assert data["retention_days"] == 180
        assert data["is_enabled"] is True

    async def test_create_policy_duplicate_name(self, client):
        payload = {"name": "p-dup", "retention_days": 30}
        first = await client.post("/api/audit/retention-policies", json=payload, headers=H)
        assert first.status_code == 201
        second = await client.post("/api/audit/retention-policies", json=payload, headers=H)
        assert second.status_code == 409

    async def test_create_policy_requires_token(self, client):
        resp = await client.post("/api/audit/retention-policies", json={
            "name": "p-notoken", "retention_days": 30,
        }, headers=BAD)
        assert resp.status_code in (401, 403)

    async def test_create_policy_days_out_of_range(self, client):
        resp = await client.post("/api/audit/retention-policies", json={
            "name": "p-bad", "retention_days": 0,
        }, headers=H)
        assert resp.status_code == 422

    async def test_list_policies_enabled_filter(self, client):
        await client.post("/api/audit/retention-policies", json={
            "name": "p-disabled", "retention_days": 10, "is_enabled": False,
        }, headers=H)
        resp = await client.get("/api/audit/retention-policies?enabled=false", headers=H)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert all(p["is_enabled"] is False for p in data["items"])

    async def test_update_policy(self, client):
        create = await client.post("/api/audit/retention-policies", json={
            "name": "p-upd", "retention_days": 30,
        }, headers=H)
        policy_id = create.json()["id"]
        resp = await client.patch(f"/api/audit/retention-policies/{policy_id}", json={
            "retention_days": 90, "is_enabled": False,
        }, headers=H)
        assert resp.status_code == 200
        assert resp.json()["retention_days"] == 90
        assert resp.json()["is_enabled"] is False

    async def test_get_policy_not_found(self, client):
        resp = await client.get("/api/audit/retention-policies/nonexistent", headers=H)
        assert resp.status_code == 404

    async def test_delete_policy(self, client):
        create = await client.post("/api/audit/retention-policies", json={
            "name": "p-del", "retention_days": 30,
        }, headers=H)
        policy_id = create.json()["id"]
        resp = await client.delete(f"/api/audit/retention-policies/{policy_id}", headers=H)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True
