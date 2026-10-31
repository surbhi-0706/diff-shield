import os
import sys
import tempfile
import unittest
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
import main
import quarantine_store


class QuarantineStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            os.environ,
            {"DIFFSHIELD_QUARANTINE_DB": str(Path(self.temp_dir.name) / "test.db")},
        )
        self.environment.start()
        quarantine_store.init_db()

    def tearDown(self):
        self.environment.stop()
        self.temp_dir.cleanup()

    def record_suspicious_scan(self, head_sha="abc123"):
        return quarantine_store.record_scan(
            repository="example/project",
            pr_number=42,
            pr_url="https://github.com/example/project/pull/42",
            pr_author="contributor",
            head_sha=head_sha,
            base_sha="base123",
            finding={
                "id": "DS-FIND-42",
                "title": "Removed security guard",
                "severity": "HIGH",
            },
            risk_score=92,
            confidence=0.85,
        )

    def test_quarantine_deadline_is_exactly_twelve_hours_and_persistent(self):
        record = self.record_suspicious_scan()

        started = datetime.fromisoformat(record["quarantine_started_at"])
        deadline = datetime.fromisoformat(record["review_deadline"])
        self.assertEqual(deadline - started, timedelta(hours=12))
        self.assertEqual(record["state"], "QUARANTINED")
        self.assertEqual(record["pr_author"], "contributor")
        self.assertEqual(record["head_sha"], "abc123")

        persisted = quarantine_store.get_quarantine(record["finding_id"])
        self.assertEqual(persisted, record)

    def test_duplicate_commit_updates_one_scan_and_preserves_active_hold(self):
        first = self.record_suspicious_scan()
        second = quarantine_store.record_scan(
            repository="example/project",
            pr_number=42,
            pr_url="https://github.com/example/project/pull/42",
            pr_author="contributor",
            head_sha="abc123",
            base_sha="base123",
            finding=None,
            risk_score=0,
        )

        self.assertEqual(second["finding_id"], first["finding_id"])
        self.assertEqual(second["state"], "QUARANTINED")
        self.assertEqual(second["review_deadline"], first["review_deadline"])
        self.assertEqual(len(quarantine_store.list_quarantines()), 1)

    def test_deadline_escalates_without_releasing_quarantine(self):
        record = self.record_suspicious_scan()
        deadline = datetime.fromisoformat(record["review_deadline"])

        changed = quarantine_store.expire_overdue(
            now=deadline + timedelta(microseconds=1),
        )
        escalated = quarantine_store.get_quarantine(record["finding_id"])

        self.assertEqual(changed, 1)
        self.assertEqual(escalated["state"], "ESCALATED")
        self.assertEqual(len(escalated["review_history"]), 1)
        self.assertEqual(
            quarantine_store.list_quarantines(active_only=True)[0]["state"],
            "ESCALATED",
        )

    def test_clean_scan_does_not_create_quarantine(self):
        record = quarantine_store.record_scan(
            repository="example/project",
            pr_number=43,
            pr_url="https://github.com/example/project/pull/43",
            pr_author="contributor",
            head_sha="clean-sha",
            base_sha="base123",
            finding=None,
            risk_score=0,
        )

        self.assertEqual(record["state"], "CLEAN")
        self.assertIsNone(record["quarantine_started_at"])
        self.assertIsNone(record["review_deadline"])
        self.assertEqual(quarantine_store.list_quarantines(active_only=True), [])

    def test_resolution_requires_authorized_reviewer_and_records_audit(self):
        finding = self.record_suspicious_scan()
        client = TestClient(main.app)
        token = "reviewer-secret-value-with-at-least-32-characters"
        with patch.dict(
            os.environ,
            {"DIFFSHIELD_REVIEWER_TOKENS": f'{{"security-reviewer":"{token}"}}'},
        ):
            unauthorized = client.post(
                f"/api/quarantines/{finding['finding_id']}/resolve",
                json={"decision": "RESOLVED", "reason": "Reviewed"},
            )
            self.assertEqual(unauthorized.status_code, 401)

            rejected = client.post(
                f"/api/quarantines/{finding['finding_id']}/resolve",
                headers={"Authorization": "Bearer not-the-token"},
                json={"decision": "RESOLVED", "reason": "Reviewed"},
            )
            self.assertEqual(rejected.status_code, 403)

            resolved = client.post(
                f"/api/quarantines/{finding['finding_id']}/resolve",
                headers={"Authorization": f"Bearer {token}"},
                json={"decision": "RESOLVED", "reason": "Patch verified"},
            )

        self.assertEqual(resolved.status_code, 200, resolved.text)
        result = resolved.json()
        self.assertEqual(result["state"], "RESOLVED")
        self.assertEqual(result["reviewer_identity"], "security-reviewer")
        self.assertEqual(result["resolution_reason"], "Patch verified")
        self.assertEqual(result["review_history"][-1]["reviewer"], "security-reviewer")
        self.assertEqual(result["merge_protection"]["status"], "NOT_ENFORCED")

    def test_quarantine_endpoints_report_actual_persistence_and_enforcement(self):
        finding = self.record_suspicious_scan()
        client = TestClient(main.app)

        listed = client.get("/api/quarantines?active_only=true")
        detail = client.get(f"/api/quarantines/{finding['finding_id']}")
        status = client.get("/api/github/status")

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()["items"][0]["finding_id"], finding["finding_id"])
        self.assertEqual(detail.json()["state"], "QUARANTINED")
        self.assertEqual(status.json()["merge_protection"], "NOT_ENFORCED")

    def test_webhook_rejects_invalid_signature(self):
        client = TestClient(main.app)
        with patch.dict(os.environ, {"GITHUB_WEBHOOK_SECRET": "webhook-secret"}):
            response = client.post(
                "/api/github/webhook",
                content=b'{"action":"opened"}',
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": "delivery-1",
                    "X-Hub-Signature-256": "sha256=invalid",
                },
            )
        self.assertEqual(response.status_code, 401)

    def test_signed_installation_webhooks_record_creation_and_removal(self):
        secret = "webhook-secret"
        client = TestClient(main.app)
        with patch.dict(
            os.environ,
            {
                "GITHUB_WEBHOOK_SECRET": secret,
                "DIFFSHIELD_QUARANTINE_DB": str(
                    Path(self.temp_dir.name) / "installation-webhook.db"
                ),
            },
        ):
            for action, delivery, expected_state in (
                ("created", "installation-created", "INSTALLED"),
                ("deleted", "installation-deleted", "REMOVED"),
            ):
                body = json.dumps(
                    {
                        "action": action,
                        "installation": {
                            "id": 77,
                            "account": {"login": "example"},
                        },
                    }
                ).encode()
                signature = "sha256=" + hmac.new(
                    secret.encode(), body, hashlib.sha256
                ).hexdigest()
                response = client.post(
                    "/api/github/webhook",
                    content=body,
                    headers={
                        "X-GitHub-Event": "installation",
                        "X-GitHub-Delivery": delivery,
                        "X-Hub-Signature-256": signature,
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(
                    response.json()["installation_state"], expected_state
                )
                self.assertEqual(
                    quarantine_store.get_github_installation(77)["state"],
                    expected_state,
                )

    def test_webhook_deduplicates_signed_pull_request_deliveries(self):
        secret = "webhook-secret"
        body = json.dumps(
            {
                "action": "opened",
                "repository": {"full_name": "example/project"},
                "pull_request": {"number": 42},
            }
        ).encode()
        signature = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()
        headers = {
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-42",
            "X-Hub-Signature-256": signature,
        }
        client = TestClient(main.app)
        result = {
            "status": "PASSED",
            "quarantine": {"state": "CLEAN"},
            "merge_protection": {"status": "NOT_ENFORCED"},
        }

        with (
            patch.dict(
                os.environ,
                {
                    "GITHUB_WEBHOOK_SECRET": secret,
                    "DIFFSHIELD_QUARANTINE_DB": str(
                        Path(self.temp_dir.name) / "webhook.db"
                    ),
                },
            ),
            patch.object(main, "analyze_pr", new_callable=AsyncMock) as analyze,
        ):
            analyze.return_value = result
            first = client.post("/api/github/webhook", content=body, headers=headers)
            duplicate = client.post("/api/github/webhook", content=body, headers=headers)

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["status"], "processed")
        self.assertEqual(first.json()["quarantine_state"], "CLEAN")
        self.assertEqual(duplicate.json()["status"], "duplicate")
        analyze.assert_awaited_once()

    def test_webhook_rejects_invalid_repository_identity(self):
        secret = "webhook-secret"
        body = json.dumps(
            {
                "action": "opened",
                "repository": {"full_name": "../project"},
                "pull_request": {"number": 42},
            }
        ).encode()
        signature = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()
        client = TestClient(main.app)
        with patch.dict(os.environ, {"GITHUB_WEBHOOK_SECRET": secret}):
            response = client.post(
                "/api/github/webhook",
                content=body,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": "invalid-repository-delivery",
                    "X-Hub-Signature-256": signature,
                },
            )
        self.assertEqual(response.status_code, 400)

    def test_signed_app_webhook_quarantines_and_fails_required_check(self):
        secret = "webhook-secret"
        body = json.dumps(
            {
                "action": "opened",
                "installation": {
                    "id": 77,
                    "account": {"login": "example"},
                },
                "repository": {"full_name": "example/project"},
                "pull_request": {"number": 42},
            }
        ).encode()
        signature = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()
        client = TestClient(main.app)
        metadata = {
            "title": "Example change",
            "user": {"login": "contributor"},
            "head": {"sha": "a" * 40},
            "base": {"sha": "b" * 40, "ref": "main"},
        }
        finding = {
            "id": "DS-APP-42",
            "title": "Security guard regression",
            "severity": "HIGH",
            "description": "A security guard was removed.",
        }
        with (
            patch.dict(
                os.environ,
                {
                    "GITHUB_WEBHOOK_SECRET": secret,
                    "GITHUB_APP_ID": "321",
                    "GITHUB_APP_PRIVATE_KEY": "test-key-not-used",
                    "DIFFSHIELD_QUARANTINE_DB": str(
                        Path(self.temp_dir.name) / "app-webhook.db"
                    ),
                },
            ),
            patch.object(
                main.github_app,
                "fetch_pull_request",
                new_callable=AsyncMock,
                return_value=(metadata, "test diff", "installation-token"),
            ),
            patch.object(
                main.github_app,
                "installation_token",
                new_callable=AsyncMock,
                return_value="installation-token",
            ),
            patch.object(
                main.github_app,
                "create_check_run",
                new_callable=AsyncMock,
                return_value=123,
            ) as create_check,
            patch.object(
                main.github_app,
                "required_check_configured",
                new_callable=AsyncMock,
                return_value=(True, "Required check is configured."),
            ),
            patch.object(
                main.github_app,
                "complete_check_run",
                new_callable=AsyncMock,
            ) as complete_check,
            patch.object(
                main.github_app,
                "notify_pull_request",
                new_callable=AsyncMock,
            ) as notify,
            patch.object(
                main.regression_engine,
                "analyze_diff",
                return_value={
                    "status": "QUARANTINE_HOLD",
                    "is_regression": True,
                    "risk_score": 92,
                    "hold_hours": 12,
                    "finding": finding,
                },
            ),
        ):
            response = client.post(
                "/api/github/webhook",
                content=body,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": "app-delivery-42",
                    "X-Hub-Signature-256": signature,
                },
            )
            status = client.get("/api/github/status?repository=example/project")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["quarantine_state"], "QUARANTINED")
        self.assertEqual(response.json()["merge_protection"]["status"], "ENFORCED")
        create_check.assert_awaited_once()
        complete_check.assert_awaited_once()
        self.assertEqual(complete_check.await_args.kwargs["conclusion"], "failure")
        notify.assert_awaited_once()
        self.assertTrue(status.json()["installed"])
        self.assertTrue(status.json()["required_check_configured"])
        self.assertEqual(status.json()["merge_protection"], "ENFORCED")


if __name__ == "__main__":
    unittest.main()
