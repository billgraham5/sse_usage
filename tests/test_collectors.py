from __future__ import annotations

import tempfile
import time
import unittest
from unittest.mock import patch

from sse_user_counter.cache import CorrelationCache
from sse_user_counter.collectors import (
    SWG,
    VPN,
    ZTNA,
    UsageCollector,
    correlate_roaming_computers,
    extract_identity_labels,
    filter_active_ztna_devices,
    summarize_vpn_events,
)
from sse_user_counter.http import ApiError
from sse_user_counter.models import Product, RoamingComputer, RunConfig, ServiceReport, ServiceRow
from sse_user_counter.reports import build_correlated_rows


class CollectorTests(unittest.TestCase):
    def test_correlate_roaming_computers_maps_user_to_device(self) -> None:
        report = correlate_roaming_computers(
            roaming_computers=[
                RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected"),
                RoamingComputer(device_id="A2", computer_name="wkst3", swg_status="Protected"),
            ],
            proxy_events=[
                {
                    "timestamp": 1710000000000,
                    "identities": [
                        {"label": "wkst2", "type": {"type": "anyconnect"}},
                        {"label": "alice@example.com", "type": {"type": "directory_user"}},
                    ],
                }
            ],
            product=Product.SECURE_ACCESS,
        )

        self.assertEqual(report.service_type, SWG)
        self.assertEqual(report.primary_count, 2)
        self.assertEqual(report.unique_users, 1)
        self.assertEqual(len(report.rows), 2)
        mapped = [row for row in report.rows if row.user_name]
        unmapped = [row for row in report.rows if not row.user_name]
        self.assertEqual(mapped[0].user_name, "alice@example.com")
        self.assertEqual(unmapped[0].computer_name, "wkst3")

    def test_summarize_vpn_events_deduplicates_users(self) -> None:
        report = summarize_vpn_events(
            events=[
                {
                    "timestamp": 1710000000,
                    "osversion": "Windows 11",
                    "identities": [{"label": "alice@example.com", "type": {"type": "directory_user"}}],
                },
                {
                    "timestamp": 1711000000,
                    "osversion": "Windows 11",
                    "identities": [{"label": "alice@example.com", "type": {"type": "directory_user"}}],
                },
            ],
            product=Product.SECURE_ACCESS,
        )

        self.assertEqual(report.service_type, VPN)
        self.assertEqual(report.primary_count, 1)
        self.assertEqual(report.unique_users, 1)
        self.assertEqual(report.rows[0].event_count, 2)

    def test_filter_active_ztna_devices_only_returns_active_certificates(self) -> None:
        rows = filter_active_ztna_devices(
            user_name="alice@example.com",
            device_payload={
                "devices": [
                    {
                        "deviceId": "device-1",
                        "certificates": [{"status": "active", "createdAt": "2024-01-01T00:00:00Z", "expiresAt": "2024-03-01T00:00:00Z"}],
                    },
                    {
                        "deviceId": "device-2",
                        "certificates": [{"status": "revoked", "createdAt": "2024-01-01T00:00:00Z", "expiresAt": "2024-03-01T00:00:00Z"}],
                    },
                ]
            },
            product=Product.SECURE_ACCESS,
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].device_id, "device-1")
        self.assertEqual(rows[0].service_type, ZTNA)

    def test_build_correlated_rows_merges_services(self) -> None:
        reports = {
            SWG: ServiceReport(
                service_type=SWG,
                supported=True,
                rows=[
                    ServiceRow(
                        user_name="alice@example.com",
                        computer_name="wkst2",
                        service_type=SWG,
                        source_product=Product.SECURE_ACCESS.display_name,
                    )
                ],
            ),
            VPN: ServiceReport(
                service_type=VPN,
                supported=True,
                rows=[
                    ServiceRow(
                        user_name="alice@example.com",
                        computer_name="",
                        service_type=VPN,
                        source_product=Product.SECURE_ACCESS.display_name,
                        last_seen="2024-03-01T00:00:00+00:00",
                    )
                ],
            ),
            ZTNA: ServiceReport(
                service_type=ZTNA,
                supported=True,
                rows=[
                    ServiceRow(
                        user_name="alice@example.com",
                        computer_name="",
                        service_type=ZTNA,
                        source_product=Product.SECURE_ACCESS.display_name,
                        device_id="device-1",
                    )
                ],
            ),
        }

        rows = build_correlated_rows(reports)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["services"], "SWG, VPN, ZTNA")
        self.assertEqual(rows[0]["swg_computers"], "wkst2")
        self.assertEqual(rows[0]["ztna_device_ids"], "device-1")

    def test_extract_identity_labels_ignores_non_dict_records(self) -> None:
        users, devices = extract_identity_labels(
            [
                "bad-record",
                {"label": "alice@example.com", "type": {"type": "directory_user"}},
                {"label": "wkst2", "type": {"type": "anyconnect"}},
            ]
        )
        self.assertEqual(users, ["alice@example.com"])
        self.assertEqual(devices, ["wkst2"])

    def test_fetch_ztna_user_summaries_batch_skips_not_found_ids(self) -> None:
        class FakeClient:
            def request_json(self, scope: str, path: str, *, params=None, method="GET", body=None):
                self.last_scope = scope
                self.last_path = path
                batch = params["userIds"].split(",")
                if "missing" in batch:
                    if len(batch) == 1:
                        raise ApiError("HTTP 404", status_code=404, url="https://example.invalid")
                    raise ApiError("HTTP 404", status_code=404, url="https://example.invalid")
                return {"users": [{"userId": user_id, "deviceCertificateCounts": {"active": 0}} for user_id in batch]}

        collector = UsageCollector(
            client=FakeClient(),
            config=RunConfig(
                product=Product.SECURE_ACCESS,
                output_dir=__import__("pathlib").Path("output"),
            ),
        )

        summaries, skipped = collector._fetch_ztna_user_summaries_batch(["good-1", "missing", "good-2"])
        self.assertEqual([summary["userId"] for summary in summaries], ["good-1", "good-2"])
        self.assertEqual(skipped, ["missing"])

    def test_collect_ztna_returns_unsupported_on_forbidden(self) -> None:
        class FakeClient:
            def request_json(self, scope: str, path: str, *, params=None, method="GET", body=None):
                if path == "/identities":
                    return {"data": [{"id": "user-1", "label": "alice@example.com", "type": {"type": "directory_user"}}]}
                if path == "/ztna/userSummaries":
                    raise ApiError("HTTP 403", status_code=403, url="https://example.invalid")
                raise AssertionError(f"Unexpected path {path}")

        collector = UsageCollector(
            client=FakeClient(),
            config=RunConfig(
                product=Product.SECURE_ACCESS,
                output_dir=__import__("pathlib").Path("output"),
            ),
        )

        report = collector.collect_ztna()
        self.assertFalse(report.supported)
        self.assertEqual(report.primary_count, 0)
        self.assertTrue(any("admin.ztna.users:read" in note for note in report.notes))

    def test_collect_swg_uses_targeted_correlation(self) -> None:
        class TargetedCollector(UsageCollector):
            def _list_roaming_computers(self) -> list[RoamingComputer]:
                return [
                    RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected", last_sync="2024-09-19T10:34:30.000Z"),
                    RoamingComputer(device_id="A2", computer_name="wkst3", swg_status="Protected", last_sync="2024-09-19T10:35:30.000Z"),
                ]

            def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
                return {"wkst2": "identity-1", "wkst3": "identity-2"}

            def _find_user_for_swg_device(self, identity_id: str) -> tuple[str, str, str]:
                if identity_id == "identity-1":
                    return "alice@example.com", "2024-09-19T10:34:30.000Z", "2024-09-19T10:34:30.000Z"
                return "", "", ""

        progress_messages: list[str] = []
        collector = TargetedCollector(
            client=object(),
            config=RunConfig(
                product=Product.SECURE_ACCESS,
                output_dir=__import__("pathlib").Path("output"),
            ),
            progress_callback=progress_messages.append,
        )

        report = collector.collect_swg()
        self.assertEqual(report.primary_count, 2)
        self.assertEqual(report.unique_users, 1)
        self.assertEqual([row.computer_name for row in report.rows], ["wkst2", "wkst3"])
        self.assertEqual(report.rows[0].user_name, "alice@example.com")
        self.assertEqual(report.rows[1].user_name, "")
        self.assertTrue(any("top-identities plus up to" in note for note in report.notes))
        self.assertTrue(any("targeted proxy lookups" in message for message in progress_messages))

    def test_collect_swg_falls_back_to_inventory_when_targeted_correlation_fails(self) -> None:
        class FallbackCollector(UsageCollector):
            def _list_roaming_computers(self) -> list[RoamingComputer]:
                return [
                    RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected", last_sync="2024-09-19T10:34:30.000Z"),
                ]

            def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
                raise ApiError("HTTP 403", status_code=403, url="https://example.invalid")

        progress_messages: list[str] = []
        collector = FallbackCollector(
            client=object(),
            config=RunConfig(
                product=Product.SECURE_ACCESS,
                output_dir=__import__("pathlib").Path("output"),
            ),
            progress_callback=progress_messages.append,
        )

        report = collector.collect_swg()
        self.assertEqual(report.primary_count, 1)
        self.assertEqual(report.unique_users, 0)
        self.assertEqual(report.rows[0].computer_name, "wkst2")
        self.assertEqual(report.rows[0].user_name, "")
        self.assertTrue(any("inventory only" in note for note in report.notes))
        self.assertTrue(any("Falling back to roaming computer inventory only" in message for message in progress_messages))

    def test_collect_swg_skips_correlation_when_disabled(self) -> None:
        class NoCorrelationCollector(UsageCollector):
            def _list_roaming_computers(self) -> list[RoamingComputer]:
                return [
                    RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected", last_sync="2024-09-19T10:34:30.000Z"),
                ]

            def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
                raise AssertionError("SWG correlation APIs should not be called when correlation is disabled")

        progress_messages: list[str] = []
        collector = NoCorrelationCollector(
            client=object(),
            config=RunConfig(
                product=Product.SECURE_ACCESS,
                output_dir=__import__("pathlib").Path("output"),
                swg_correlate_identities=False,
            ),
            progress_callback=progress_messages.append,
        )

        report = collector.collect_swg()
        self.assertEqual(report.primary_count, 1)
        self.assertEqual(report.unique_users, 0)
        self.assertTrue(any("skipped at the user's request" in note for note in report.notes))
        self.assertTrue(any("Skipping SWG user correlation because it was not requested" in message for message in progress_messages))

    def test_collect_swg_uses_targeted_correlation_for_umbrella(self) -> None:
        requested_identity_ids: list[str] = []

        class UmbrellaTargetedCollector(UsageCollector):
            def _list_roaming_computers(self) -> list[RoamingComputer]:
                return [
                    RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected", last_sync="2024-09-19T10:34:30.000Z"),
                ]

            def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
                return {"wkst2": "identity-1"}

            def _find_user_for_swg_device(self, identity_id: str) -> tuple[str, str, str]:
                requested_identity_ids.append(identity_id)
                return "alice@example.com", "2024-09-19T10:34:30.000Z", "2024-09-19T10:34:30.000Z"

        collector = UmbrellaTargetedCollector(
            client=object(),
            config=RunConfig(
                product=Product.UMBRELLA,
                output_dir=__import__("pathlib").Path("output"),
            ),
        )

        report = collector.collect_swg()
        self.assertEqual(requested_identity_ids, ["identity-1"])
        self.assertEqual(report.primary_count, 1)
        self.assertEqual(report.unique_users, 1)
        self.assertEqual(report.rows[0].computer_name, "wkst2")
        self.assertEqual(report.rows[0].user_name, "alice@example.com")

    def test_collect_swg_emits_heartbeat_while_correlation_runs(self) -> None:
        progress_messages: list[str] = []

        class SlowCollector(UsageCollector):
            def _list_roaming_computers(self) -> list[RoamingComputer]:
                return [
                    RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected", last_sync="2024-09-19T10:34:30.000Z"),
                ]

            def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
                return {"wkst2": "identity-1"}

            def _find_user_for_swg_device(self, identity_id: str) -> tuple[str, str, str]:
                time.sleep(0.03)
                return "alice@example.com", "2024-09-19T10:34:30.000Z", "2024-09-19T10:34:30.000Z"

        collector = SlowCollector(
            client=object(),
            config=RunConfig(
                product=Product.UMBRELLA,
                output_dir=__import__("pathlib").Path("output"),
            ),
            progress_callback=progress_messages.append,
        )

        with patch("sse_user_counter.collectors.SWG_CORRELATION_HEARTBEAT_SECONDS", 0.01):
            report = collector.collect_swg()

        self.assertEqual(report.unique_users, 1)
        self.assertTrue(any("Still running on step: Correlating SWG users with targeted proxy lookups" in message for message in progress_messages))

    def test_collect_swg_continues_when_one_targeted_lookup_errors(self) -> None:
        progress_messages: list[str] = []

        with tempfile.TemporaryDirectory() as temp_dir:
            cache = CorrelationCache(__import__("pathlib").Path(temp_dir) / "swg_cache.json")
            cache.set_swg_correlation(
                product=Product.UMBRELLA.value,
                scope_key="org-1",
                computer_name="wkst1",
                user_name="cached@example.com",
                first_seen="2024-09-19T10:34:30.000Z",
                last_seen="2024-09-19T10:34:30.000Z",
            )

            class PartialFailureCollector(UsageCollector):
                def _list_roaming_computers(self) -> list[RoamingComputer]:
                    return [
                        RoamingComputer(device_id="A1", computer_name="wkst1", swg_status="Protected", last_sync="2024-09-19T10:34:30.000Z"),
                        RoamingComputer(device_id="A2", computer_name="wkst2", swg_status="Protected", last_sync="2024-09-19T10:35:30.000Z"),
                    ]

                def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
                    return {"wkst2": "identity-2"}

                def _find_user_for_swg_device(self, identity_id: str) -> tuple[str, str, str]:
                    raise ApiError("HTTP 502", status_code=502, url="https://example.invalid")

            client = type(
                "FakeClient",
                (),
                {"_organization_id": "org-1", "credentials": type("Creds", (), {"org_id": "", "api_key": "key"})()},
            )()
            collector = PartialFailureCollector(
                client=client,
                config=RunConfig(
                    product=Product.UMBRELLA,
                    output_dir=__import__("pathlib").Path("output"),
                ),
                progress_callback=progress_messages.append,
                correlation_cache=cache,
            )

            report = collector.collect_swg()

        self.assertEqual(report.primary_count, 2)
        self.assertEqual(report.unique_users, 1)
        self.assertEqual(report.rows[0].user_name, "cached@example.com")
        self.assertEqual(report.rows[1].user_name, "")
        self.assertTrue(any("targeted proxy activity lookup failed" in row.notes for row in report.rows))
        self.assertTrue(any("Continuing with the remaining devices" in message for message in progress_messages))
        self.assertTrue(any("encountered an API error" in note for note in report.notes))

    def test_fetch_swg_device_identity_ids_uses_proxy_top_identities_for_umbrella(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, dict[str, str]]] = []

            def request_json(self, scope: str, path: str, *, params=None, method="GET", body=None):
                self.calls.append((scope, path, params or {}))
                if path == "/top-identities/proxy":
                    return {
                        "data": [
                            {
                                "identity": {
                                    "id": 42,
                                    "label": "wkst2",
                                    "type": {"type": "directory_computer"},
                                }
                            }
                        ]
                    }
                raise AssertionError(f"Unexpected path {path}")

        collector = UsageCollector(
            client=FakeClient(),
            config=RunConfig(
                product=Product.UMBRELLA,
                output_dir=__import__("pathlib").Path("output"),
                page_limit=100,
            ),
        )

        identity_ids = collector._fetch_swg_device_identity_ids(
            [RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected")]
        )

        self.assertEqual(identity_ids, {"wkst2": "42"})
        self.assertEqual(collector.client.calls[0][1], "/top-identities/proxy")
        self.assertIn("directory_computer", collector.client.calls[0][2]["identitytypes"])

    def test_fetch_swg_device_identity_ids_falls_back_to_identities_for_umbrella(self) -> None:
        offsets: list[int] = []

        class FakeClient:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, dict[str, str]]] = []

            def request_json(self, scope: str, path: str, *, params=None, method="GET", body=None):
                self.calls.append((scope, path, params or {}))
                if path == "/top-identities/proxy":
                    return {"data": []}
                if path == "/identities":
                    offsets.append(params["offset"])
                    return {
                        "data": [
                            {
                                "id": 77,
                                "label": "wkst2",
                                "type": {"type": "directory_computer"},
                            }
                        ]
                    }
                raise AssertionError(f"Unexpected path {path}")

        collector = UsageCollector(
            client=FakeClient(),
            config=RunConfig(
                product=Product.UMBRELLA,
                output_dir=__import__("pathlib").Path("output"),
                page_limit=100,
            ),
        )

        identity_ids = collector._fetch_swg_device_identity_ids(
            [RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected")]
        )

        self.assertEqual(offsets, [0])
        self.assertEqual(identity_ids, {"wkst2": "77"})
        self.assertEqual([path for _, path, _ in collector.client.calls], ["/top-identities/proxy", "/identities"])
        self.assertNotIn("search", collector.client.calls[1][2])

    def test_collect_swg_reuses_local_cache_before_querying_cisco(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = CorrelationCache(__import__("pathlib").Path(temp_dir) / "swg_cache.json")
            cache.set_swg_correlation(
                product=Product.UMBRELLA.value,
                scope_key="org-1",
                computer_name="wkst2",
                user_name="alice@example.com",
                first_seen="2024-09-19T10:34:30.000Z",
                last_seen="2024-09-19T10:34:30.000Z",
            )

            class CachedCollector(UsageCollector):
                def _list_roaming_computers(self) -> list[RoamingComputer]:
                    return [
                        RoamingComputer(
                            device_id="A1",
                            computer_name="wkst2",
                            swg_status="Protected",
                            last_sync="2024-09-19T10:34:30.000Z",
                        ),
                    ]

                def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
                    raise AssertionError("Cisco should not be queried when a cached SWG correlation exists")

            client = type(
                "FakeClient",
                (),
                {"_organization_id": "org-1", "credentials": type("Creds", (), {"org_id": "", "api_key": "key"})()},
            )()
            collector = CachedCollector(
                client=client,
                config=RunConfig(
                    product=Product.UMBRELLA,
                    output_dir=__import__("pathlib").Path("output"),
                ),
                correlation_cache=cache,
            )

            report = collector.collect_swg()

        self.assertEqual(report.primary_count, 1)
        self.assertEqual(report.unique_users, 1)
        self.assertEqual(report.rows[0].user_name, "alice@example.com")
        self.assertTrue(any("matched via local correlation cache" in row.notes for row in report.rows))

    def test_collect_umbrella_skips_vpn_and_ztna_with_progress(self) -> None:
        class InventoryOnlyCollector(UsageCollector):
            def _list_roaming_computers(self) -> list[RoamingComputer]:
                return [RoamingComputer(device_id="A1", computer_name="wkst2", swg_status="Protected")]

            def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
                return {}

        progress_messages: list[str] = []
        collector = InventoryOnlyCollector(
            client=object(),
            config=RunConfig(
                product=Product.UMBRELLA,
                output_dir=__import__("pathlib").Path("output"),
            ),
            progress_callback=progress_messages.append,
        )

        reports = collector.collect()
        self.assertTrue(reports[SWG].supported)
        self.assertFalse(reports[VPN].supported)
        self.assertFalse(reports[ZTNA].supported)
        self.assertTrue(any("Skipping VPN collection for Cisco Umbrella" in message for message in progress_messages))
        self.assertTrue(any("Skipping ZTNA collection for Cisco Umbrella" in message for message in progress_messages))

    def test_list_proxy_activity_splits_before_offset_cap(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.offsets: list[int] = []

            def request_json(self, scope: str, path: str, *, params=None, method="GET", body=None):
                if path != "/activity/proxy":
                    raise AssertionError(f"Unexpected path {path}")

                offset = int(params["offset"])
                self.offsets.append(offset)
                if offset > 4:
                    raise ApiError("HTTP 400", status_code=400, url="https://example.invalid")

                start = int(params["from"])
                end = int(params["to"])
                duration_ms = end - start

                if duration_ms > 30 * 60 * 1000:
                    return {
                        "data": [
                            {"timestamp": offset + 1, "identities": [{"label": "other-device", "type": {"type": "anyconnect"}}]},
                            {"timestamp": offset + 2, "identities": [{"label": "other-device", "type": {"type": "anyconnect"}}]},
                        ]
                    }

                return {
                    "data": [
                        {"timestamp": 999, "identities": [{"label": "target-device", "type": {"type": "anyconnect"}}]}
                    ]
                }

        client = FakeClient()
        collector = UsageCollector(
            client=client,
            config=RunConfig(
                product=Product.SECURE_ACCESS,
                output_dir=__import__("pathlib").Path("output"),
                page_limit=2,
                reporting_offset_max=4,
                min_remote_access_window_minutes=5,
            ),
        )

        events = collector._list_proxy_activity(
            days=1,
            stop_after_all_devices=[RoamingComputer(device_id="1", computer_name="target-device")],
        )

        self.assertTrue(events)
        self.assertLessEqual(max(client.offsets), 4)

    def test_list_proxy_activity_splits_on_forbidden_deep_page(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.offsets: list[int] = []

            def request_json(self, scope: str, path: str, *, params=None, method="GET", body=None):
                if path != "/activity/proxy":
                    raise AssertionError(f"Unexpected path {path}")

                offset = int(params["offset"])
                self.offsets.append(offset)
                start = int(params["from"])
                end = int(params["to"])
                duration_ms = end - start

                if duration_ms > 30 * 60 * 1000 and offset >= 4:
                    raise ApiError("HTTP 403", status_code=403, url="https://example.invalid")

                if duration_ms > 30 * 60 * 1000:
                    return {
                        "data": [
                            {"timestamp": offset + 1, "identities": [{"label": "other-device", "type": {"type": "anyconnect"}}]},
                            {"timestamp": offset + 2, "identities": [{"label": "other-device", "type": {"type": "anyconnect"}}]},
                        ]
                    }

                return {
                    "data": [
                        {"timestamp": 999, "identities": [{"label": "target-device", "type": {"type": "anyconnect"}}]}
                    ]
                }

        progress_messages: list[str] = []
        client = FakeClient()
        collector = UsageCollector(
            client=client,
            config=RunConfig(
                product=Product.SECURE_ACCESS,
                output_dir=__import__("pathlib").Path("output"),
                page_limit=2,
                reporting_offset_max=100,
                min_remote_access_window_minutes=5,
            ),
            progress_callback=progress_messages.append,
        )

        events = collector._list_proxy_activity(
            days=1,
            stop_after_all_devices=[RoamingComputer(device_id="1", computer_name="target-device")],
        )

        self.assertTrue(events)
        self.assertIn(4, client.offsets)
        self.assertTrue(any("HTTP 403" in message for message in progress_messages))


if __name__ == "__main__":
    unittest.main()
