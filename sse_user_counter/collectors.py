from __future__ import annotations

import hashlib
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Iterator

from .cache import CorrelationCache
from .http import ApiError, CiscoApiClient
from .models import Product, RoamingComputer, RunConfig, ServiceReport, ServiceRow

SWG = "SWG"
VPN = "VPN"
ZTNA = "ZTNA"

KNOWN_USER_TYPES = ("user",)
KNOWN_DEVICE_TYPES = ("anyconnect", "roaming", "device", "computer")
SWG_TOP_IDENTITIES_LOOKBACK_DAYS = 30
SWG_ACTIVITY_PAGE_LIMIT = 10
SWG_ACTIVITY_ATTEMPTS_PER_DEVICE = 1
SWG_IDENTITIES_PAGE_LIMIT = 5000
SWG_CORRELATION_HEARTBEAT_SECONDS = 60.0


def dedupe_preserving_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = normalize_label(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(value.strip())
    return ordered


def normalize_label(value: str) -> str:
    return value.strip().casefold()


def is_user_identity(identity_type: str) -> bool:
    normalized = identity_type.casefold()
    return any(token in normalized for token in KNOWN_USER_TYPES)


def is_device_identity(identity_type: str) -> bool:
    normalized = identity_type.casefold()
    return any(token in normalized for token in KNOWN_DEVICE_TYPES)


def extract_identity_labels(identities: Iterable[dict[str, Any]]) -> tuple[list[str], list[str]]:
    users: list[str] = []
    devices: list[str] = []
    for identity in identities:
        if not isinstance(identity, dict):
            continue
        label = str(identity.get("label", "")).strip()
        type_payload = identity.get("type", {})
        identity_type = str(type_payload.get("type", "")).strip() if isinstance(type_payload, dict) else ""
        if not label or not identity_type:
            continue
        if is_user_identity(identity_type):
            users.append(label)
        elif is_device_identity(identity_type):
            devices.append(label)
    return dedupe_preserving_order(users), dedupe_preserving_order(devices)


def preferred_user_labels(identities: Iterable[dict[str, Any]]) -> list[str]:
    saml_users: list[str] = []
    fallback_users: list[str] = []
    for identity in identities:
        if not isinstance(identity, dict):
            continue
        label = str(identity.get("label", "")).strip()
        type_payload = identity.get("type", {})
        identity_type = str(type_payload.get("type", "")).strip() if isinstance(type_payload, dict) else ""
        if not label or not identity_type:
            continue
        if identity_type.casefold() == "saml_user":
            saml_users.append(label)
        elif is_user_identity(identity_type):
            fallback_users.append(label)
    return dedupe_preserving_order(saml_users or fallback_users)


def to_iso_timestamp(value: Any, *, milliseconds: bool) -> str:
    if value in (None, ""):
        return ""
    timestamp = float(value)
    if milliseconds:
        timestamp /= 1000
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def chunked(values: list[str], size: int) -> Iterator[list[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def iter_dict_records(values: Iterable[Any]) -> Iterator[dict[str, Any]]:
    for value in values:
        if isinstance(value, dict):
            yield value


def payload_records(payload: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        values = payload.get(key, [])
    elif isinstance(payload, list):
        values = payload
    else:
        return []
    if not isinstance(values, list):
        return []
    return list(iter_dict_records(values))


def correlate_roaming_computers(
    roaming_computers: list[RoamingComputer],
    proxy_events: list[dict[str, Any]],
    product: Product,
) -> ServiceReport:
    device_lookup = {normalize_label(device.computer_name): device for device in roaming_computers}
    correlations: dict[str, set[str]] = defaultdict(set)
    first_seen: dict[tuple[str, str], str] = {}
    last_seen: dict[tuple[str, str], str] = {}

    for event in proxy_events:
        if not isinstance(event, dict):
            continue
        identities = event.get("identities", [])
        users, devices = extract_identity_labels(identities)
        matched_devices = set()
        for device_label in devices:
            device = device_lookup.get(normalize_label(device_label))
            if device:
                matched_devices.add(device.computer_name)

        if not matched_devices:
            for identity in identities:
                if not isinstance(identity, dict):
                    continue
                label = str(identity.get("label", "")).strip()
                device = device_lookup.get(normalize_label(label))
                if device:
                    matched_devices.add(device.computer_name)

        if not matched_devices or not users:
            continue

        event_seen = to_iso_timestamp(event.get("timestamp"), milliseconds=True)
        for computer_name in matched_devices:
            for user_name in users:
                key = (user_name, computer_name)
                correlations[computer_name].add(user_name)
                if event_seen:
                    first_seen[key] = min(first_seen.get(key, event_seen), event_seen)
                    last_seen[key] = max(last_seen.get(key, event_seen), event_seen)

    rows: list[ServiceRow] = []
    mapped_users: set[str] = set()
    unmapped_devices = 0

    for device in sorted(roaming_computers, key=lambda item: item.computer_name.casefold()):
        matched_users = sorted(correlations.get(device.computer_name, set()), key=str.casefold)
        if not matched_users:
            unmapped_devices += 1
            rows.append(
                ServiceRow(
                    user_name="",
                    computer_name=device.computer_name,
                    service_type=SWG,
                    source_product=product.display_name,
                    device_id=device.device_id,
                    notes=f"swgStatus={device.swg_status or 'unknown'}; no matching user found in proxy activity",
                )
            )
            continue

        for user_name in matched_users:
            mapped_users.add(user_name)
            key = (user_name, device.computer_name)
            rows.append(
                ServiceRow(
                    user_name=user_name,
                    computer_name=device.computer_name,
                    service_type=SWG,
                    source_product=product.display_name,
                    device_id=device.device_id,
                    first_seen=first_seen.get(key, ""),
                    last_seen=last_seen.get(key, ""),
                    event_count=1,
                    notes=f"swgStatus={device.swg_status or 'unknown'}",
                )
            )

    notes = [
        "Primary SWG count is the number of registered roaming computers, per the requirement.",
        f"User correlation uses proxy activity from the last 30 days or less; {unmapped_devices} device(s) could not be mapped to a user.",
    ]
    return ServiceReport(
        service_type=SWG,
        supported=True,
        primary_count=len(roaming_computers),
        unique_users=len(mapped_users),
        rows=rows,
        notes=notes,
    )


def summarize_vpn_events(events: list[dict[str, Any]], product: Product) -> ServiceReport:
    by_user: dict[str, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        users, _ = extract_identity_labels(event.get("identities", []))
        if not users:
            continue
        seen = to_iso_timestamp(event.get("timestamp"), milliseconds=False)
        os_version = str(event.get("osversion", "")).strip()
        for user_name in users:
            state = by_user.setdefault(
                user_name,
                {"first_seen": seen, "last_seen": seen, "event_count": 0, "os_versions": set()},
            )
            if seen:
                state["first_seen"] = min(state["first_seen"] or seen, seen)
                state["last_seen"] = max(state["last_seen"] or seen, seen)
            state["event_count"] += 1
            if os_version:
                state["os_versions"].add(os_version)

    rows = [
        ServiceRow(
            user_name=user_name,
            computer_name="",
            service_type=VPN,
            source_product=product.display_name,
            first_seen=state["first_seen"],
            last_seen=state["last_seen"],
            event_count=state["event_count"],
            notes=f"osVersions={'; '.join(sorted(state['os_versions']))}" if state["os_versions"] else "",
        )
        for user_name, state in sorted(by_user.items(), key=lambda item: item[0].casefold())
    ]

    return ServiceReport(
        service_type=VPN,
        supported=True,
        primary_count=len(rows),
        unique_users=len(rows),
        rows=rows,
        notes=["VPN count is based on unique users with connected events in the requested lookback window."],
    )


def filter_active_ztna_devices(
    user_name: str,
    device_payload: dict[str, Any],
    product: Product,
) -> list[ServiceRow]:
    rows: list[ServiceRow] = []
    if not isinstance(device_payload, dict):
        return rows
    for device in device_payload.get("devices", []):
        if not isinstance(device, dict):
            continue
        certificates = device.get("certificates", [])
        if not certificates:
            continue
        latest = certificates[0]
        if not isinstance(latest, dict):
            continue
        if str(latest.get("status", "")).casefold() != "active":
            continue
        rows.append(
            ServiceRow(
                user_name=user_name,
                computer_name="",
                service_type=ZTNA,
                source_product=product.display_name,
                device_id=str(device.get("deviceId", "")).strip(),
                first_seen=str(latest.get("createdAt", "")).strip(),
                last_seen=str(latest.get("expiresAt", "")).strip(),
                event_count=1,
                notes="active ZTNA device certificate",
            )
        )
    return rows


class UsageCollector:
    def __init__(
        self,
        client: CiscoApiClient,
        config: RunConfig,
        progress_callback: Callable[[str], None] | None = None,
        correlation_cache: CorrelationCache | None = None,
    ) -> None:
        self.client = client
        self.config = config
        self.progress_callback = progress_callback
        self.correlation_cache = correlation_cache or CorrelationCache()

    def collect(self) -> dict[str, ServiceReport]:
        self._emit_progress(f"Starting collection for {self.config.product.display_name}.")
        swg_report = self.collect_swg()
        reports = {SWG: swg_report}

        if self.config.product.supports_vpn:
            reports[VPN] = self.collect_vpn()
        else:
            self._emit_progress("Skipping VPN collection for Cisco Umbrella in the current implementation.")
            reports[VPN] = ServiceReport(
                service_type=VPN,
                supported=False,
                notes=["Cisco Umbrella's current Cloud Security API documentation does not expose Secure Access VPN reporting endpoints."],
            )

        if self.config.product.supports_ztna:
            reports[ZTNA] = self.collect_ztna()
        else:
            self._emit_progress("Skipping ZTNA collection for Cisco Umbrella in the current implementation.")
            reports[ZTNA] = ServiceReport(
                service_type=ZTNA,
                supported=False,
                notes=["Cisco Umbrella's current Cloud Security API documentation does not expose Zero Trust User Devices endpoints."],
            )

        return reports

    def collect_swg(self) -> ServiceReport:
        self._emit_progress("Loading roaming computers for SWG...")
        roaming_computers = self._list_roaming_computers()
        if not self.config.swg_correlate_identities:
            self._emit_progress("Skipping SWG user correlation because it was not requested.")
            return self._build_swg_inventory_only_report(
                roaming_computers,
                "SWG username correlation was skipped at the user's request, so SWG logs include computer inventory only.",
            )
        self._emit_progress("Resolving active SWG device identities from top-identities...")
        try:
            report = self._collect_swg_targeted(roaming_computers)
        except ApiError as error:
            self._emit_progress(
                f"SWG targeted correlation is unavailable ({error}). Falling back to roaming computer inventory only."
            )
            return self._build_swg_inventory_only_report(
                roaming_computers,
                "SWG targeted username correlation was unavailable, so SWG logs include computer inventory only.",
            )
        return report

    def collect_vpn(self) -> ServiceReport:
        self._emit_progress(f"Loading Remote Access VPN activity for the last {self.config.vpn_days} day(s)...")
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.config.vpn_days)
        events = self._list_remote_access_events(start, end)
        return summarize_vpn_events(events, self.config.product)

    def collect_ztna(self) -> ServiceReport:
        self._emit_progress("Checking ZTNA registrations...")
        try:
            identity_map = self._fetch_user_identity_map()
            user_ids = sorted(identity_map.keys())
            rows: list[ServiceRow] = []
            summaries, skipped_user_ids = self._fetch_ztna_user_summaries(user_ids)

            for user_summary in summaries:
                if not isinstance(user_summary, dict):
                    continue
                user_id = str(user_summary.get("userId", "")).strip()
                active = int(user_summary.get("deviceCertificateCounts", {}).get("active", 0) or 0)
                if not user_id or active <= 0:
                    continue

                certificates = self.client.request_json(
                    "admin",
                    f"/ztna/users/{user_id}/deviceCertificates",
                )
                user_name = identity_map.get(user_id, f"userId:{user_id}")
                rows.extend(filter_active_ztna_devices(user_name, certificates, self.config.product))

            unique_users = len({row.user_name for row in rows if row.user_name})
            notes = ["ZTNA count is the number of active device registrations returned by the Zero Trust User Devices API."]
            if skipped_user_ids:
                notes.append(
                    f"Skipped {len(skipped_user_ids)} user ID(s) that Cisco returned as not found when querying ZTNA summaries."
                )
            return ServiceReport(
                service_type=ZTNA,
                supported=True,
                primary_count=len(rows),
                unique_users=unique_users,
                rows=sorted(rows, key=lambda row: (row.user_name.casefold(), row.device_id.casefold())),
                notes=notes,
            )
        except ApiError as error:
            if error.status_code == 403:
                self._emit_progress("ZTNA admin endpoints are not available for this API key or org. Continuing without ZTNA.")
                return ServiceReport(
                    service_type=ZTNA,
                    supported=False,
                    notes=[
                        "ZTNA could not be queried because the API key or org does not have access to the Secure Access Zero Trust User Devices admin endpoints.",
                        "Cisco documents this workflow under GET /admin/v2/ztna/userSummaries and GET /admin/v2/ztna/users/{userId}/deviceCertificates.",
                        "The API key likely needs ZTNA admin read scopes such as admin.ztna.users:read.",
                    ],
                )
            raise

    def _collect_swg_targeted(self, roaming_computers: list[RoamingComputer]) -> ServiceReport:
        if not roaming_computers:
            return self._build_swg_inventory_only_report(
                roaming_computers,
                "No roaming computers were returned for this organization.",
            )

        rows: list[ServiceRow] = []
        mapped_users: set[str] = set()
        cached_matches = 0
        missing_identity_matches = 0
        no_user_matches = 0
        lookup_errors = 0
        uncached_devices: list[RoamingComputer] = []
        cache_scope = self._swg_cache_scope_key()

        for device in sorted(roaming_computers, key=lambda item: item.computer_name.casefold()):
            cached = self.correlation_cache.get_swg_correlation(
                product=self.config.product.value,
                scope_key=cache_scope,
                computer_name=device.computer_name,
            )
            if cached is not None:
                cached_matches += 1
                mapped_users.add(cached.user_name)
                rows.append(
                    ServiceRow(
                        user_name=cached.user_name,
                        computer_name=device.computer_name,
                        service_type=SWG,
                        source_product=self.config.product.display_name,
                        device_id=device.device_id,
                        first_seen=cached.first_seen or device.last_sync,
                        last_seen=cached.last_seen,
                        event_count=1,
                        notes=f"swgStatus={device.swg_status or 'unknown'}; matched via local correlation cache",
                    )
                )
                continue
            uncached_devices.append(device)

        if cached_matches:
            self._emit_progress(f"Loaded {cached_matches} SWG user correlation(s) from the local cache.")

        device_identity_ids: dict[str, str] = {}
        if uncached_devices:
            device_identity_ids = self._fetch_swg_device_identity_ids(uncached_devices)
            self._emit_progress(
                f"Correlating SWG users with targeted proxy lookups (up to {SWG_ACTIVITY_ATTEMPTS_PER_DEVICE} attempt per uncached device)..."
            )

        heartbeat_state = {"processed": 0}
        heartbeat_stop, heartbeat_thread = self._start_swg_correlation_heartbeat(
            total_uncached=len(uncached_devices),
            state=heartbeat_state,
        )
        try:
            for device in uncached_devices:
                try:
                    identity_id = device_identity_ids.get(normalize_label(device.computer_name), "")
                    if not identity_id:
                        missing_identity_matches += 1
                        rows.append(
                            ServiceRow(
                                user_name="",
                                computer_name=device.computer_name,
                                service_type=SWG,
                                source_product=self.config.product.display_name,
                                device_id=device.device_id,
                                first_seen=device.last_sync,
                                notes=f"swgStatus={device.swg_status or 'unknown'}; no matching device identity found in top-identities",
                            )
                        )
                        continue

                    try:
                        user_name, first_seen, last_seen = self._find_user_for_swg_device(identity_id)
                    except ApiError as error:
                        lookup_errors += 1
                        self._emit_progress(
                            f"SWG targeted lookup failed for {device.computer_name} ({error}). Continuing with the remaining devices."
                        )
                        rows.append(
                            ServiceRow(
                                user_name="",
                                computer_name=device.computer_name,
                                service_type=SWG,
                                source_product=self.config.product.display_name,
                                device_id=device.device_id,
                                first_seen=device.last_sync,
                                notes=(
                                    f"swgStatus={device.swg_status or 'unknown'}; "
                                    f"targeted proxy activity lookup failed: {error}"
                                ),
                            )
                        )
                        continue

                    if not user_name:
                        no_user_matches += 1
                        rows.append(
                            ServiceRow(
                                user_name="",
                                computer_name=device.computer_name,
                                service_type=SWG,
                                source_product=self.config.product.display_name,
                                device_id=device.device_id,
                                first_seen=device.last_sync,
                                notes=(
                                    f"swgStatus={device.swg_status or 'unknown'}; "
                                    f"no SAML or user identity found after {SWG_ACTIVITY_ATTEMPTS_PER_DEVICE} targeted activity attempts"
                                ),
                            )
                        )
                        continue

                    mapped_users.add(user_name)
                    resolved_first_seen = first_seen or device.last_sync
                    self.correlation_cache.set_swg_correlation(
                        product=self.config.product.value,
                        scope_key=cache_scope,
                        computer_name=device.computer_name,
                        user_name=user_name,
                        first_seen=resolved_first_seen,
                        last_seen=last_seen,
                    )
                    rows.append(
                        ServiceRow(
                            user_name=user_name,
                            computer_name=device.computer_name,
                            service_type=SWG,
                            source_product=self.config.product.display_name,
                            device_id=device.device_id,
                            first_seen=resolved_first_seen,
                            last_seen=last_seen,
                            event_count=1,
                            notes=f"swgStatus={device.swg_status or 'unknown'}; matched via targeted proxy activity lookup",
                        )
                    )
                finally:
                    heartbeat_state["processed"] += 1
        finally:
            self._stop_swg_correlation_heartbeat(heartbeat_stop, heartbeat_thread)

        return ServiceReport(
            service_type=SWG,
            supported=True,
            primary_count=len(roaming_computers),
            unique_users=len(mapped_users),
            rows=sorted(rows, key=lambda row: (row.computer_name.casefold(), row.user_name.casefold())),
            notes=[
                "Primary SWG count is the number of registered roaming computers, per the requirement.",
                (
                    f"SWG username correlation used top-identities plus up to "
                    f"{SWG_ACTIVITY_ATTEMPTS_PER_DEVICE} targeted proxy activity lookup per uncached device."
                ),
                f"{cached_matches} device(s) reused a prior local SWG correlation cache entry.",
                f"{missing_identity_matches} device(s) were not found in top-identities for the lookback window.",
                f"{lookup_errors} device(s) encountered an API error during targeted proxy correlation and were left uncached.",
                f"{no_user_matches} device(s) were found but did not reveal a user identity within the targeted lookup limit.",
            ],
        )

    def _build_swg_inventory_only_report(
        self,
        roaming_computers: list[RoamingComputer],
        note: str,
    ) -> ServiceReport:
        rows = [
            ServiceRow(
                user_name="",
                computer_name=device.computer_name,
                service_type=SWG,
                source_product=self.config.product.display_name,
                device_id=device.device_id,
                first_seen=device.last_sync,
                notes=f"swgStatus={device.swg_status or 'unknown'}; {note.rstrip('.')}",
            )
            for device in sorted(roaming_computers, key=lambda item: item.computer_name.casefold())
        ]
        return ServiceReport(
            service_type=SWG,
            supported=True,
            primary_count=len(roaming_computers),
            unique_users=0,
            rows=rows,
            notes=[
                "Primary SWG count is the number of registered roaming computers, per the requirement.",
                note,
            ],
        )

    def _fetch_ztna_user_summaries(self, user_ids: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
        summaries: list[dict[str, Any]] = []
        skipped_user_ids: list[str] = []
        for user_batch in chunked(user_ids, 100):
            batch_summaries, batch_skipped = self._fetch_ztna_user_summaries_batch(user_batch)
            summaries.extend(batch_summaries)
            skipped_user_ids.extend(batch_skipped)
        return summaries, skipped_user_ids

    def _fetch_ztna_user_summaries_batch(
        self,
        user_ids: list[str],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        if not user_ids:
            return [], []

        try:
            payload = self.client.request_json(
                "admin",
                "/ztna/userSummaries",
                params={"userIds": ",".join(user_ids)},
            )
        except ApiError as error:
            if error.status_code != 404:
                raise
            if len(user_ids) == 1:
                return [], user_ids

            midpoint = len(user_ids) // 2
            left_summaries, left_skipped = self._fetch_ztna_user_summaries_batch(user_ids[:midpoint])
            right_summaries, right_skipped = self._fetch_ztna_user_summaries_batch(user_ids[midpoint:])
            return left_summaries + right_summaries, left_skipped + right_skipped

        return payload_records(payload, "users"), []

    def _fetch_swg_device_identity_ids(self, roaming_computers: list[RoamingComputer]) -> dict[str, str]:
        if not roaming_computers:
            return {}

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=min(self.config.swg_correlation_days, SWG_TOP_IDENTITIES_LOOKBACK_DAYS))
        expected_labels = {
            normalize_label(device.computer_name): device.computer_name for device in roaming_computers
        }
        device_identity_ids: dict[str, str] = {}
        offset = 0

        while expected_labels.keys() - set(device_identity_ids.keys()):
            payload = self.client.request_json(
                "reports",
                self._swg_top_identities_path(),
                params={
                    "from": str(int(start.timestamp() * 1000)),
                    "to": str(int(end.timestamp() * 1000)),
                    "offset": offset,
                    "limit": self.config.page_limit,
                    "identitytypes": self._swg_device_identity_types(),
                },
            )
            page = payload_records(payload, "data")
            if not page:
                break

            for item in page:
                identity = item.get("identity")
                if not isinstance(identity, dict):
                    continue
                label = normalize_label(str(identity.get("label", "")).strip())
                identity_id = str(identity.get("id", "")).strip()
                type_payload = identity.get("type", {})
                identity_type = str(type_payload.get("type", "")).strip() if isinstance(type_payload, dict) else ""
                if not label or not identity_id or label not in expected_labels or not is_device_identity(identity_type):
                    continue
                device_identity_ids[label] = identity_id

            if len(page) < self.config.page_limit:
                break
            next_offset = offset + self.config.page_limit
            if next_offset > self.config.reporting_offset_max:
                break
            offset = next_offset

        missing_labels = {
            normalized: original
            for normalized, original in expected_labels.items()
            if normalized not in device_identity_ids
        }
        if missing_labels:
            self._emit_progress(
                f"Top-identities did not resolve {len(missing_labels)} SWG device(s). Checking the identities utility for exact computer-name matches..."
            )
            try:
                device_identity_ids.update(self._search_swg_device_identity_ids(missing_labels))
            except ApiError as error:
                self._emit_progress(
                    f"SWG identities utility fallback is unavailable ({error}). Continuing with top-identities matches only."
                )

        return device_identity_ids

    def _swg_top_identities_path(self) -> str:
        if self.config.product is Product.UMBRELLA:
            return "/top-identities/proxy"
        return "/top-identities"

    def _swg_device_identity_types(self) -> str:
        if self.config.product is Product.UMBRELLA:
            return "roaming,anyconnect,directory_computer"
        return "roaming,anyconnect,device"

    def _search_swg_device_identity_ids(self, expected_labels: dict[str, str]) -> dict[str, str]:
        matches: dict[str, str] = {}
        offset = 0

        while expected_labels.keys() - set(matches.keys()):
            payload = self.client.request_json(
                "reports",
                "/identities",
                params={
                    "limit": SWG_IDENTITIES_PAGE_LIMIT,
                    "offset": offset,
                    "identitytypes": self._swg_device_identity_types(),
                },
            )
            page = payload_records(payload, "data")
            if not page:
                break

            for item in page:
                label = normalize_label(str(item.get("label", "")).strip())
                identity_id = str(item.get("id", "")).strip()
                type_payload = item.get("type", {})
                identity_type = str(type_payload.get("type", "")).strip() if isinstance(type_payload, dict) else ""
                if label not in expected_labels or not identity_id or not is_device_identity(identity_type):
                    continue
                matches[label] = identity_id

            if len(page) < SWG_IDENTITIES_PAGE_LIMIT:
                break
            next_offset = offset + SWG_IDENTITIES_PAGE_LIMIT
            if next_offset > self.config.reporting_offset_max:
                break
            offset = next_offset

        return matches

    def _start_swg_correlation_heartbeat(
        self,
        *,
        total_uncached: int,
        state: dict[str, int],
    ) -> tuple[threading.Event | None, threading.Thread | None]:
        if total_uncached <= 0:
            return None, None

        stop_event = threading.Event()

        def heartbeat_worker() -> None:
            while not stop_event.wait(SWG_CORRELATION_HEARTBEAT_SECONDS):
                self._emit_progress(
                    "Still running on step: "
                    f"Correlating SWG users with targeted proxy lookups (up to {SWG_ACTIVITY_ATTEMPTS_PER_DEVICE} attempt per uncached device)... "
                    f"processed {state['processed']}/{total_uncached} uncached device(s) so far."
                )

        thread = threading.Thread(target=heartbeat_worker, name="swg-correlation-heartbeat", daemon=True)
        thread.start()
        return stop_event, thread

    @staticmethod
    def _stop_swg_correlation_heartbeat(
        stop_event: threading.Event | None,
        thread: threading.Thread | None,
    ) -> None:
        if stop_event is not None:
            stop_event.set()
        if thread is not None:
            thread.join(timeout=0.2)

    def _swg_cache_scope_key(self) -> str:
        organization_id = str(getattr(self.client, "_organization_id", "") or "").strip()
        if organization_id:
            return organization_id

        credentials = getattr(self.client, "credentials", None)
        org_id = str(getattr(credentials, "org_id", "") or "").strip()
        if org_id:
            return org_id

        api_key = str(getattr(credentials, "api_key", "") or "").strip()
        if api_key:
            digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
            return f"api-key:{digest}"

        return "unknown"

    def _find_user_for_swg_device(self, identity_id: str) -> tuple[str, str, str]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=min(self.config.swg_correlation_days, SWG_TOP_IDENTITIES_LOOKBACK_DAYS))

        for attempt in range(SWG_ACTIVITY_ATTEMPTS_PER_DEVICE):
            payload = self.client.request_json(
                "reports",
                "/activity/proxy",
                params={
                    "from": str(int(start.timestamp() * 1000)),
                    "to": str(int(end.timestamp() * 1000)),
                    "identityids": identity_id,
                    "limit": SWG_ACTIVITY_PAGE_LIMIT,
                    "offset": attempt * SWG_ACTIVITY_PAGE_LIMIT,
                    "order": "desc",
                },
            )
            page = payload_records(payload, "data")
            if not page:
                break

            for event in page:
                if not isinstance(event, dict):
                    continue
                users = preferred_user_labels(event.get("identities", []))
                if not users:
                    continue
                event_seen = to_iso_timestamp(event.get("timestamp"), milliseconds=True)
                return users[0], event_seen, event_seen

            if len(page) < SWG_ACTIVITY_PAGE_LIMIT:
                break

        return "", "", ""

    def _list_roaming_computers(self) -> list[RoamingComputer]:
        records: list[RoamingComputer] = []
        page = 1
        while True:
            payload = self.client.request_json(
                "deployments",
                "/roamingcomputers",
                params={"page": page, "limit": 100},
            )
            page_items = payload_records(payload, "items") if isinstance(payload, dict) else payload_records(payload, "")
            if isinstance(payload, list):
                page_items = list(iter_dict_records(payload))
            if not page_items:
                break
            for item in page_items:
                records.append(
                    RoamingComputer(
                        device_id=str(item.get("deviceId", "")).strip(),
                        computer_name=str(item.get("name", "")).strip(),
                        swg_status=str(item.get("swgStatus", "")).strip(),
                        status=str(item.get("status", "")).strip(),
                        last_sync=str(item.get("lastSync", "")).strip(),
                    )
                )
            if len(page_items) < 100:
                break
            page += 1
        return [record for record in records if record.computer_name]

    def _list_proxy_activity(
        self,
        *,
        days: int,
        stop_after_all_devices: list[RoamingComputer],
    ) -> list[dict[str, Any]]:
        if not stop_after_all_devices:
            return []

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        expected_devices = {normalize_label(device.computer_name) for device in stop_after_all_devices}
        deduped: dict[tuple[Any, ...], dict[str, Any]] = {}
        for event in self._fetch_proxy_activity_window(start, end, expected_devices):
            deduped[self._proxy_event_key(event)] = event
        return list(deduped.values())

    def _fetch_proxy_activity_window(
        self,
        start: datetime,
        end: datetime,
        expected_devices: set[str],
    ) -> list[dict[str, Any]]:
        if not expected_devices:
            return []

        seen_devices: set[str] = set()
        events: list[dict[str, Any]] = []
        offset = 0

        while True:
            try:
                payload = self.client.request_json(
                    "reports",
                    "/activity/proxy",
                    params={
                        "from": str(int(start.timestamp() * 1000)),
                        "to": str(int(end.timestamp() * 1000)),
                        "offset": offset,
                        "limit": self.config.page_limit,
                        "order": "desc",
                    },
                )
            except ApiError as error:
                if error.status_code in (400, 403) and offset > 0:
                    self._emit_progress(
                        f"Cisco rejected SWG proxy pagination at offset {offset} with HTTP {error.status_code}. Splitting the time range and continuing..."
                    )
                    break
                raise
            page = payload_records(payload, "data")
            if not page:
                break
            events.extend(page)
            seen_devices.update(self._seen_proxy_devices(page, expected_devices))

            if len(page) < self.config.page_limit or seen_devices == expected_devices:
                return events

            next_offset = offset + self.config.page_limit
            if next_offset > self.config.reporting_offset_max:
                break
            offset = next_offset

        minimum_window = timedelta(minutes=self.config.min_remote_access_window_minutes)
        if end - start <= minimum_window:
            return events

        self._emit_progress("SWG proxy activity window hit Cisco's offset cap. Splitting the time range and continuing...")
        midpoint = start + (end - start) / 2
        left = self._fetch_proxy_activity_window(start, midpoint, expected_devices)
        left_seen = self._seen_proxy_devices(left, expected_devices)
        remaining_devices = expected_devices - left_seen
        if not remaining_devices:
            return left

        right = self._fetch_proxy_activity_window(midpoint + timedelta(milliseconds=1), end, remaining_devices)
        return left + right

    def _list_remote_access_events(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        deduped: dict[tuple[Any, ...], dict[str, Any]] = {}
        for window_start, window_end in self._split_long_window(start, end, max_days=30):
            for event in self._fetch_remote_access_window(window_start, window_end):
                deduped[self._remote_access_event_key(event)] = event
        return list(deduped.values())

    def _fetch_remote_access_window(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        payload = self.client.request_json(
            "reports",
            "/remote-access-events",
            params={
                "from": str(int(start.timestamp() * 1000)),
                "to": str(int(end.timestamp() * 1000)),
                "limit": self.config.remote_access_window_limit,
                "connectionevent": "connected",
            },
        )
        events = payload_records(payload, "data")
        if len(events) < self.config.remote_access_window_limit:
            return events

        minimum_window = timedelta(minutes=self.config.min_remote_access_window_minutes)
        if end - start <= minimum_window:
            return events

        self._emit_progress("VPN activity window is dense. Splitting the time range and continuing...")
        midpoint = start + (end - start) / 2
        left = self._fetch_remote_access_window(start, midpoint)
        right = self._fetch_remote_access_window(midpoint + timedelta(milliseconds=1), end)
        return left + right

    def _fetch_user_identity_map(self) -> dict[str, str]:
        mapping = self._fetch_identities_with_filter("directory_user,saml_user")
        if mapping:
            return mapping
        return self._fetch_identities_with_filter("")


    def _fetch_identities_with_filter(self, identity_types: str) -> dict[str, str]:
        mapping: dict[str, str] = {}
        offset = 0
        limit = 5000
        while True:
            params = {"limit": limit, "offset": offset}
            if identity_types:
                params["identitytypes"] = identity_types
            payload = self.client.request_json("reports", "/identities", params=params)
            page = payload_records(payload, "data")
            if not page:
                break
            for identity in page:
                if not isinstance(identity, dict):
                    continue
                user_id = str(identity.get("id", "")).strip()
                label = str(identity.get("label", "")).strip()
                type_payload = identity.get("type", {})
                identity_type = str(type_payload.get("type", "")).strip() if isinstance(type_payload, dict) else ""
                if not user_id or not label:
                    continue
                if identity_types or is_user_identity(identity_type):
                    mapping[user_id] = label
            if len(page) < limit:
                break
            offset += limit
        return mapping

    @staticmethod
    def _split_long_window(start: datetime, end: datetime, *, max_days: int) -> Iterator[tuple[datetime, datetime]]:
        current = start
        delta = timedelta(days=max_days)
        while current < end:
            window_end = min(current + delta, end)
            yield current, window_end
            current = window_end + timedelta(milliseconds=1)

    @staticmethod
    def _remote_access_event_key(event: dict[str, Any]) -> tuple[Any, ...]:
        users, _ = extract_identity_labels(event.get("identities", []))
        return (
            event.get("timestamp"),
            event.get("connecttimestamp"),
            event.get("publicip"),
            event.get("internalip"),
            tuple(users),
            event.get("connectionevent"),
        )

    @staticmethod
    def _seen_proxy_devices(events: Iterable[dict[str, Any]], expected_devices: set[str]) -> set[str]:
        seen_devices: set[str] = set()
        for event in events:
            if not isinstance(event, dict):
                continue
            for identity in event.get("identities", []):
                if not isinstance(identity, dict):
                    continue
                label = str(identity.get("label", "")).strip()
                normalized = normalize_label(label)
                if normalized in expected_devices:
                    seen_devices.add(normalized)
        return seen_devices

    @staticmethod
    def _proxy_event_key(event: dict[str, Any]) -> tuple[Any, ...]:
        return (repr(event),)


    def _emit_progress(self, message: str) -> None:
        if self.progress_callback is not None:
            self.progress_callback(message)
