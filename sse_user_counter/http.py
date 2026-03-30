from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .models import Credentials, Product


class ApiError(RuntimeError):
    """Raised when a Cisco API request fails."""

    def __init__(self, message: str, *, status_code: int | None = None, url: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.url = url


@dataclass
class CiscoApiClient:
    product: Product
    credentials: Credentials
    reporting_region: str = "auto"
    timeout_seconds: int = 60
    max_retries: int = 5
    retry_backoff_seconds: float = 1.0
    max_retry_delay_seconds: float = 30.0
    token_refresh_skew_seconds: float = 60.0
    progress_callback: Callable[[str], None] | None = None

    def __post_init__(self) -> None:
        self._token: str | None = None
        self._token_expires_at: float | None = None
        self._organization_id: str | None = None
        self._organization_id_lookup_attempted = False

    def _host(self) -> str:
        if self.product is Product.UMBRELLA:
            return "https://api.umbrella.com"
        return "https://api.sse.cisco.com"

    def _scope_path(self, scope: str) -> str:
        paths = {
            "auth": "auth/v2",
            "deployments": "deployments/v2",
            "admin": "admin/v2",
            "reports": self._reporting_scope_path(),
        }
        try:
            return paths[scope]
        except KeyError as error:
            raise ValueError(f"Unsupported API scope: {scope}") from error

    def _reporting_scope_path(self) -> str:
        region = self.reporting_region.lower()
        if region == "us":
            return "reports.us/v2"
        if region == "eu":
            return "reports.eu/v2"
        return "reports/v2"

    def _build_url(self, scope: str, path: str, params: dict[str, Any] | None = None) -> str:
        normalized = path if path.startswith("/") else f"/{path}"
        url = f"{self._host()}/{self._scope_path(scope)}{normalized}"
        if params:
            clean_params = {key: value for key, value in params.items() if value not in (None, "")}
            if clean_params:
                url = f"{url}?{urlencode(clean_params, doseq=True)}"
        return url

    def authenticate(self) -> str:
        self._emit_progress(f"Authenticating with {self.product.display_name}...")
        url = self._build_url("auth", "/token")
        auth_bytes = f"{self.credentials.api_key}:{self.credentials.api_secret}".encode("utf-8")
        headers = {
            "Authorization": f"Basic {base64.b64encode(auth_bytes).decode('ascii')}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "sse-user-counter/0.1.0",
        }
        if self.credentials.org_id:
            headers["X-Umbrella-OrgId"] = self.credentials.org_id

        request = Request(
            url=url,
            data=urlencode({"grant_type": "client_credentials"}).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        response = self._execute(request)
        access_token = response.get("access_token")
        if not access_token:
            raise ApiError("Cisco authentication response did not include an access token.")
        self._token = str(access_token)
        expires_in = response.get("expires_in", 3600)
        try:
            self._token_expires_at = time.time() + max(0.0, float(expires_in))
        except (TypeError, ValueError):
            self._token_expires_at = time.time() + 3600.0
        self._emit_progress("Authentication succeeded.")
        return self._token

    def request_json(
        self,
        scope: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> Any:
        return self._request_json(scope, path, params=params, method=method, body=body, allow_reauth_retry=True)

    def _request_json(
        self,
        scope: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        allow_reauth_retry: bool,
    ) -> Any:
        if self._token_needs_refresh():
            if self._token:
                self._emit_progress("Cisco access token is expiring soon. Refreshing authentication...")
            self.authenticate()

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "sse-user-counter/0.1.0",
        }
        data: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        request = Request(
            url=self._build_url(scope, path, params=params),
            data=data,
            headers=headers,
            method=method.upper(),
        )
        try:
            return self._execute(request)
        except ApiError as error:
            if error.status_code == 401 and allow_reauth_retry:
                self._emit_progress("Cisco API rejected the access token. Re-authenticating and retrying once...")
                self._token = None
                self._token_expires_at = None
                return self._request_json(
                    scope,
                    path,
                    params=params,
                    method=method,
                    body=body,
                    allow_reauth_retry=False,
                )
            raise

    def get_organization_id(self) -> str | None:
        if self._organization_id_lookup_attempted:
            return self._organization_id

        self._organization_id_lookup_attempted = True
        self._emit_progress("Retrieving organization information...")
        try:
            payload = self.request_json("deployments", "/roamingcomputers/orgInfo")
        except ApiError as error:
            if error.status_code in (403, 404):
                self._emit_progress("Organization ID lookup is not available for this API key. Continuing without it.")
                return None
            raise

        if not isinstance(payload, dict):
            self._emit_progress("Organization ID lookup returned an unexpected payload. Continuing without it.")
            return None

        organization_id = payload.get("organizationId")
        if organization_id in (None, ""):
            self._emit_progress("Organization ID was not present in the OrgInfo response.")
            return None
        self._organization_id = str(organization_id)
        return self._organization_id

    def _execute(self, request: Request) -> Any:
        for attempt in range(self.max_retries + 1):
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    raw = response.read().decode("utf-8")
            except HTTPError as error:
                raw = error.read().decode("utf-8", errors="replace")
                if error.code in {429, 502, 503, 504} and attempt < self.max_retries:
                    delay = self._retry_delay_seconds(error.headers, attempt)
                    if error.code == 429:
                        self._emit_progress(
                            f"Rate limited by Cisco API. Backoff timer set for {delay:.1f}s before retry {attempt + 1}/{self.max_retries} on {request.full_url}"
                        )
                    else:
                        self._emit_progress(
                            f"Cisco API returned HTTP {error.code}. Backoff timer set for {delay:.1f}s before retry {attempt + 1}/{self.max_retries} on {request.full_url}"
                        )
                    time.sleep(delay)
                    continue

                message = self._extract_error_message(raw) or error.reason
                raise ApiError(
                    f"HTTP {error.code} for {request.full_url}: {message}",
                    status_code=error.code,
                    url=request.full_url,
                ) from error
            except URLError as error:
                raise ApiError(
                    f"Unable to reach Cisco API endpoint {request.full_url}: {error.reason}",
                    url=request.full_url,
                ) from error

            if not raw:
                return None
            try:
                return json.loads(raw)
            except json.JSONDecodeError as error:
                raise ApiError(f"Cisco API returned invalid JSON for {request.full_url}.") from error

        raise ApiError(f"HTTP 429 for {request.full_url}: Too Many Requests", status_code=429, url=request.full_url)

    def _retry_delay_seconds(self, headers: Any, attempt: int) -> float:
        retry_after = None
        if headers is not None:
            retry_after = headers.get("Retry-After")
        parsed_retry_after = self._parse_retry_after(retry_after)
        if parsed_retry_after is not None:
            return min(parsed_retry_after, self.max_retry_delay_seconds)
        return min(self.retry_backoff_seconds * (2 ** attempt), self.max_retry_delay_seconds)

    def _token_needs_refresh(self) -> bool:
        if not self._token:
            return True
        if self._token_expires_at is None:
            return False
        return time.time() >= (self._token_expires_at - self.token_refresh_skew_seconds)

    @staticmethod
    def _parse_retry_after(value: Any) -> float | None:
        if value in (None, ""):
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            return max(0.0, float(text))
        except ValueError:
            pass
        try:
            retry_at = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        return max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())

    def _emit_progress(self, message: str) -> None:
        if self.progress_callback is not None:
            self.progress_callback(message)

    @staticmethod
    def _extract_error_message(raw_body: str) -> str:
        if not raw_body:
            return ""
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            return raw_body.strip()
        if isinstance(payload, dict):
            for key in ("message", "description", "error"):
                value = payload.get(key)
                if value:
                    return str(value)
        return raw_body.strip()
