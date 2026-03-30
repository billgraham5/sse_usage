from __future__ import annotations

import io
import unittest
from email.message import Message
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

from sse_user_counter.http import ApiError, CiscoApiClient
from sse_user_counter.models import Credentials, Product


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class HttpClientTests(unittest.TestCase):
    def test_execute_retries_on_rate_limit(self) -> None:
        headers = Message()
        headers["Retry-After"] = "0"
        rate_limited = HTTPError(
            url="https://example.invalid",
            code=429,
            msg="Too Many Requests",
            hdrs=headers,
            fp=io.BytesIO(b"Too Many Requests"),
        )
        success = _FakeResponse(b'{"ok": true}')
        messages: list[str] = []

        client = CiscoApiClient(
            product=Product.SECURE_ACCESS,
            credentials=Credentials(api_key="key", api_secret="secret"),
            progress_callback=messages.append,
        )
        request = Request("https://example.invalid")

        with patch("sse_user_counter.http.urlopen", side_effect=[rate_limited, success]) as mocked_urlopen:
            with patch("sse_user_counter.http.time.sleep") as mocked_sleep:
                payload = client._execute(request)

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(mocked_urlopen.call_count, 2)
        mocked_sleep.assert_called_once_with(0.0)
        self.assertTrue(any("Backoff timer set for 0.0s" in message for message in messages))

    def test_execute_retries_on_transient_gateway_error(self) -> None:
        headers = Message()
        gateway_error = HTTPError(
            url="https://example.invalid",
            code=502,
            msg="Bad Gateway",
            hdrs=headers,
            fp=io.BytesIO(b"Bad Gateway"),
        )
        success = _FakeResponse(b'{"ok": true}')
        messages: list[str] = []

        client = CiscoApiClient(
            product=Product.UMBRELLA,
            credentials=Credentials(api_key="key", api_secret="secret"),
            progress_callback=messages.append,
        )
        request = Request("https://example.invalid")

        with patch("sse_user_counter.http.urlopen", side_effect=[gateway_error, success]) as mocked_urlopen:
            with patch("sse_user_counter.http.time.sleep") as mocked_sleep:
                payload = client._execute(request)

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(mocked_urlopen.call_count, 2)
        mocked_sleep.assert_called_once_with(1.0)
        self.assertTrue(any("Cisco API returned HTTP 502" in message for message in messages))

    def test_get_organization_id_reads_orginfo_endpoint(self) -> None:
        class FakeClient(CiscoApiClient):
            def request_json(self, scope: str, path: str, *, params=None, method="GET", body=None):
                self.last_scope = scope
                self.last_path = path
                return {"organizationId": 8363425, "fingerprint": "abc", "userId": 1234}

        client = FakeClient(
            product=Product.SECURE_ACCESS,
            credentials=Credentials(api_key="key", api_secret="secret"),
        )

        organization_id = client.get_organization_id()
        self.assertEqual(organization_id, "8363425")
        self.assertEqual(client.last_scope, "deployments")
        self.assertEqual(client.last_path, "/roamingcomputers/orgInfo")

    def test_get_organization_id_returns_none_on_forbidden(self) -> None:
        messages: list[str] = []

        class FakeClient(CiscoApiClient):
            def request_json(self, scope: str, path: str, *, params=None, method="GET", body=None):
                raise ApiError(
                    "HTTP 403",
                    status_code=403,
                    url="https://example.invalid",
                )

        client = FakeClient(
            product=Product.SECURE_ACCESS,
            credentials=Credentials(api_key="key", api_secret="secret"),
            progress_callback=messages.append,
        )

        organization_id = client.get_organization_id()
        self.assertIsNone(organization_id)
        self.assertTrue(any("Continuing without it" in message for message in messages))

    def test_request_json_refreshes_expired_token_before_request(self) -> None:
        class FakeClient(CiscoApiClient):
            def __post_init__(self) -> None:
                super().__post_init__()
                self.executed_authorization_headers: list[str] = []
                self.authenticate_calls = 0

            def authenticate(self) -> str:
                self.authenticate_calls += 1
                self._token = f"fresh-token-{self.authenticate_calls}"
                self._token_expires_at = 10_000.0
                return self._token

            def _execute(self, request):  # type: ignore[override]
                self.executed_authorization_headers.append(request.headers["Authorization"])
                return {"ok": True}

        client = FakeClient(
            product=Product.UMBRELLA,
            credentials=Credentials(api_key="key", api_secret="secret"),
        )
        client._token = "stale-token"
        client._token_expires_at = 0.0

        with patch("sse_user_counter.http.time.time", return_value=100.0):
            payload = client.request_json("reports", "/activity/proxy", params={"limit": 1, "from": 1, "to": 2})

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(client.authenticate_calls, 1)
        self.assertEqual(client.executed_authorization_headers, ["Bearer fresh-token-1"])

    def test_request_json_retries_once_after_unauthorized(self) -> None:
        unauthorized = ApiError("HTTP 401", status_code=401, url="https://example.invalid")

        class FakeClient(CiscoApiClient):
            def __post_init__(self) -> None:
                super().__post_init__()
                self.authenticate_calls = 0
                self.execute_calls = 0

            def authenticate(self) -> str:
                self.authenticate_calls += 1
                self._token = f"token-{self.authenticate_calls}"
                self._token_expires_at = 10_000.0
                return self._token

            def _execute(self, request):  # type: ignore[override]
                self.execute_calls += 1
                if self.execute_calls == 1:
                    raise unauthorized
                return {"ok": request.headers["Authorization"]}

        client = FakeClient(
            product=Product.SECURE_ACCESS,
            credentials=Credentials(api_key="key", api_secret="secret"),
        )

        with patch("sse_user_counter.http.time.time", return_value=100.0):
            payload = client.request_json("reports", "/top-identities", params={"limit": 1, "from": 1, "to": 2})

        self.assertEqual(payload, {"ok": "Bearer token-2"})
        self.assertEqual(client.authenticate_calls, 2)
        self.assertEqual(client.execute_calls, 2)


if __name__ == "__main__":
    unittest.main()
