"""Opt-in device-authenticated front door for native S&G clients.

The surface is default-off and deliberately narrow.  It owns device
enrollment/revocation and exposes sanitized profile metadata; profile secrets
and filesystem paths never cross this boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from api.config import STATE_DIR


_LOCK = threading.RLock()
_STATE_FILE = "sgbot_front_door.json"
_ENABLED_VALUES = {"1", "true", "yes", "on"}


class FrontDoorError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def enabled() -> bool:
    return os.getenv("HERMES_WEBUI_SGBOT_FRONT_DOOR", "").strip().lower() in _ENABLED_VALUES


def _state_path(state_dir: Path | None = None) -> Path:
    return Path(state_dir or STATE_DIR) / _STATE_FILE


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load(state_dir: Path | None = None) -> dict[str, Any]:
    path = _state_path(state_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": 1, "devices": {}, "pairing_codes": {}, "runs": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise FrontDoorError("front-door state is unavailable", 503) from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise FrontDoorError("front-door state is unavailable", 503)
    data.setdefault("devices", {})
    data.setdefault("pairing_codes", {})
    data.setdefault("runs", {})
    return data


def _save(data: dict[str, Any], state_dir: Path | None = None) -> None:
    path = _state_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=".sgbot-front-door-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        path.chmod(0o600)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def issue_pairing_code(*, ttl_seconds: int = 300, state_dir: Path | None = None) -> str:
    """Create one six-digit, single-use enrollment code."""
    if ttl_seconds < 1 or ttl_seconds > 3600:
        raise FrontDoorError("pairing-code ttl must be between 1 and 3600 seconds")
    code = f"{secrets.randbelow(1_000_000):06d}"
    with _LOCK:
        state = _load(state_dir)
        now = time.time()
        state["pairing_codes"] = {
            key: row for key, row in state["pairing_codes"].items()
            if float(row.get("expires_at", 0)) > now
        }
        state["pairing_codes"][_digest(code)] = {"expires_at": now + ttl_seconds}
        _save(state, state_dir)
    return code


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    display_name: str
    kind: str


def enroll_device(
    code: str,
    device_id: str,
    display_name: str,
    kind: str,
    *,
    server_origin: str,
    state_dir: Path | None = None,
) -> dict[str, Any]:
    code = str(code or "").strip()
    device_id = str(device_id or "").strip()
    display_name = str(display_name or "").strip()
    kind = str(kind or "").strip().lower()
    if len(code) != 6 or not code.isdigit():
        raise FrontDoorError("pairing code must contain six digits")
    if not device_id or len(device_id) > 200:
        raise FrontDoorError("device_id is required")
    if not display_name or len(display_name) > 200:
        raise FrontDoorError("display_name is required")
    if kind not in {"mac", "phone"}:
        raise FrontDoorError("kind must be mac or phone")
    token = secrets.token_urlsafe(32)
    issued_at = time.time()
    with _LOCK:
        state = _load(state_dir)
        code_key = _digest(code)
        code_row = state["pairing_codes"].get(code_key)
        if not code_row or float(code_row.get("expires_at", 0)) <= issued_at:
            raise FrontDoorError("pairing code is invalid or expired", 401)
        if device_id in state["devices"]:
            raise FrontDoorError("device is already enrolled", 409)
        del state["pairing_codes"][code_key]
        state["devices"][device_id] = {
            "token_hash": _digest(token),
            "display_name": display_name,
            "kind": kind,
            "issued_at": issued_at,
        }
        _save(state, state_dir)
    return {
        "device_id": device_id,
        "token": token,
        "server_origin": server_origin.rstrip("/"),
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued_at)),
    }


def authenticate(authorization: str | None, *, state_dir: Path | None = None) -> DeviceIdentity:
    scheme, _, token = str(authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise FrontDoorError("device credential required", 401)
    candidate = _digest(token.strip())
    with _LOCK:
        devices = _load(state_dir)["devices"]
        for device_id, row in devices.items():
            if hmac.compare_digest(str(row.get("token_hash", "")), candidate):
                return DeviceIdentity(device_id, str(row.get("display_name", "")), str(row.get("kind", "")))
    raise FrontDoorError("device credential rejected", 401)


def revoke_device(authorization: str | None, *, state_dir: Path | None = None) -> None:
    identity = authenticate(authorization, state_dir=state_dir)
    with _LOCK:
        state = _load(state_dir)
        state["devices"].pop(identity.device_id, None)
        _save(state, state_dir)


def roster_payload(profile_rows: list[dict[str, Any]]) -> dict[str, Any]:
    profiles = []
    seen: set[str] = set()
    for row in profile_rows:
        if row.get("visible", True) is False:
            continue
        profile_id = str(row.get("name") or "").strip()
        if not profile_id or profile_id in seen:
            continue
        seen.add(profile_id)
        profiles.append({
            "id": profile_id,
            "display_name": "Clarence" if profile_id == "clarence" else profile_id.replace("-", " ").title(),
            "available": bool(row.get("gateway_running")),
            "reason": None if row.get("gateway_running") else "Hermes profile is unavailable",
        })
    default_id = "clarence" if any(row["id"] == "clarence" for row in profiles) else (profiles[0]["id"] if profiles else None)
    return {"profiles": profiles, "default_profile_id": default_id}


def capabilities_payload() -> dict[str, Any]:
    return {
        "version": "1",
        "supports_voice": True,
        "supports_approvals": False,
        "supports_cursor_replay": False,
    }


@dataclass(frozen=True)
class ProfileGateway:
    profile_id: str
    profile_home: Path
    base_url: str
    api_key: str


def bot_chat_id(profile_id: str) -> str:
    normalized = str(profile_id or "").strip()
    if not normalized or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in normalized):
        raise FrontDoorError("profile not found", 404)
    return f"sgbot.bot-chat.{normalized}"


def profile_id_for_chat(chat_id: str) -> str:
    prefix = "sgbot.bot-chat."
    value = str(chat_id or "")
    if not value.startswith(prefix):
        raise FrontDoorError("Bot Chat not found", 404)
    profile_id = value[len(prefix):]
    if bot_chat_id(profile_id) != value:
        raise FrontDoorError("Bot Chat not found", 404)
    return profile_id


def bot_chat_payload(profile_id: str, display_name: str | None = None) -> dict[str, Any]:
    return {
        "id": bot_chat_id(profile_id),
        "persona_id": profile_id,
        "title": str(display_name or profile_id).strip() or profile_id,
    }


def profile_row(profile_id: str, profile_rows: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [row for row in profile_rows if str(row.get("name") or "") == profile_id and row.get("visible", True) is not False]
    if len(matches) != 1:
        raise FrontDoorError("profile not found", 404)
    return matches[0]


def resolve_profile_gateway(profile_id: str, profile_rows: list[dict[str, Any]]) -> ProfileGateway:
    """Resolve one local profile gateway without exposing its endpoint or key."""
    row = profile_row(profile_id, profile_rows)
    if not row.get("gateway_running"):
        raise FrontDoorError("profile is unavailable", 503)
    home = Path(str(row.get("path") or "")).expanduser().resolve()
    if not home.is_dir():
        raise FrontDoorError("profile is unavailable", 503)
    try:
        from api.providers import _load_env_file

        env = _load_env_file(home / ".env")
    except Exception as exc:
        raise FrontDoorError("profile gateway configuration is unavailable", 503) from exc
    try:
        port = int(str(env.get("API_SERVER_PORT") or "8642"))
    except (TypeError, ValueError) as exc:
        raise FrontDoorError("profile gateway configuration is invalid", 503) from exc
    if not 1 <= port <= 65535:
        raise FrontDoorError("profile gateway configuration is invalid", 503)
    api_key = str(env.get("API_SERVER_KEY") or "").strip()
    if not api_key:
        raise FrontDoorError("profile gateway credential is unavailable", 503)
    return ProfileGateway(profile_id, home, f"http://127.0.0.1:{port}", api_key)


def load_history(chat_id: str, profile_rows: list[dict[str, Any]]) -> dict[str, Any]:
    profile_id = profile_id_for_chat(chat_id)
    row = profile_row(profile_id, profile_rows)
    home = Path(str(row.get("path") or "")).expanduser().resolve()
    db_path = home / "state.db"
    if not db_path.is_file():
        return {"session_id": chat_id, "messages": [], "next_cursor": None}
    try:
        from hermes_state import SessionDB

        db = SessionDB(db_path=db_path, read_only=True)
        try:
            raw_messages = db.get_messages_as_conversation(
                chat_id,
                include_ancestors=True,
                include_compacted=True,
                include_row_ids=True,
            )
        finally:
            db.close()
    except Exception as exc:
        raise FrontDoorError("Bot Chat history is unavailable", 503) from exc
    messages = []
    for index, item in enumerate(raw_messages):
        if not isinstance(item, dict):
            continue
        content = item.get("content", "")
        if isinstance(content, list):
            content = "\n".join(
                str(part.get("text") or "") for part in content
                if isinstance(part, dict) and part.get("type") in {"text", "input_text", "output_text"}
            )
        messages.append({
            "id": str(item.get("id") or item.get("row_id") or f"{chat_id}:{index}"),
            "role": str(item.get("role") or "assistant"),
            "text": str(content or ""),
            "created_at": item.get("created_at") or item.get("timestamp"),
        })
    return {"session_id": chat_id, "messages": messages, "next_cursor": None}


def _gateway_request(
    gateway: ProfileGateway,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 35,
):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        gateway.base_url + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {gateway.api_key}",
            **({"Content-Type": "application/json"} if data is not None else {}),
            **(headers or {}),
        },
    )
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
            message = payload.get("error") if isinstance(payload, dict) else None
            if isinstance(message, dict):
                message = message.get("message")
        except Exception:
            message = None
        raise FrontDoorError(str(message or "Hermes gateway request failed"), exc.code) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FrontDoorError("profile gateway is unreachable", 503) from exc


def proxy_json(
    gateway: ProfileGateway,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    with _gateway_request(gateway, method, path, body=body, headers=headers) as response:
        try:
            payload = json.loads(response.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FrontDoorError("Hermes gateway returned an invalid response", 502) from exc
        if not isinstance(payload, dict):
            raise FrontDoorError("Hermes gateway returned an invalid response", 502)
        return int(getattr(response, "status", 200)), payload


def create_run(
    chat_id: str,
    body: dict[str, Any],
    profile_rows: list[dict[str, Any]],
    *,
    idempotency_key: str,
    state_dir: Path | None = None,
) -> tuple[int, dict[str, Any]]:
    profile_id = profile_id_for_chat(chat_id)
    if str(body.get("session_id") or chat_id) != chat_id:
        raise FrontDoorError("session_id must match the selected Bot Chat")
    content = str(body.get("content") or body.get("input") or "").strip()
    if not content:
        raise FrontDoorError("content is required")
    if not idempotency_key.strip():
        raise FrontDoorError("Idempotency-Key is required")
    gateway = resolve_profile_gateway(profile_id, profile_rows)
    status, payload = proxy_json(
        gateway,
        "POST",
        "/v1/runs",
        body={"input": content, "session_id": chat_id},
        headers={"Idempotency-Key": idempotency_key.strip()},
    )
    run_id = str(payload.get("run_id") or payload.get("id") or "").strip()
    if not run_id:
        raise FrontDoorError("Hermes gateway returned an invalid response", 502)
    with _LOCK:
        state = _load(state_dir)
        state["runs"][run_id] = {"profile_id": profile_id, "chat_id": chat_id, "updated_at": time.time()}
        _save(state, state_dir)
    return status, payload


def gateway_for_run(
    run_id: str,
    profile_rows: list[dict[str, Any]],
    *,
    state_dir: Path | None = None,
) -> ProfileGateway:
    with _LOCK:
        row = _load(state_dir)["runs"].get(str(run_id or ""))
    if not isinstance(row, dict) or not row.get("profile_id"):
        raise FrontDoorError("run not found", 404)
    return resolve_profile_gateway(str(row["profile_id"]), profile_rows)


def proxy_run_json(
    run_id: str,
    suffix: str,
    method: str,
    profile_rows: list[dict[str, Any]],
    *,
    body: dict[str, Any] | None = None,
    state_dir: Path | None = None,
) -> tuple[int, dict[str, Any]]:
    gateway = gateway_for_run(run_id, profile_rows, state_dir=state_dir)
    safe_run_id = urllib.parse.quote(str(run_id), safe="")
    return proxy_json(gateway, method, f"/v1/runs/{safe_run_id}{suffix}", body=body)


def open_run_events(
    run_id: str,
    profile_rows: list[dict[str, Any]],
    *,
    state_dir: Path | None = None,
):
    gateway = gateway_for_run(run_id, profile_rows, state_dir=state_dir)
    safe_run_id = urllib.parse.quote(str(run_id), safe="")
    return _gateway_request(
        gateway,
        "GET",
        f"/v1/runs/{safe_run_id}/events",
        headers={"Accept": "text/event-stream"},
        timeout=90,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Manage the opt-in S&G device front door")
    parser.add_argument("command", choices=["issue-code"])
    parser.add_argument("--ttl", type=int, default=300)
    args = parser.parse_args()
    if args.command == "issue-code":
        print(issue_pairing_code(ttl_seconds=args.ttl))
