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
        return {"version": 1, "devices": {}, "pairing_codes": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise FrontDoorError("front-door state is unavailable", 503) from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise FrontDoorError("front-door state is unavailable", 503)
    data.setdefault("devices", {})
    data.setdefault("pairing_codes", {})
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
    for row in profile_rows:
        if row.get("visible", True) is False:
            continue
        profile_id = str(row.get("name") or "").strip()
        if not profile_id:
            continue
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
        "supports_voice": False,
        "supports_approvals": False,
        "supports_cursor_replay": False,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Manage the opt-in S&G device front door")
    parser.add_argument("command", choices=["issue-code"])
    parser.add_argument("--ttl", type=int, default=300)
    args = parser.parse_args()
    if args.command == "issue-code":
        print(issue_pairing_code(ttl_seconds=args.ttl))
