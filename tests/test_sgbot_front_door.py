import json
import stat
from types import SimpleNamespace
from pathlib import Path
from urllib.parse import urlparse

import pytest

from api import sgbot_front_door as front_door


def test_pairing_is_single_use_and_tokens_are_only_stored_hashed(tmp_path):
    code = front_door.issue_pairing_code(state_dir=tmp_path)
    enrolled = front_door.enroll_device(
        code,
        "mac-1",
        "Spencer's Mac",
        "mac",
        server_origin="https://hermes.example",
        state_dir=tmp_path,
    )
    identity = front_door.authenticate(f"Bearer {enrolled['token']}", state_dir=tmp_path)
    assert identity.device_id == "mac-1"

    raw = (tmp_path / "sgbot_front_door.json").read_text(encoding="utf-8")
    assert enrolled["token"] not in raw
    assert code not in raw
    assert stat.S_IMODE((tmp_path / "sgbot_front_door.json").stat().st_mode) == 0o600

    with pytest.raises(front_door.FrontDoorError) as reused:
        front_door.enroll_device(
            code,
            "phone-1",
            "Phone",
            "phone",
            server_origin="https://hermes.example",
            state_dir=tmp_path,
        )
    assert reused.value.status == 401


def test_revoking_one_device_leaves_the_other_authorized(tmp_path):
    credentials = []
    for device_id, kind in (("mac-1", "mac"), ("phone-1", "phone")):
        code = front_door.issue_pairing_code(state_dir=tmp_path)
        credentials.append(front_door.enroll_device(
            code,
            device_id,
            device_id,
            kind,
            server_origin="https://hermes.example",
            state_dir=tmp_path,
        ))

    front_door.revoke_device(f"Bearer {credentials[1]['token']}", state_dir=tmp_path)
    with pytest.raises(front_door.FrontDoorError) as revoked:
        front_door.authenticate(f"Bearer {credentials[1]['token']}", state_dir=tmp_path)
    assert revoked.value.status == 401
    assert front_door.authenticate(f"Bearer {credentials[0]['token']}", state_dir=tmp_path).device_id == "mac-1"


def test_roster_is_sanitized_and_clarence_is_default():
    payload = front_door.roster_payload([
        {"name": "franklin", "path": "/secret/franklin", "gateway_running": False},
        {"name": "clarence", "path": "/secret/clarence", "gateway_running": True},
        {"name": "hidden", "visible": False, "gateway_running": True},
    ])
    assert payload == {
        "profiles": [
            {"id": "franklin", "display_name": "Franklin", "available": False, "reason": "Hermes profile is unavailable"},
            {"id": "clarence", "display_name": "Clarence", "available": True, "reason": None},
        ],
        "default_profile_id": "clarence",
    }
    assert "/secret" not in json.dumps(payload)


def test_capabilities_do_not_claim_unimplemented_run_routes():
    assert front_door.capabilities_payload() == {
        "version": "1",
        "supports_voice": False,
        "supports_approvals": False,
        "supports_cursor_replay": False,
    }


def test_corrupt_state_fails_closed(tmp_path):
    Path(tmp_path, "sgbot_front_door.json").write_text("not json", encoding="utf-8")
    with pytest.raises(front_door.FrontDoorError) as exc:
        front_door.authenticate("Bearer anything", state_dir=tmp_path)
    assert exc.value.status == 503


def test_routes_are_default_off(monkeypatch):
    import api.routes as routes

    monkeypatch.delenv("HERMES_WEBUI_SGBOT_FRONT_DOOR", raising=False)
    handler = SimpleNamespace(headers={})
    assert routes.handle_get(handler, urlparse("/v1/health")) is False
    assert routes.handle_post(handler, urlparse("/v1/devices/enroll")) is False
    assert routes.handle_delete(handler, urlparse("/v1/devices/self")) is False


def test_authenticated_routes_and_single_device_revoke(monkeypatch, tmp_path):
    import api.routes as routes

    monkeypatch.setenv("HERMES_WEBUI_SGBOT_FRONT_DOOR", "1")
    monkeypatch.setattr(front_door, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        routes,
        "j",
        lambda _handler, payload, status=200: {"status": status, "payload": payload},
    )
    monkeypatch.setattr(
        "api.profiles.list_profiles_api",
        lambda: [{"name": "clarence", "gateway_running": True}],
    )

    code = front_door.issue_pairing_code(state_dir=tmp_path)
    enrollment_body = {
        "code": code,
        "device_id": "mac-route",
        "display_name": "Route Mac",
        "kind": "mac",
    }
    monkeypatch.setattr(routes, "read_body", lambda _handler: enrollment_body)
    handler = SimpleNamespace(headers={"Host": "hermes.example"}, request=SimpleNamespace())
    enrolled = routes.handle_post(handler, urlparse("/v1/devices/enroll"))
    assert enrolled["status"] == 200
    token = enrolled["payload"]["token"]

    authorized = SimpleNamespace(headers={"Authorization": f"Bearer {token}"})
    roster = routes.handle_get(authorized, urlparse("/v1/profiles"))
    assert roster["status"] == 200
    assert roster["payload"]["default_profile_id"] == "clarence"

    revoked = routes.handle_delete(authorized, urlparse("/v1/devices/self"))
    assert revoked == {"status": 200, "payload": {}}
    rejected = routes.handle_get(authorized, urlparse("/v1/health"))
    assert rejected["status"] == 401


def test_front_door_routes_reject_missing_bearer(monkeypatch, tmp_path):
    import api.routes as routes

    monkeypatch.setenv("HERMES_WEBUI_SGBOT_FRONT_DOOR", "true")
    monkeypatch.setattr(front_door, "STATE_DIR", tmp_path)
    monkeypatch.setattr(
        routes,
        "j",
        lambda _handler, payload, status=200: {"status": status, "payload": payload},
    )
    response = routes.handle_get(SimpleNamespace(headers={}), urlparse("/v1/capabilities"))
    assert response["status"] == 401
