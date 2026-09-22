import json
import stat
import sys
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
        {"name": "clarence", "path": "/duplicate/clarence", "gateway_running": True},
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
        "supports_voice": True,
        "supports_approvals": False,
        "supports_cursor_replay": False,
    }


def test_bot_chat_identity_is_stable_and_fail_closed():
    assert front_door.bot_chat_payload("clarence", "Clarence") == {
        "id": "sgbot.bot-chat.clarence",
        "persona_id": "clarence",
        "title": "Clarence",
    }
    assert front_door.profile_id_for_chat("sgbot.bot-chat.franklin") == "franklin"
    with pytest.raises(front_door.FrontDoorError) as malformed:
        front_door.profile_id_for_chat("some-local-chat")
    assert malformed.value.status == 404


def test_profile_gateway_resolution_keeps_endpoint_and_key_server_side(monkeypatch, tmp_path):
    profile_home = tmp_path / "clarence"
    profile_home.mkdir()
    monkeypatch.setattr(
        "api.providers._load_env_file",
        lambda _path: {"API_SERVER_PORT": "8644", "API_SERVER_KEY": "server-only-key"},
    )
    gateway = front_door.resolve_profile_gateway("clarence", [{
        "name": "clarence",
        "path": str(profile_home),
        "visible": True,
        "gateway_running": True,
    }])
    assert gateway.base_url == "http://127.0.0.1:8644"
    assert gateway.api_key == "server-only-key"
    assert "server-only-key" not in json.dumps(front_door.roster_payload([{
        "name": "clarence", "path": str(profile_home), "gateway_running": True,
    }]))


def test_history_reads_canonical_profile_state(monkeypatch, tmp_path):
    profile_home = tmp_path / "clarence"
    profile_home.mkdir()
    (profile_home / "state.db").write_bytes(b"fixture")
    observed = {}

    class FakeDB:
        def __init__(self, db_path, read_only):
            observed.update(db_path=db_path, read_only=read_only, closed=False)

        def get_messages_as_conversation(self, session_id, **kwargs):
            observed.update(session_id=session_id, kwargs=kwargs)
            return [
                {"row_id": 7, "role": "user", "content": "hello"},
                {"row_id": 8, "role": "assistant", "content": "hi"},
            ]

        def close(self):
            observed["closed"] = True

    monkeypatch.setitem(sys.modules, "hermes_state", SimpleNamespace(SessionDB=FakeDB))
    payload = front_door.load_history("sgbot.bot-chat.clarence", [{
        "name": "clarence", "path": str(profile_home), "gateway_running": True,
    }])
    assert payload["session_id"] == "sgbot.bot-chat.clarence"
    assert [(item["id"], item["role"], item["text"]) for item in payload["messages"]] == [
        ("7", "user", "hello"), ("8", "assistant", "hi"),
    ]
    assert observed["read_only"] is True
    assert observed["session_id"] == "sgbot.bot-chat.clarence"
    assert observed["closed"] is True


def test_create_run_forwards_stable_chat_and_persists_profile_owner(monkeypatch, tmp_path):
    gateway = front_door.ProfileGateway("clarence", tmp_path, "http://127.0.0.1:8644", "secret")
    monkeypatch.setattr(front_door, "resolve_profile_gateway", lambda *_args: gateway)
    observed = {}

    def fake_proxy(resolved, method, path, *, body=None, headers=None):
        observed.update(gateway=resolved, method=method, path=path, body=body, headers=headers)
        return 202, {"run_id": "run-1", "status": "started"}

    monkeypatch.setattr(front_door, "proxy_json", fake_proxy)
    status, payload = front_door.create_run(
        "sgbot.bot-chat.clarence",
        {"content": "hello", "session_id": "sgbot.bot-chat.clarence"},
        [],
        idempotency_key="idem-1",
        state_dir=tmp_path,
    )
    assert status == 202
    assert payload["run_id"] == "run-1"
    assert observed["body"] == {"input": "hello", "session_id": "sgbot.bot-chat.clarence"}
    assert observed["headers"] == {"Idempotency-Key": "idem-1"}
    assert front_door._load(tmp_path)["runs"]["run-1"]["profile_id"] == "clarence"


def test_run_controls_resolve_the_original_profile(monkeypatch, tmp_path):
    state = front_door._load(tmp_path)
    state["runs"]["run/1"] = {
        "profile_id": "franklin", "chat_id": "sgbot.bot-chat.franklin", "updated_at": 1,
    }
    front_door._save(state, tmp_path)
    gateway = front_door.ProfileGateway("franklin", tmp_path, "http://127.0.0.1:8642", "secret")
    monkeypatch.setattr(front_door, "resolve_profile_gateway", lambda profile_id, _rows: gateway)
    observed = {}
    monkeypatch.setattr(
        front_door,
        "proxy_json",
        lambda resolved, method, path, *, body=None, headers=None: (
            observed.update(gateway=resolved, method=method, path=path, body=body) or (200, {"accepted": True})
        ),
    )
    status, payload = front_door.proxy_run_json(
        "run/1", "/steer", "POST", [], body={"input": "focus"}, state_dir=tmp_path,
    )
    assert (status, payload) == (200, {"accepted": True})
    assert observed["gateway"].profile_id == "franklin"
    assert observed["path"] == "/v1/runs/run%2F1/steer"


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
        routes,
        "list_profiles_api",
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

    chat = routes.handle_get(authorized, urlparse("/v1/profiles/clarence/bot-chat"))
    assert chat["payload"]["id"] == "sgbot.bot-chat.clarence"
    monkeypatch.setattr(
        front_door,
        "load_history",
        lambda chat_id, _rows: {"session_id": chat_id, "messages": [], "next_cursor": None},
    )
    history = routes.handle_get(
        authorized, urlparse("/v1/bot-chats/sgbot.bot-chat.clarence/messages")
    )
    assert history["payload"]["session_id"] == "sgbot.bot-chat.clarence"

    monkeypatch.setattr(routes, "read_body", lambda _handler: {
        "content": "hello", "session_id": "sgbot.bot-chat.clarence",
    })
    monkeypatch.setattr(
        front_door,
        "create_run",
        lambda chat_id, body, _rows, *, idempotency_key: (
            202,
            {"run_id": "run-route", "status": "started", "chat_id": chat_id,
             "idempotency_key": idempotency_key, "input": body["content"]},
        ),
    )
    authorized.headers["Idempotency-Key"] = "route-idempotency"
    created = routes.handle_post(
        authorized, urlparse("/v1/bot-chats/sgbot.bot-chat.clarence/runs")
    )
    assert created["status"] == 202
    assert created["payload"]["run_id"] == "run-route"

    monkeypatch.setattr(
        front_door,
        "proxy_run_json",
        lambda run_id, suffix, method, _rows, *, body=None: (
            200, {"run_id": run_id, "status": "running", "suffix": suffix, "method": method},
        ),
    )
    status = routes.handle_get(authorized, urlparse("/v1/runs/run-route"))
    assert status["payload"]["status"] == "running"

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
