from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.models import Role
from app.services.token_service import issue_signup_token


def test_open_signup_and_login_flow() -> None:
    with TestClient(app) as client:
        begin = client.post("/api/auth/signup/begin", json={"username": "alice"})
        assert begin.status_code == 200

        challenge_id = begin.json()["challenge_id"]
        complete = client.post(
            "/api/auth/signup/complete",
            json={
                "challenge_id": challenge_id,
                "credential": {
                    "id": "cred-alice-1",
                    "response": {"attestationObject": "pk-alice-1"},
                },
            },
        )
        assert complete.status_code == 200
        assert complete.json()["user"]["role"] == "user"

        me = client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["username"] == "alice"

        login_begin = client.post("/api/auth/login/begin", json={"username": "alice"})
        assert login_begin.status_code == 200

        login_challenge_id = login_begin.json()["challenge_id"]
        login_complete = client.post(
            "/api/auth/login/complete",
            json={"challenge_id": login_challenge_id, "credential": {"id": "cred-alice-1"}},
        )
        assert login_complete.status_code == 200


def test_invite_only_mode_blocks_public_signup_without_token(test_session_factory) -> None:
    settings = get_settings()

    with test_session_factory() as db:
        _, bootstrap_token = issue_signup_token(
            db,
            role=Role.SUPERADMIN,
            created_by_id=None,
            expires_in_minutes=60,
            token_pepper=settings.token_pepper,
        )
        db.commit()

    with TestClient(app) as client:
        begin_super = client.post(
            "/api/auth/signup/begin",
            json={"username": "root", "token": bootstrap_token},
        )
        assert begin_super.status_code == 200

        complete_super = client.post(
            "/api/auth/signup/complete",
            json={
                "challenge_id": begin_super.json()["challenge_id"],
                "credential": {
                    "id": "cred-root-1",
                    "response": {"attestationObject": "pk-root-1"},
                },
            },
        )
        assert complete_super.status_code == 200
        assert complete_super.json()["user"]["role"] == "superadmin"

        mode = client.put(
            "/api/admin/settings/public-signup-mode",
            json={"mode": "invite_only"},
        )
        assert mode.status_code == 200

        blocked = client.post("/api/auth/signup/begin", json={"username": "bob"})
        assert blocked.status_code == 403

        token_resp = client.post(
            "/api/admin/signup-tokens",
            json={"role": "user", "expires_in_minutes": 60},
        )
        assert token_resp.status_code == 200

        allowed = client.post(
            "/api/auth/signup/begin",
            json={"username": "bob", "token": token_resp.json()["token"]},
        )
        assert allowed.status_code == 200
