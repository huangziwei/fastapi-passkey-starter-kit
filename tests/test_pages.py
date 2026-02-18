from fastapi.testclient import TestClient

from app.main import app


def test_signup_pages_are_available() -> None:
    with TestClient(app) as client:
        signup = client.get('/signup')
        assert signup.status_code == 200
        assert 'User signup' in signup.text
        assert 'Passkey label' not in signup.text

        admin_signup = client.get('/admin_signup')
        assert admin_signup.status_code == 200
        assert 'Admin or Superadmin signup' in admin_signup.text
        assert 'Passkey label' not in admin_signup.text

        login = client.get('/login')
        assert login.status_code == 200
        assert 'Login with passkey' in login.text

        passkeys = client.get('/passkeys')
        assert passkeys.status_code == 200
        assert 'Passkey management' in passkeys.text

        admin = client.get('/admin', follow_redirects=False)
        assert admin.status_code == 303
        assert admin.headers['location'] == '/login'

        me = client.get('/me')
        assert me.status_code == 200
        assert 'Current session' in me.text
