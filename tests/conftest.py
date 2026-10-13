import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="pg-tests-")
TEMPLATE_DB = os.path.join(TMP, "template.db")
os.environ.update(PG_INSTANCE_DIR=TMP, PG_DATABASE=TEMPLATE_DB, PG_HTTPS="0", APP_ENV="test")
sys.path.insert(0, str(ROOT))

from scripts import seed  # noqa: E402

seed.main(reset=True)  # seed once; each test gets a fresh copy

from app import create_app  # noqa: E402
from app.security import limiter  # noqa: E402

PASSWORD = seed.DEMO_PASSWORD
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def app(tmp_path):
    db = tmp_path / "test.db"
    shutil.copy(TEMPLATE_DB, db)
    application = create_app({"DATABASE": str(db), "HTTPS": False, "TESTING": True})
    limiter._hits.clear()
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def csrf_from(client, path="/login") -> str:
    return CSRF_RE.search(client.get(path).get_data(as_text=True)).group(1)


def login(client, username, password=PASSWORD, follow=False):
    token = csrf_from(client, "/login")
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token},
                       follow_redirects=follow)


@pytest.fixture
def as_role(app):
    """Return a logged-in client and its CSRF token for a demo account."""
    def make(username):
        c = app.test_client()
        r = login(c, username)
        assert r.status_code == 302, r.get_data(as_text=True)[:500]
        home = r.headers["Location"]
        token = csrf_from(c, home)
        return c, token
    return make


def db_query(app, sql, params=()):
    from app.db import query
    with app.app_context():
        return [dict(r) for r in query(sql, params)]


def student_id(app, pid):
    return db_query(app, "SELECT id FROM students WHERE placement_id = ?", (pid,))[0]["id"]


def drive_id(app, company):
    return db_query(app, "SELECT d.id FROM drives d JOIN companies c ON c.id = d.company_id WHERE c.name = ?", (company,))[0]["id"]
