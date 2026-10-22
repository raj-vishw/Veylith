import os
import tempfile
from pathlib import Path

from sqlalchemy.engine import make_url

TEST_DB = "veylith_test"


def _url(name: str, database: str) -> str:
    return make_url(os.environ[name]).set(database=database).render_as_string(hide_password=False)


# Point everything at an isolated test database BEFORE the application is imported.
ADMIN_URL = _url("MIGRATION_DATABASE_URL", "postgres")
os.environ["DATABASE_URL"] = _url("DATABASE_URL", TEST_DB)
os.environ["MIGRATION_DATABASE_URL"] = _url("MIGRATION_DATABASE_URL", TEST_DB)
os.environ["ALEMBIC_DATABASE_URL"] = os.environ["MIGRATION_DATABASE_URL"]
os.environ["CELERY_EAGER"] = "true"
os.environ["STORAGE_DIR"] = tempfile.mkdtemp(prefix="veylith-test-storage-")
os.environ["ENVIRONMENT"] = "test"
os.environ["AUTO_CORRELATE"] = "false"  # tests trigger correlation explicitly; see test_autocorrelate.py
os.environ["NVD_API_KEY"] = ""

import email_validator  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

# Tests use the reserved .test TLD for addresses; production keeps the stricter default.
if "test" in email_validator.SPECIAL_USE_DOMAIN_NAMES:
    email_validator.SPECIAL_USE_DOMAIN_NAMES.remove("test")

from app.models import Base  # noqa: E402
from app.security import limiter  # noqa: E402

from .helpers import TEST_PASSWORD  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _database():
    admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)"))
        conn.execute(text(f"CREATE DATABASE {TEST_DB}"))
        conn.execute(text(f"GRANT CONNECT ON DATABASE {TEST_DB} TO veylith_app"))
    admin.dispose()
    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    command.upgrade(cfg, "head")  # also proves the migrations apply from scratch
    yield


@pytest.fixture(scope="session")
def owner_engine():
    """Schema-owner connection: bypasses RLS, used for fixtures and for inspecting what the app wrote."""
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"])
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def _clean(owner_engine):
    names = ", ".join(t.name for t in Base.metadata.sorted_tables)
    with owner_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
    limiter.reset()
    yield


class Api:
    """HTTP client that keeps its session cookie and sends the CSRF token on every request."""

    def __init__(self):
        from app.main import app

        self.http = TestClient(app, base_url="http://localhost")
        self.csrf = ""
        self.me_data: dict = {}

    def _headers(self, extra=None):
        h = {"X-CSRF-Token": self.csrf} if self.csrf else {}
        h.update(extra or {})
        return h

    def request(self, method, path, **kw):
        kw["headers"] = self._headers(kw.get("headers"))
        return self.http.request(method, "/api/v1" + path, **kw)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    def patch(self, path, **kw):
        return self.request("PATCH", path, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    def _adopt(self, resp):
        if resp.status_code in (200, 201):
            self.me_data = resp.json()
            self.csrf = self.me_data["csrf_token"]
        return resp

    def register(self, email, org="Acme MSP", password=TEST_PASSWORD):
        return self._adopt(self.post("/auth/register", json={"email": email, "password": password, "organization_name": org, "display_name": email.split("@")[0]}))

    def login(self, email, password=TEST_PASSWORD, organization_id=None):
        body = {"email": email, "password": password}
        if organization_id:
            body["organization_id"] = organization_id
        return self._adopt(self.post("/auth/login", json=body))

    @property
    def org_id(self):
        return self.me_data["organization"]["id"]

    @property
    def user_id(self):
        return self.me_data["user"]["id"]


@pytest.fixture
def make_api():
    return Api


@pytest.fixture
def owner(make_api):
    api = make_api()
    assert api.register("owner@msp.test").status_code == 201
    return api


@pytest.fixture
def other_owner(make_api):
    """An owner of a completely separate organization."""
    api = make_api()
    assert api.register("owner@rival.test", org="Rival MSP").status_code == 201
    return api


def member_api(make_api, owner_api, email, role):
    assert owner_api.post("/members", json={"email": email, "password": TEST_PASSWORD, "role": role}).status_code == 201
    api = make_api()
    assert api.login(email).status_code == 200
    return api


@pytest.fixture
def analyst(make_api, owner):
    return member_api(make_api, owner, "analyst@msp.test", "analyst")


@pytest.fixture
def viewer(make_api, owner):
    return member_api(make_api, owner, "viewer@msp.test", "viewer")
