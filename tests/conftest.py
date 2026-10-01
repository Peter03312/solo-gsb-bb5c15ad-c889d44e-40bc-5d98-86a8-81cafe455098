import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from app import db, main


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """每个用例一个独立的临时 SQLite 数据库。"""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    with TestClient(main.app) as c:
        yield c
