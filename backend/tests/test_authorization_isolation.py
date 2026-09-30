"""Multi-tenancy: investigations are private to their owner.

This is the critical authorization boundary.  Two independent accounts are
used — ``client`` (user A) and ``second_client`` (user B) — and the tests pin
that neither can read, delete, or even *enumerate* the other's work, and that
a foreign id is indistinguishable from a missing one (``404``, not ``403``), so
existence is never leaked.

There is no update/rename endpoint, so "modify" reduces to delete + create; the
delete cases below cover that surface.
"""
from __future__ import annotations

from tests.conftest import BANKING_PHISH


def _create(tc, title: str) -> str:
    resp = tc.post("/api/investigations", data={"text": BANKING_PHISH, "title": title})
    assert resp.status_code == 200, resp.text
    return resp.json()["investigation_id"]


def test_other_user_cannot_read_a_foreign_investigation(client, second_client):
    inv = _create(client, "A: private banking phish")
    assert client.get(f"/api/investigations/{inv}").status_code == 200
    # B gets the same 404 a missing id would produce — no existence leak.
    assert second_client.get(f"/api/investigations/{inv}").status_code == 404
    # …and it is still there for its owner.
    assert client.get(f"/api/investigations/{inv}").status_code == 200
    client.delete(f"/api/investigations/{inv}")


def test_other_user_cannot_delete_a_foreign_investigation(client, second_client):
    inv = _create(client, "A: delete-protected")
    assert second_client.delete(f"/api/investigations/{inv}").status_code == 404
    # The owner's record survived the attempt.
    assert client.get(f"/api/investigations/{inv}").status_code == 200
    client.delete(f"/api/investigations/{inv}")


def test_isolation_is_symmetric(client, second_client):
    a = _create(client, "A: symmetric")
    b = _create(second_client, "B: symmetric")
    assert second_client.get(f"/api/investigations/{a}").status_code == 404
    assert client.get(f"/api/investigations/{b}").status_code == 404
    assert second_client.delete(f"/api/investigations/{a}").status_code == 404
    assert client.delete(f"/api/investigations/{b}").status_code == 404
    client.delete(f"/api/investigations/{a}")
    second_client.delete(f"/api/investigations/{b}")


def test_history_only_returns_the_current_users_investigations(client, second_client):
    a = _create(client, "A: history")
    b = _create(second_client, "B: history")

    a_ids = [item["id"] for item in client.get("/api/investigations", params={"page_size": 100}).json()["items"]]
    b_ids = [
        item["id"]
        for item in second_client.get("/api/investigations", params={"page_size": 100}).json()["items"]
    ]

    assert a in a_ids and b not in a_ids
    assert b in b_ids and a not in b_ids

    client.delete(f"/api/investigations/{a}")
    second_client.delete(f"/api/investigations/{b}")


def test_missing_and_foreign_ids_are_indistinguishable(client, second_client):
    inv = _create(client, "A: indistinguishable")
    foreign = second_client.get(f"/api/investigations/{inv}")
    missing = second_client.get("/api/investigations/00000000-0000-0000-0000-000000000000")
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()
    client.delete(f"/api/investigations/{inv}")


def test_anonymous_cannot_touch_history(anon_client):
    assert anon_client.get("/api/investigations").status_code == 401
