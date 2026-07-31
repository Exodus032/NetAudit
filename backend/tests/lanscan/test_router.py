from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netaudit.lanscan.providers import StaticInterfaceProvider, get_interface_provider, get_port_connector
from netaudit.lanscan.router import router
from netaudit.lanscan.service import CONSENT_NOTICE, LanScanService, get_lanscan_service

from .conftest import FakeConnector


def make_client(connector=None, interfaces=None, service=None):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_port_connector] = lambda: (connector or FakeConnector())
    app.dependency_overrides[get_interface_provider] = lambda: (interfaces or StaticInterfaceProvider([{"address": "192.168.1.10", "prefixlen": 24}]))
    # One instance per *client* (captured by closure, not constructed fresh
    # inside the lambda) -- FastAPI calls a dependency override once per
    # request, so a fresh LanScanService() per call would silently lose the
    # job between the POST and the following GET/DELETE. Still isolated
    # from the module-level default singleton and from every other test.
    instance = service if service is not None else LanScanService(connect_timeout=0.5)
    app.dependency_overrides[get_lanscan_service] = lambda: instance
    return TestClient(app)


def test_post_returns_job_with_consent_notice():
    client = make_client()
    resp = client.post("/api/devices/scan", json={"subnet": "192.168.1.0/30", "ports": [22, 80], "rate_limit_pps": 50})
    assert resp.status_code == 200
    body = resp.json()
    assert body["consent_notice"] == CONSENT_NOTICE
    assert "job_id" in body
    assert body["status"] == "running"


def test_post_invalid_subnet_400():
    client = make_client()
    resp = client.post("/api/devices/scan", json={"subnet": "8.8.8.0/24", "ports": [80], "rate_limit_pps": 10})
    assert resp.status_code == 400


def test_post_slash16_400():
    client = make_client()
    resp = client.post("/api/devices/scan", json={"subnet": "192.168.0.0/16", "ports": [80], "rate_limit_pps": 10})
    assert resp.status_code == 400


def test_get_poll_until_completed():
    client = make_client()
    resp = client.post("/api/devices/scan", json={"subnet": "192.168.1.0/30", "ports": [22], "rate_limit_pps": 100})
    job_id = resp.json()["job_id"]

    deadline = time.perf_counter() + 5.0
    status = None
    while time.perf_counter() < deadline:
        poll = client.get(f"/api/devices/scan/{job_id}")
        assert poll.status_code == 200
        status = poll.json()["status"]
        if status != "running":
            break
        time.sleep(0.01)
    assert status == "completed"


def test_get_unknown_job_404():
    client = make_client()
    resp = client.get("/api/devices/scan/does-not-exist")
    assert resp.status_code == 404


def test_delete_unknown_job_404():
    client = make_client()
    resp = client.delete("/api/devices/scan/does-not-exist")
    assert resp.status_code == 404


def test_second_concurrent_scan_via_router_gets_409():
    service = LanScanService(connect_timeout=5.0)
    from .conftest import BlockingConnector

    connector = BlockingConnector()
    client = make_client(connector=connector, service=service)

    resp1 = client.post("/api/devices/scan", json={"subnet": "192.168.1.0/24", "ports": [22], "rate_limit_pps": 1})
    assert resp1.status_code == 200
    assert connector.first_call_started.wait(timeout=2.0)

    resp2 = client.post("/api/devices/scan", json={"subnet": "192.168.1.0/24", "ports": [22], "rate_limit_pps": 1})
    assert resp2.status_code == 409

    connector.release_event.set()
    client.delete(f"/api/devices/scan/{resp1.json()['job_id']}")


def test_delete_cancels_and_returns_cancelled_status():
    service = LanScanService(connect_timeout=5.0)
    from .conftest import BlockingConnector

    connector = BlockingConnector()
    client = make_client(connector=connector, service=service)

    resp = client.post("/api/devices/scan", json={"subnet": "192.168.1.0/24", "ports": [22], "rate_limit_pps": 1})
    job_id = resp.json()["job_id"]
    assert connector.first_call_started.wait(timeout=2.0)

    connector.release_event.set()
    del_resp = client.delete(f"/api/devices/scan/{job_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "cancelled"
