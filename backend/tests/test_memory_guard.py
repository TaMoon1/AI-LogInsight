"""上传内存预检测试：把「机器跑不动这份日志」变成可读的拒绝理由。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import memory_guard
from app.services.memory_guard import (
    HEADROOM_BYTES,
    PEAK_FACTOR,
    check_upload_memory,
    estimate_peak_bytes,
)

client = TestClient(app)


def test_estimate_uses_measured_factor():
    assert estimate_peak_bytes(100 * 1048576) == int(100 * 1048576 * PEAK_FACTOR)


def test_small_upload_passes_with_plenty_of_memory(monkeypatch):
    monkeypatch.setattr(memory_guard, "available_bytes", lambda: 8 * 1024**3)
    assert check_upload_memory(10 * 1048576) is None


def test_large_upload_is_rejected_with_actionable_message(monkeypatch):
    # 本机真实场景：500 MB 日志需要约 2.2 GB，但只有 1.5 GB 可用
    monkeypatch.setattr(
        memory_guard, "available_bytes", lambda: int(1.5 * 1024**3)
    )
    problem = check_upload_memory(500 * 1048576)
    assert problem is not None
    assert "内存不足" in problem
    assert "约需" in problem and "可用内存仅" in problem
    # 给出可操作出路，而不是只说「失败」
    assert "拆分文件" in problem


def test_boundary_requires_headroom(monkeypatch):
    size = 200 * 1048576
    needed = estimate_peak_bytes(size)
    monkeypatch.setattr(memory_guard, "available_bytes", lambda: needed)
    assert check_upload_memory(size) is not None  # 刚好等于峰值：不给余量，拒绝
    monkeypatch.setattr(
        memory_guard, "available_bytes", lambda: needed + HEADROOM_BYTES
    )
    assert check_upload_memory(size) is None


def test_unknown_memory_fails_open(monkeypatch):
    """读不到系统信息时放行：不能因为拿不到内存数就拒绝用户上传。"""

    monkeypatch.setattr(memory_guard, "available_bytes", lambda: None)
    assert check_upload_memory(500 * 1048576) is None


def test_upload_endpoint_rejects_when_memory_is_short(monkeypatch):
    monkeypatch.setattr(
        memory_guard, "available_bytes", lambda: 128 * 1024 * 1024
    )
    payload = b"1.2.3.4 - - [12/Sep/2026:09:00:00 +0800] \"GET / HTTP/1.1\" 200 1\n" * 20000
    response = client.post(
        "/api/logs/upload", files={"file": ("big.log", payload, "text/plain")}
    )
    assert response.status_code == 413
    assert "内存不足" in response.json()["detail"]


@pytest.mark.parametrize("size_mb", [1, 10])
def test_normal_sized_uploads_still_work(size_mb, monkeypatch):
    monkeypatch.setattr(memory_guard, "available_bytes", lambda: 2 * 1024**3)
    payload = (
        b"1.2.3.4 - - [12/Sep/2026:09:00:00 +0800] \"GET / HTTP/1.1\" 200 1\n"
        * (size_mb * 100)
    )
    response = client.post(
        "/api/logs/upload", files={"file": (f"ok-{size_mb}mb.log", payload, "text/plain")}
    )
    assert response.status_code == 200
