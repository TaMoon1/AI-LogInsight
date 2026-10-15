"""AI 任务状态的持久化：服务重启后、多 worker 部署下都要能查到进度与结果。

原先任务状态只存在进程内存（`AI_TASKS`）里，重启即丢、多 worker 互相看不见。
现在同库另表落盘，内存只作为运行期缓存。
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app.main import app

client = TestClient(app)


@pytest.fixture()
def isolated_tasks():
    """隔离内存任务表，避免与其它用例互相影响。"""

    saved = dict(main_module.AI_TASKS)
    main_module.AI_TASKS.clear()
    yield main_module
    main_module.AI_TASKS.clear()
    main_module.AI_TASKS.update(saved)


def _seed(task_id: str, *, status: str, age_seconds: float, partial: str | None = None):
    now = time.time()
    main_module.repository.save_ai_task(
        {
            "task_id": task_id,
            "analysis_id": "analysis-x",
            "status": status,
            "stage": "completed" if status != "running" else "call_model",
            "progress": 100 if status != "running" else 65,
            "error": None,
            "result": None,
            "partial": partial,
            "created_at": datetime.fromtimestamp(now - age_seconds, timezone.utc).isoformat(),
            "updated_at": now - age_seconds,
        }
    )


def test_task_is_readable_after_restart(isolated_tasks):
    """重启后内存为空，但库里有 ⇒ 仍然查得到（这是多 worker / 重启场景的关键）。"""

    _seed("t-restart", status="completed", age_seconds=5, partial="结论正在生成")
    assert client.get("/api/ai/tasks/t-restart").json()["status"] == "completed"
    body = client.get("/api/ai/tasks/t-restart").json()
    assert body["partial"] == "结论正在生成"
    assert body["progress"] == 100
    assert body["analysis_id"] == "analysis-x"


def test_task_state_is_upserted_not_duplicated(isolated_tasks):
    _seed("t-upsert", status="running", age_seconds=1)
    _seed("t-upsert", status="completed", age_seconds=0)
    rows = main_module.repository.get_ai_task("t-upsert")
    assert rows is not None
    assert rows["status"] == "completed"


def test_unknown_task_is_still_404(isolated_tasks):
    assert client.get("/api/ai/tasks/not-exist").status_code == 404


def test_finished_stored_task_is_pruned_after_ttl(isolated_tasks):
    """已结束且超过保留期的任务要清掉，否则这张表会一直涨。"""

    _seed("t-old", status="completed", age_seconds=main_module.AI_TASK_TTL_SECONDS + 60)
    _seed("t-fresh", status="completed", age_seconds=5)
    main_module._prune_stored_ai_tasks()
    assert main_module.repository.get_ai_task("t-old") is None
    assert main_module.repository.get_ai_task("t-fresh") is not None


def test_running_stored_task_is_never_pruned(isolated_tasks):
    """运行中的任务不能被清掉，否则前端轮询会突然拿到 404。"""

    _seed("t-running", status="running", age_seconds=main_module.AI_TASK_TTL_SECONDS * 10)
    main_module._prune_stored_ai_tasks()
    assert main_module.repository.get_ai_task("t-running") is not None


def test_failure_is_persisted_with_readable_reason(isolated_tasks):
    """失败原因也要落盘：重启后重新查这条任务应能看到「为什么失败」。"""

    now = time.time()
    main_module.AI_TASKS["t-fail"] = {
        "task_id": "t-fail",
        "analysis_id": "not-exist",
        "status": "running",
        "stage": "prepare_context",
        "progress": 5,
        "error": None,
        "result": None,
        "partial": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": now,
    }
    main_module._run_ai_task("t-fail", "not-exist")

    stored = main_module.repository.get_ai_task("t-fail")
    assert stored is not None
    assert stored["status"] == "failed"
    assert stored["error"] == "分析记录不存在"


def test_running_task_is_recovered_once_after_restart(monkeypatch, isolated_tasks):
    stored = {
        "task_id": "t-recover",
        "analysis_id": "analysis-x",
        "status": "running",
        "stage": "call_model",
        "progress": 65,
        "error": None,
        "result": None,
        "partial": "正在生成",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    started: list[tuple[str, str]] = []
    saved: list[dict] = []
    monkeypatch.setattr(main_module.repository, "list_ai_tasks", lambda status: [stored])
    monkeypatch.setattr(main_module.repository, "get", lambda _analysis_id: object())
    monkeypatch.setattr(main_module.repository, "get_records", lambda _analysis_id: [])
    monkeypatch.setattr(main_module.repository, "save_ai_task", saved.append)
    monkeypatch.setattr(
        main_module, "_start_ai_task_thread", lambda task_id, analysis_id: started.append(
            (task_id, analysis_id)
        )
    )

    assert main_module.recover_running_ai_tasks() == 1
    assert started == [("t-recover", "analysis-x")]
    assert main_module.AI_TASKS["t-recover"]["stage"] == "recovering"
    assert main_module.AI_TASKS["t-recover"]["partial"] == "正在生成"
    assert saved

    assert main_module.recover_running_ai_tasks() == 0
    assert started == [("t-recover", "analysis-x")]


def test_missing_analysis_is_marked_failed_during_recovery(
    monkeypatch, isolated_tasks
):
    stored = {
        "task_id": "t-missing",
        "analysis_id": "not-exist",
        "status": "running",
        "stage": "call_model",
        "progress": 65,
        "error": None,
        "result": None,
        "partial": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    saved: list[dict] = []
    monkeypatch.setattr(main_module.repository, "list_ai_tasks", lambda status: [stored])
    monkeypatch.setattr(main_module.repository, "get", lambda _analysis_id: None)
    monkeypatch.setattr(main_module.repository, "get_records", lambda _analysis_id: None)
    monkeypatch.setattr(main_module.repository, "save_ai_task", saved.append)
    monkeypatch.setattr(
        main_module, "_start_ai_task_thread", lambda *_args: pytest.fail("不应启动线程")
    )

    assert main_module.recover_running_ai_tasks() == 0
    task = main_module.AI_TASKS["t-missing"]
    assert task["status"] == "failed"
    assert "分析记录不存在" in task["error"]
    assert saved
