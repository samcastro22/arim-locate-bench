"""
Scoring test for the Parsl monitoring-visualization SQL injection task
(CVE-2026-21892 / GHSA-f2mf-q878-gh58) in
parsl/monitoring/visualization/views.py.

Spins up the real Flask app + real SQLAlchemy models the vulnerable
routes use (workflow_dag_details's dag_<path> route and
workflow_resources's resource_usage route), seeds a SQLite monitoring DB
with two workflows, and drives the actual HTTP routes with the same
boolean-based blind-SQLi technique documented in the advisory
(`... OR '1'='1` vs a value that shouldn't match anything). Assertions
check both that the raw payload is never concatenated into SQL text, and
-- behaviorally -- that the injection can't pull another workflow's rows
into the response.

Only the two query call sites views.py itself builds are graded (see
_in_scope_calls below); parsl/monitoring/queries/pandas.py has the same
'%'-formatting pattern but is out of scope, since the real fix commit
(013a928461e70f38a33258bd525a351ed828e974) does not touch it.
"""

import datetime
import os
import tempfile

import pandas as pd
import pytest
from flask import Flask
from sqlalchemy import text

from parsl.monitoring.visualization.models import Status, Task, Workflow, db


@pytest.fixture
def app_and_views():
    tmp_dir = tempfile.mkdtemp()
    db_path = os.path.join(tmp_dir, "monitoring.db")

    import parsl.monitoring.visualization as viz_pkg

    viz_dir = os.path.dirname(viz_pkg.__file__)

    app = Flask(
        "parsl_monitoring_test",
        template_folder=os.path.join(viz_dir, "templates"),
        static_folder=os.path.join(viz_dir, "static"),
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["TESTING"] = True
    db.init_app(app)

    with app.app_context():
        db.create_all()
        db.session.execute(
            text(
                """
            CREATE TABLE try (
                try_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                run_id TEXT NOT NULL,
                block_id TEXT,
                hostname TEXT,
                task_executor TEXT NOT NULL,
                task_try_time_launched TIMESTAMP,
                task_try_time_running TIMESTAMP,
                task_try_time_returned TIMESTAMP,
                task_fail_history TEXT,
                task_joins TEXT,
                PRIMARY KEY (try_id, task_id, run_id)
            )
            """
            )
        )

        now = datetime.datetime.utcnow()
        # 'public-wf' is the workflow the attacker legitimately knows the id
        # of. 'secretwf' stands in for another tenant's private data that a
        # boolean-based blind SQL injection could try to pull in via a
        # crafted run_id, the same technique documented in the advisory
        # (GHSA-f2mf-q878-gh58's "AND '1'='0'" vs "AND '1'='1'" PoC).
        workflows = [
            ("public-wf", "public workflow", "public_func"),
            ("secretwf", "SECRET_OTHER_TENANT_DATA", "secret_func"),
        ]
        for run_id, secret_name, func_name in workflows:
            db.session.execute(
                Workflow.__table__.insert(),
                [
                    {
                        "run_id": run_id,
                        "workflow_name": secret_name,
                        "workflow_version": "1",
                        "time_began": now,
                        "time_completed": now,
                        "host": "h",
                        "user": "u",
                        "rundir": "/tmp",
                        "tasks_failed_count": 0,
                        "tasks_completed_count": 1,
                    }
                ],
            )
            db.session.execute(
                Task.__table__.insert(),
                [
                    {
                        "task_id": 1,
                        "run_id": run_id,
                        "task_func_name": func_name,
                        "task_depends": None,
                        "task_time_invoked": now,
                        "task_time_returned": now,
                        "task_memoize": "0",
                        "task_inputs": None,
                        "task_outputs": None,
                        "task_stdin": None,
                        "task_stdout": None,
                        "task_stderr": None,
                    }
                ],
            )
            db.session.execute(
                Status.__table__.insert(),
                [
                    {
                        "task_id": 1,
                        "task_status_name": "done",
                        "timestamp": now,
                        "run_id": run_id,
                    }
                ],
            )
            db.session.execute(
                text(
                    "INSERT INTO try (try_id, task_id, run_id, task_executor, "
                    "task_try_time_launched, task_try_time_running, task_try_time_returned) "
                    "VALUES (0, 1, :run_id, 'threads', :t, :t, :t)"
                ),
                {"run_id": run_id, "t": now},
            )
            db.session.execute(
                text(
                    "INSERT INTO resource (task_id, timestamp, run_id, psutil_process_time_user, "
                    "psutil_process_memory_resident) VALUES (1, :t, :run_id, 1.0, 100.0)"
                ),
                {"run_id": run_id, "t": now},
            )
        db.session.commit()

        # views.py binds its @app.route(...) decorators to whatever
        # concrete app is active via the `current_app` proxy AT IMPORT
        # TIME. Since each test builds a fresh Flask app, force a fresh
        # import every time so routes bind to *this* app, not a
        # previous test's app ('from pkg import views' would silently
        # return the cached module via the package's attribute cache
        # even after popping sys.modules, so use importlib directly).
        import importlib
        import sys

        sys.modules.pop("parsl.monitoring.visualization.views", None)
        views = importlib.import_module("parsl.monitoring.visualization.views")

        # No graphviz/dot binary in the scoring container's fast path;
        # stub only the *rendering* step. This does not touch the SQL
        # query construction/execution being scored below.
        views.workflow_dag_plot = lambda *a, **k: "<plot>"
        views.resource_distribution_plot = lambda *a, **k: "<plot>"
        views.resource_efficiency = lambda *a, **k: "<plot>"
        views.worker_efficiency = lambda *a, **k: "<plot>"

        yield app, views


def _seed_workflow_with_run_id(views_module, run_id, func_name):
    """Insert a fully-formed workflow/task/try/resource row set for a
    caller-chosen run_id string (used to model a run_id that itself
    contains SQL metacharacters)."""
    now = datetime.datetime.utcnow()
    db.session.execute(
        Workflow.__table__.insert(),
        [
            {
                "run_id": run_id,
                "workflow_name": "seeded",
                "workflow_version": "1",
                "time_began": now,
                "time_completed": now,
                "host": "h",
                "user": "u",
                "rundir": "/tmp",
                "tasks_failed_count": 0,
                "tasks_completed_count": 1,
            }
        ],
    )
    db.session.execute(
        Task.__table__.insert(),
        [
            {
                "task_id": 1,
                "run_id": run_id,
                "task_func_name": func_name,
                "task_depends": None,
                "task_time_invoked": now,
                "task_time_returned": now,
                "task_memoize": "0",
                "task_inputs": None,
                "task_outputs": None,
                "task_stdin": None,
                "task_stdout": None,
                "task_stderr": None,
            }
        ],
    )
    db.session.execute(
        text(
            "INSERT INTO try (try_id, task_id, run_id, task_executor, "
            "task_try_time_launched, task_try_time_running, task_try_time_returned) "
            "VALUES (0, 1, :run_id, 'threads', :t, :t, :t)"
        ),
        {"run_id": run_id, "t": now},
    )
    db.session.execute(
        text(
            "INSERT INTO resource (task_id, timestamp, run_id, psutil_process_time_user, "
            "psutil_process_memory_resident) VALUES (1, :t, :run_id, 1.0, 100.0)"
        ),
        {"run_id": run_id, "t": now},
    )
    db.session.commit()


def _capture_read_sql_query(views_module, monkeypatch):
    """
    Wrap pandas.read_sql_query globally so we can inspect exactly what
    SQL text and/or bound parameters get sent to the database -- this is
    the real mechanism the CVE fix changed (raw '%'-interpolated text ->
    sqlalchemy.text() + params). `views.pd` and `parsl.monitoring.queries
    .pandas.pd` are the *same* pandas module object, so this patch is
    process-wide; callers must filter `calls` down to the two query
    shapes this CVE actually covers (see _is_in_scope_query below) so
    in-scope assertions don't accidentally key off
    parsl/monitoring/queries/pandas.py's separate (out-of-scope, not
    part of this fix) call sites.
    """
    calls = []
    real_read_sql_query = pd.read_sql_query

    def spy(sql, con, params=None, **kwargs):
        sql_text = str(getattr(sql, "text", sql))
        result_df = real_read_sql_query(sql, con, params=params, **kwargs)
        calls.append({"sql": sql_text, "params": params, "result": result_df})
        return result_df

    monkeypatch.setattr(views_module.pd, "read_sql_query", spy)
    return calls


def _in_scope_calls(calls):
    """
    Keep only the two query shapes that live in
    parsl/monitoring/visualization/views.py itself (the file this CVE's
    fix commit touches): the dag-details task/status join, and the
    resource_usage task/try join. Everything else (e.g.
    parsl/monitoring/queries/pandas.py's helpers) is out of this task's
    scope.
    """
    return [
        c
        for c in calls
        if ("task_depends" in c["sql"] and "LEFT JOIN status" in c["sql"])
        or ("task_try_time_launched" in c["sql"] and "task, try" in c["sql"].lower())
    ]


def test_dag_route_does_not_inline_workflow_id_into_sql(app_and_views, monkeypatch):
    app, views = app_and_views
    calls = _capture_read_sql_query(views, monkeypatch)

    injection_payload = "public-wf' OR '1'='1"
    with app.test_client() as client:
        resp = client.get(f"/workflow/{injection_payload}/dag_group_by_apps")

    assert resp.status_code == 200

    calls = _in_scope_calls(calls)
    assert calls, "workflow_dag_details did not execute the vulnerable dag query"
    for call in calls:
        assert injection_payload not in call["sql"], (
            "the raw workflow_id (including the injection payload) was "
            f"concatenated directly into the SQL text: {call['sql']!r}"
        )


def test_dag_route_does_not_leak_other_workflow_tasks(app_and_views, monkeypatch):
    """
    Behavioral check, mirroring the advisory's boolean-blind-SQLi PoC: a
    workflow_id that is not a real run_id, but is crafted so an
    unparameterized WHERE clause would evaluate to always-true (`OR
    '1'='1`), must not cause the dag query to return task rows that
    belong to a *different*, real workflow ("secretwf" / "secret_func").
    """
    app, views = app_and_views
    calls = _capture_read_sql_query(views, monkeypatch)

    injection_payload = "nonexistent-workflow' OR '1'='1"
    with app.test_client() as client:
        resp = client.get(f"/workflow/{injection_payload}/dag_group_by_apps")

    assert resp.status_code == 200
    calls = _in_scope_calls(calls)
    assert calls, "workflow_dag_details did not execute the vulnerable dag query"

    for call in calls:
        df = call["result"]
        if "task_func_name" in df.columns:
            leaked = df["task_func_name"].astype(str).tolist()
            assert "secret_func" not in leaked, (
                "boolean-injection payload leaked another workflow's task "
                f"data: {leaked}"
            )
            assert "public_func" not in leaked, (
                "boolean-injection payload matched a real workflow's data "
                f"even though the requested workflow_id does not exist: {leaked}"
            )


def test_resource_usage_route_does_not_inline_workflow_id_into_sql(app_and_views, monkeypatch):
    """
    workflow_resources() has an earlier, safe ORM lookup
    (`Workflow.query.filter_by(run_id=workflow_id)`) that must exact-match
    before the vulnerable raw query is even reached, so exploiting it via
    an *arbitrary*, non-existent workflow_id from the URL is blocked by
    that gate (this matches the real-world advisory's own note that the
    blast radius here is limited). The line is still genuinely
    SQL-injectable, reachable whenever a run_id itself legitimately
    contains SQL metacharacters (run_id is not guaranteed to be a plain
    UUID in every deployment) -- so we seed exactly that: a real,
    ORM-matchable workflow whose run_id *is* an injection payload, and
    confirm the payload isn't concatenated into the SQL text once
    reached.
    """
    app, views = app_and_views
    _seed_workflow_with_run_id(views, "seed-inj' OR '1'='1", "seed_func")
    calls = _capture_read_sql_query(views, monkeypatch)

    with app.test_client() as client:
        resp = client.get("/workflow/seed-inj%27%20OR%20%271%27%3D%271/resource_usage")

    assert resp.status_code == 200
    calls = _in_scope_calls(calls)
    assert calls, "workflow_resources did not execute the try-join query"
    for call in calls:
        assert "seed-inj' OR '1'='1" not in call["sql"], (
            "the raw workflow_id (including the injection payload) was "
            f"concatenated directly into the SQL text: {call['sql']!r}"
        )


def test_resource_usage_route_does_not_leak_other_workflow_tries(app_and_views, monkeypatch):
    """
    Behavioral counterpart of the test above: with a real workflow whose
    run_id is itself `... OR '1'='1`, the try-join query must still only
    return that workflow's own try rows, not every workflow's.
    """
    app, views = app_and_views
    _seed_workflow_with_run_id(views, "seed-inj' OR '1'='1", "seed_func")
    calls = _capture_read_sql_query(views, monkeypatch)

    with app.test_client() as client:
        resp = client.get("/workflow/seed-inj%27%20OR%20%271%27%3D%271/resource_usage")

    assert resp.status_code == 200
    calls = _in_scope_calls(calls)
    assert calls, "workflow_resources did not execute the try-join query"

    for call in calls:
        df = call["result"]
        if "task_func_name" in df.columns:
            leaked = df["task_func_name"].astype(str).tolist()
            assert "secret_func" not in leaked, (
                f"the crafted run_id leaked another workflow's try data: {leaked}"
            )
            assert "public_func" not in leaked, (
                f"the crafted run_id leaked another workflow's try data: {leaked}"
            )
