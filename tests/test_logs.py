"""The JSON log format and its session scope (PLT-OAM-005, VP1-OAM-004,
PLT-VP-R1 RES-OP-04). ENV-UNIT."""

from __future__ import annotations

import io
import json
import logging
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from service import logs  # noqa: E402


@pytest.fixture
def lines():
    """Every line the service's handler writes, parsed as JSON."""
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.addFilter(logs.CorrelationFilter())
    handler.setFormatter(logs.JsonFormatter())
    logger = logging.getLogger("mcx.test-logs")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    yield lambda: [json.loads(l) for l in out.getvalue().splitlines()]
    logger.removeHandler(handler)


LOG = logging.getLogger("mcx.test-logs")


@pytest.mark.vp("VP1-OAM-004")
def test_a_line_logged_in_a_session_s_scope_carries_its_id(lines):
    LOG.info("outside")
    with logs.session_context("call-1"):
        LOG.warning("inside %s", "one")
        with logs.session_context("call-2"):
            LOG.info("nested")
        LOG.info("back")
    LOG.info("after")
    got = [(l["message"], l.get("correlation_id")) for l in lines()]
    assert got == [("outside", None), ("inside one", "call-1"), ("nested", "call-2"),
                   ("back", "call-1"), ("after", None)]


@pytest.mark.vp("VP1-OAM-004")
def test_an_id_the_record_names_wins_over_the_scope(lines):
    """The core cannot import the service's scope and names its session."""
    with logs.session_context("scope"):
        LOG.info("named", extra={"correlation_id": "named-id"})
    LOG.info("named outside", extra={"correlation_id": "other"})
    assert [l["correlation_id"] for l in lines()] == ["named-id", "other"]


def test_an_empty_id_is_no_session(lines):
    with logs.session_context(""):
        LOG.info("empty")
    with logs.session_context(None):
        LOG.info("none")
    assert all("correlation_id" not in l for l in lines())


def test_each_thread_logs_its_own_session(lines):
    """The media plane's receive threads each serve one session."""
    ready = threading.Barrier(2)

    def serve(cid):
        with logs.session_context(cid):
            ready.wait()
            for i in range(20):
                LOG.info("%s %d", cid, i)

    threads = [threading.Thread(target=serve, args=(c,)) for c in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    got = lines()
    assert len(got) == 40
    assert all(l["message"].split()[0] == l["correlation_id"] for l in got)


def test_the_formatter_writes_what_the_filter_stamped():
    """One mechanism: the filter stamps the record in the logging thread;
    the formatter only writes it."""
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "m", (), None)
    with logs.session_context("s1"):
        assert "correlation_id" not in json.loads(logs.JsonFormatter().format(record))
        logs.CorrelationFilter().filter(record)
    assert json.loads(logs.JsonFormatter().format(record))["correlation_id"] == "s1"


def test_the_line_is_json_with_the_documented_fields(lines):
    with logs.session_context("c9"):
        try:
            raise ValueError("boom")
        except ValueError:
            LOG.exception("failed")
    [line] = lines()
    assert set(line) == {"at_ms", "level", "logger", "message", "correlation_id",
                         "exception"}
    assert (line["level"], line["logger"], line["message"], line["correlation_id"]) == (
        "ERROR", "mcx.test-logs", "failed", "c9")
    assert "ValueError: boom" in line["exception"]


@pytest.mark.vp("VP1-OAM-004")
def test_configure_installs_the_filter_and_the_json_formatter():
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        logs.configure()
        [handler] = root.handlers
        assert isinstance(handler.formatter, logs.JsonFormatter)
        assert any(isinstance(f, logs.CorrelationFilter) for f in handler.filters)
    finally:
        root.handlers[:], _ = saved
        root.setLevel(saved[1])
