"""Per-profile conformance suite (VP1-BND-021 / PLT-VER-001).

One suite, run once per profile against the SAME built artefact. The profile
under test is named by `MCX_PROFILE`; CI runs this file once per profile.

This is the mechanical half of PLT-VER-003. Nothing here asserts behaviour
specific to one profile — every assertion is derived from the loaded profile's
own declarations. A test that needed an `if profile.name == ...` would be
evidence that the abstraction had failed, so there is none.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import Auditor, MemorySink, RecordType  # noqa: E402
from core.hooks import MediaKind, Resolution, ResolutionKind, SessionRequest  # noqa: E402
from core.session import SessionManager  # noqa: E402

PROFILES = ROOT / "profiles"
PROFILE_NAME = os.environ.get("MCX_PROFILE", "mcx")


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


@pytest.fixture(scope="module")
def loaded():
    directory = PROFILES / PROFILE_NAME
    if not directory.is_dir():
        pytest.fail(f"MCX_PROFILE={PROFILE_NAME!r} names no profile package")
    return loader.load(directory)


@pytest.fixture
def manager(loaded):
    sink = MemorySink()
    auditor = Auditor(sink, loaded.profile.identifier(), clock=Clock())
    return SessionManager(loaded, auditor, clock=Clock()), sink


def any_resolution():
    return Resolution(kind=ResolutionKind.USER, members=("sip:x@example",))


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def test_profile_loads(loaded):
    assert loaded.profile.name == PROFILE_NAME
    assert len(loaded.profile.content_hash) == 64


def test_all_five_hooks_resolve(loaded):
    for field in ("identity_resolver", "priority_policy", "session_policy",
                  "bearer_selector", "interworking_gateway"):
        assert getattr(loaded.hooks, field) is not None


def test_identity_triple_is_well_formed(loaded):
    parts = loaded.profile.identifier().split("/")
    assert len(parts) == 3 and all(parts)


# --------------------------------------------------------------------------
# Totality — derived from the profile, never hardcoded
# --------------------------------------------------------------------------


def test_priority_is_total_over_declared_call_types(loaded):
    policy = loaded.hooks.priority_policy
    scopes = {s.id for s in loaded.profile.preemption_scopes}
    for call_type in loaded.profile.call_types:
        request = SessionRequest(
            request_id="c", initiator="sip:a@example", target="t",
            call_type=call_type.id,
            media=tuple(MediaKind(m) for m in call_type.media))
        decision = policy.evaluate(request, any_resolution())
        assert decision.scope in scopes
        assert decision.label


def test_bearer_is_total_over_declared_media(loaded):
    selector = loaded.hooks.bearer_selector
    policy = loaded.hooks.priority_policy
    for call_type in loaded.profile.call_types:
        media = tuple(MediaKind(m) for m in call_type.media)
        request = SessionRequest(request_id="c", initiator="sip:a@example",
                                 target="t", call_type=call_type.id, media=media)
        priority = policy.evaluate(request, any_resolution())
        decision = selector.select(request, priority, media)
        assert sum(1 for p in decision.paths if p.primary) == 1
        assert len({p.path_id for p in decision.paths}) == len(decision.paths)


def test_session_decision_available_for_every_call_type(loaded):
    policy = loaded.hooks.session_policy
    for call_type in loaded.profile.call_types:
        request = SessionRequest(
            request_id="c", initiator="sip:a@example", target="t",
            call_type=call_type.id,
            media=tuple(MediaKind(m) for m in call_type.media))
        decision = policy.decide(request, any_resolution())
        assert decision.model.value == call_type.session_model
        assert decision.recording_required == call_type.recording_required


def test_floor_policy_consistent_for_every_voice_call_type(loaded):
    policy = loaded.hooks.session_policy
    for call_type in loaded.profile.call_types:
        if "voice" not in call_type.media and "video" not in call_type.media:
            continue
        request = SessionRequest(
            request_id="c", initiator="sip:a@example", target="t",
            call_type=call_type.id,
            media=tuple(MediaKind(m) for m in call_type.media))
        floor = policy.floor_policy(request, any_resolution())
        if floor.queueing_enabled:
            assert floor.max_queue_depth >= 1
        else:
            assert floor.max_queue_depth == 0


# --------------------------------------------------------------------------
# Comparison properties
# --------------------------------------------------------------------------


def test_compare_properties_hold_over_the_whole_decision_space(loaded):
    policy = loaded.hooks.priority_policy
    decisions = []
    for call_type in loaded.profile.call_types:
        request = SessionRequest(
            request_id="c", initiator="sip:a@example", target="t",
            call_type=call_type.id,
            media=tuple(MediaKind(m) for m in call_type.media))
        decisions.append(policy.evaluate(request, any_resolution()))

    sign = lambda n: (n > 0) - (n < 0)  # noqa: E731
    for a in decisions:
        assert policy.compare(a, a) == 0
        for b in decisions:
            assert sign(policy.compare(a, b)) == -sign(policy.compare(b, a))
            for c in decisions:
                if policy.compare(a, b) > 0 and policy.compare(b, c) > 0:
                    assert policy.compare(a, c) > 0


def test_compare_returns_zero_across_scopes(loaded):
    """Checked against every other profile in the image, not only this one."""
    policy = loaded.hooks.priority_policy
    mine = policy.evaluate(
        SessionRequest(request_id="c", initiator="sip:a@example", target="t",
                       call_type=loaded.profile.call_types[0].id,
                       media=(MediaKind.VOICE,)),
        any_resolution())

    for other_dir in sorted(PROFILES.glob("*/profile.yaml")):
        other = loader.load(other_dir.parent)
        if other.profile.name == loaded.profile.name:
            continue
        theirs = other.hooks.priority_policy.evaluate(
            SessionRequest(request_id="c", initiator="sip:b@example", target="t",
                           call_type=other.profile.call_types[0].id,
                           media=(MediaKind.VOICE,)),
            any_resolution())
        if theirs.scope != mine.scope:
            assert policy.compare(mine, theirs) == 0
            assert policy.compare(theirs, mine) == 0


# --------------------------------------------------------------------------
# Reason codes and admission
# --------------------------------------------------------------------------


def test_declared_reason_codes_are_not_core_reserved(loaded):
    from core.errors import CORE_ORIGINATED
    declared = set(loaded.profile.admission.reject_reason_codes)
    assert declared
    assert not (declared & CORE_ORIGINATED)


def test_undeclared_call_type_is_refused(manager):
    mgr, sink = manager
    session, signals, refusal = mgr.establish(SessionRequest(
        request_id="x", initiator="sip:a@example", target="t",
        call_type="definitely-not-declared", media=(MediaKind.VOICE,)))
    assert session is None
    assert refusal is not None
    assert sink.of_type(RecordType.SESSION_ESTABLISHED) == []


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


def test_every_audit_record_carries_the_profile_identity(manager, loaded):
    mgr, sink = manager
    mgr.establish(SessionRequest(
        request_id="x", initiator="sip:a@example", target="t",
        call_type="definitely-not-declared", media=(MediaKind.VOICE,)))
    assert sink.records
    for record in sink.records:
        assert record.profile == loaded.profile.identifier()


def test_reserved_capacity_fits_within_the_maximum(loaded):
    admission = loaded.profile.admission
    assert sum(admission.reserved_for_urgency.values()) <= \
        admission.max_concurrent_sessions
