"""Per-profile conformance suite (VP1-BND-021 / PLT-VER-001), at a release
(VP1-REL-002 / PLT-REL-003 / PLT-REL-007).

One suite, run once per profile against the SAME core: the shared part whose
hash is identical in every release image (VP1-BND-006, PLT-GEN-001). The
combination under test is named by `MCX_PROFILE` and `MCX_RELEASE`; CI runs
this file once per combination, every in-tree profile at every supported
release (the gate VP1-BND-020 checks the matrix). Left unset, as in a local
run, either axis covers all its values, so nothing is skipped silently.

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
ALL_PROFILES = sorted(p.parent.name for p in PROFILES.glob("*/profile.yaml"))
PROFILE_NAMES = [os.environ["MCX_PROFILE"]] if os.environ.get("MCX_PROFILE") \
    else ALL_PROFILES


def _releases():
    from core.release import SUPPORTED, parse
    raw = os.environ.get("MCX_RELEASE")
    if not raw:
        return list(SUPPORTED)
    try:
        return [parse(raw)]
    except Exception as exc:                   # noqa: BLE001 - reported, not skipped
        raise pytest.UsageError(f"MCX_RELEASE={raw!r}: {exc}") from exc


RELEASES = _releases()


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


@pytest.fixture(scope="module", params=PROFILE_NAMES)
def profile_name(request):
    return request.param


@pytest.fixture(scope="module", params=RELEASES, ids=str)
def release(request):
    return request.param


@pytest.fixture(scope="module")
def loaded(profile_name):
    directory = PROFILES / profile_name
    if not directory.is_dir():
        pytest.fail(f"MCX_PROFILE={profile_name!r} names no profile package")
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


def test_profile_loads(loaded, profile_name):
    assert loaded.profile.name == profile_name
    assert len(loaded.profile.content_hash) == 64


@pytest.mark.vp("VP1-BND-021")
def test_the_suite_runs_against_the_core_of_the_profiles_release_image(profile_name, tmp_path):
    """PLT-VER-001: the core this suite imports is the core its profile's
    release image carries (the same core hash, VP1-BND-006)."""
    import json
    import core
    sys.path.insert(0, str(ROOT / "tools"))
    import package
    tree = Path(core.__file__).resolve().parents[1]
    image = package.stage(profile_name, tmp_path, ROOT)
    manifest = json.loads((image / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["profile"] == profile_name
    assert len(manifest["core_hash"]) == 64
    assert package.core_hash(tree) == manifest["core_hash"]
    # The code that runs is the code hashed: nothing in core/ or service/
    # was replaced at run time (a conftest patching SessionManager, say).
    assert _replaced_at_run_time() == []


def _replaced_at_run_time():
    """What in the loaded core and service modules is not what their files
    say: a function, or one wrapped (partial, partialmethod, property,
    static or class method), on a module or its classes whose code was
    written elsewhere in this tree (a test, a conftest, a profile); and a
    module-level literal (`MAX = 256`, a dict, list or set included) whose
    value differs from the one its file assigns. Code or data put in at run time, which the core hash does
    not see."""
    import ast
    import copy
    import inspect
    platform = (str(ROOT / "core"), str(ROOT / "service"))

    def codes(v):
        for inner in (v, getattr(v, "__func__", None), getattr(v, "func", None),
                      getattr(v, "fget", None), getattr(v, "fset", None),
                      getattr(v, "fdel", None)):
            code = getattr(inner, "__code__", None)
            if code is not None:
                yield code.co_filename

    out = []
    for name, module in sorted(sys.modules.items()):
        if name.split(".")[0] not in ("core", "service") or module is None:
            continue
        for attr, value in list(vars(module).items()):
            owners = [(attr, value)]
            if inspect.isclass(value) and value.__module__ == name:
                owners += [(f"{attr}.{k}", v) for k, v in vars(value).items()]
            for where, v in owners:
                if any(f.startswith(str(ROOT)) and not f.startswith(platform) for f in codes(v)):
                    out.append(f"{name}.{where}")
        source = getattr(module, "__file__", None)
        if not source or not source.startswith(platform):
            continue
        tree = ast.parse(Path(source).read_text(encoding="utf-8"))
        assigned = {}                  # names the file binds to a literal so far

        def resolved(value):
            # A name bound to a literal earlier in the file reads as it.
            class Names(ast.NodeTransformer):
                def visit_Name(self, n):
                    if n.id in assigned:
                        return ast.copy_location(ast.Constant(assigned[n.id]), n)
                    return n
            return Names().visit(copy.deepcopy(value))
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                try:
                    written = ast.literal_eval(resolved(node.value))
                except (ValueError, SyntaxError, TypeError):
                    for t in targets:
                        if isinstance(t, ast.Name):
                            assigned.pop(t.id, None)
                    continue
                for t in targets:
                    if isinstance(t, ast.Name):
                        assigned[t.id] = written
                    if isinstance(t, ast.Name) and t.id in vars(module) and \
                            vars(module)[t.id] != written:
                        out.append(f"{name}.{t.id}")
    return out


@pytest.fixture(scope="session", autouse=True)
def _still_as_their_files_say():
    """The same check once every test has run: nothing in core/ or service/
    was replaced or changed by a test that ran after CORE_HASH_TEST."""
    yield
    assert _replaced_at_run_time() == []


def test_all_five_hooks_resolve(loaded):
    for field in ("identity_resolver", "priority_policy", "session_policy",
                  "bearer_selector", "interworking_gateway"):
        assert getattr(loaded.hooks, field) is not None


def test_identity_triple_is_well_formed(loaded):
    assert len(loaded.profile.identifier().split("/")) == 3
    assert all(loaded.profile.identifier().split("/"))


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


# --------------------------------------------------------------------------
# At the release (VP1-REL-002): what the release decides, for this profile
# --------------------------------------------------------------------------


def _invite_for(signature, target="sip:t@example"):
    """A conformant client's INVITE for `signature`, written by the
    independent fixture, not by core/mcinfo.py."""
    from core.sip import Headers, Request
    from tests import mcpttinfo_fixture as mcf
    adhoc = signature.session_type == "adhoc"
    xml = mcf.mcinfo_xml(signature.session_type, target,
                         emergency=signature.emergency and not adhoc,
                         imminent_peril=signature.imminent_peril,
                         adhoc_emergency=True if adhoc and signature.emergency else None)
    sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
    return Request("INVITE", "sip:server@example", Headers([
        ("From", "<sip:a@example>;tag=1"), ("To", "<sip:server@example>"),
        ("Call-ID", "conf-1"), ("CSeq", "1 INVITE"),
        ("Content-Type", mcf.CONTENT_TYPE)]), mcf.multipart(sdp, xml))


@pytest.mark.vp("VP1-REL-002")
def test_every_call_type_is_requestable_or_reported_unreachable(loaded, release):
    """PLT-REL-003: at this release, a call type with a signature is either
    one a conformant client can request -- its INVITE comes out as that call
    type -- or one the startup report names as unreachable (ICD-SIG-006).
    Never silently neither."""
    from core import mcinfo
    from core.sip import Adapter
    adapter = Adapter("sip:server@example", release, loaded.profile.call_types)
    undeclared, blocked = mcinfo.reachability(loaded.profile.call_types, release)
    blocked_ids = {ct for ct, _ in blocked}
    by_group = set(mcinfo.group_selected(loaded.profile.call_types))
    for ct in loaded.profile.call_types:
        if ct.mc_signature is None:
            assert ct.id in undeclared
            continue
        got = adapter.parse_invite(_invite_for(ct.mc_signature)).call_type
        if ct.id in by_group:
            # PRF-OP-01: never by its signature alone, and through a group
            # that names it, with that signature, whenever the release can.
            assert got != ct.id and ct.id not in undeclared, ct.id
            chooser = Adapter("sip:server@example", release, loaded.profile.call_types,
                              group_call_types={"grp:chooser": ct.id})
            got = chooser.parse_invite(_invite_for(ct.mc_signature, "grp:chooser")).call_type
        if ct.id in blocked_ids:
            assert got == "", (ct.id, str(release))
        else:
            assert got == ct.id, (ct.id, str(release))
        # Spelled out, not read from core/release.py: TS 24.379 has ad hoc
        # group calls and their emergency indication from Rel-18; every other
        # session type an in-tree profile uses is Rel-13.
        expected_blocked = ct.mc_signature.session_type == "adhoc" and int(release) < 18
        assert (ct.id in blocked_ids) is expected_blocked, (ct.id, str(release))


@pytest.mark.vp("VP1-REL-002")
def test_every_refusal_speaks_only_codes_the_release_defines(loaded, release):
    """PLT-REL-009 with this profile's own codes: whatever the profile may
    refuse with renders at this release, carrying only a warning code the
    release's table 4.4.2-2 defines."""
    import re
    from core.errors import RESERVED_REASON_CODES
    from core.release import supports_sip_warning
    from core.sip import Adapter, DialogContext
    adapter = Adapter("sip:server@example", release, loaded.profile.call_types)
    # Spelled out: warning 179 is Rel-17 onwards, 100 and 145 every release
    # (TS 24.379 table 4.4.2-2).
    assert supports_sip_warning(release, 100) and supports_sip_warning(release, 145)
    assert supports_sip_warning(release, 179) is (int(release) >= 17)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@example")
    for code in sorted(set(loaded.profile.admission.reject_reason_codes)
                       | set(RESERVED_REASON_CODES)):
        response = adapter.reject(code, ctx)
        assert 400 <= response.status.code < 700, code
        warning = response.headers.get("Warning")
        m = re.match(r'399 \S+ "(\d{3}) ', warning or "")
        if m:
            assert supports_sip_warning(release, int(m.group(1))), (code, str(release))


@pytest.mark.vp("VP1-REL-002")
def test_every_floor_message_the_policy_can_send_exists_at_the_release(loaded, release):
    """The floor messages, fields and causes this profile's floor policies can
    make the platform send are all defined at this release, and round-trip."""
    from core import rtcp
    from core.floor import DenyReason, RevokeReason
    from service.media import _DENY_CAUSE, _REVOKE_CAUSE
    M = rtcp.MsgType
    codec = rtcp.Codec(release)
    res = Resolution(kind=ResolutionKind.GROUP, members=("sip:x@example",), group_id="g")
    for ct in loaded.profile.call_types:
        if not ({"voice", "video"} & set(ct.media)):
            continue
        fp = loaded.hooks.session_policy.floor_policy(SessionRequest(
            request_id="f", initiator="sip:a@example", target="t",
            call_type=ct.id, media=(MediaKind.VOICE,)), res)
        messages = [rtcp.message(M.GRANTED, 1, rtcp.f_duration(30)),
                    rtcp.message(M.TAKEN, 1, rtcp.f_granted_party("sip:a@example")),
                    rtcp.message(M.IDLE, 1)]
        denies = [DenyReason.QUEUEING_DISABLED, DenyReason.LOWER_PRIORITY,
                  DenyReason.ALREADY_HOLDER, DenyReason.NO_SESSION]
        revokes = [RevokeReason.MEDIA_BURST_TOO_LONG, RevokeReason.OTHER]
        if fp.queueing_enabled:
            denies.append(DenyReason.QUEUE_FULL)
            messages.append(rtcp.message(M.QUEUE_POSITION_INFO, 1, rtcp.f_queue_info(1, 100)))
        if fp.override_allowed:
            revokes.append(RevokeReason.PREEMPTED)
        messages += [rtcp.message(M.DENY, 1, rtcp.f_reject(_DENY_CAUSE[d], d.value))
                     for d in denies]
        messages += [rtcp.message(M.REVOKE, 1, rtcp.f_reject(_REVOKE_CAUSE[r], r.value))
                     for r in revokes]
        for m in messages:
            assert codec.decode(codec.encode(m)) == m, (ct.id, m.type, str(release))
    # Spelled out: Floor Revoke cause 7 arrives in Rel-19 (TS 24.380
    # 8.2.10.2), so the codec this suite just used must refuse it before.
    revoke7 = rtcp.message(M.REVOKE, 1, rtcp.f_reject(7, "x"))
    if int(release) >= 19:
        assert codec.decode(codec.encode(revoke7)) == revoke7
    else:
        with pytest.raises(rtcp.ReleaseRefused):
            codec.encode(revoke7)


@pytest.mark.vp("VP1-REL-002")
def test_the_release_axis_changes_what_a_profile_can_carry():
    """Not a test per combination but of the matrix: across the in-tree
    profiles some call type is unreachable at one supported release and
    reachable at another, so running every release is not running one
    release eight times."""
    from core import mcinfo
    from core.release import SUPPORTED
    changes, adhoc = set(), set()
    for name in ALL_PROFILES:
        types = loader.load(PROFILES / name).profile.call_types
        if any(ct.mc_signature is not None and ct.mc_signature.session_type == "adhoc"
               for ct in types):
            adhoc.add(name)
        blocked = {r: {ct for ct, _ in mcinfo.reachability(types, r)[1]} for r in SUPPORTED}
        if len({frozenset(b) for b in blocked.values()}) > 1:
            changes.add(name)
            assert blocked[SUPPORTED[0]] and not blocked[SUPPORTED[-1]], name
    # Derived from the profiles, not named: the ones with an ad hoc call type
    # are the ones the release changes, and the tree has at least one.
    assert changes and changes == adhoc, (changes, adhoc)
