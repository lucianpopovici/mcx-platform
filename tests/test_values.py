"""Hook value types hold nothing mutable (VP1-BND-004, PLT-VP-R1 RES-OP-06).

`frozen=True` stops reassignment, not a change in place. These tests build
every value type with the caller's own dict and list, then try to change the
value through its fields and through the caller's originals.
"""

import dataclasses
import sys
from pathlib import Path
import copy
import json
import pickle

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import core.hooks as h  # noqa: E402

SCOPE = "public-safety"


def build(cls):
    """(instance, the caller's mutable arguments by field name) for `cls`,
    every Mapping and Sequence field given a fresh dict or list."""
    required = {
        h.Admission: dict(permitted=True, reason_code="ok"),
        h.BearerDecision: dict(qos_identifier=65, arp_level=1, arp_preemption_capability=False,
                               arp_preemption_vulnerability=True, redundancy="none"),
        h.FloorPolicy: dict(initial_grant_to_initiator=True, queueing_enabled=True,
                            override_allowed=False, max_queue_depth=4),
        h.InterworkingRoute: dict(system="tetra", gateway="gw"),
        h.LocationContext: dict(),
        h.PartnerRights: dict(scope=SCOPE),
        h.PartnerRoute: dict(partner_id="p", gateway="gw"),
        h.PathSpec: dict(path_id="a", transport="lte", primary=True),
        h.PriorityDecision: dict(level=1, scope=SCOPE, preemption_capability=True,
                                 preemption_vulnerability=False, floor_priority=1, label="x"),
        h.Resolution: dict(kind=h.ResolutionKind.USER),
        h.SessionDecision: dict(model=h.SessionModel.ON_DEMAND, auto_answer=False,
                                acknowledgement_required=False, recording_required=True),
        h.SessionRequest: dict(request_id="r", initiator="sip:a@mcptt.example",
                               target="t", call_type="c"),
    }[cls]
    given = {}
    for f in dataclasses.fields(cls):
        if "Mapping[" in str(f.type):
            given[f.name] = {"k": 1 if "int" in str(f.type) else "v"}
        elif "Sequence[" in str(f.type):
            item = {"paths": h.PathSpec("a", "lte", True),
                    "media": h.MediaKind.VOICE}.get(f.name, "sip:a@mcptt.example")
            given[f.name] = [item]
    return cls(**required, **given), given


VALUE_TYPES = sorted((c for c in vars(h).values()
                      if isinstance(c, type) and issubclass(c, h.Value) and c is not h.Value),
                     key=lambda c: c.__name__)


@pytest.mark.vp("VP1-BND-004")
def test_every_value_type_is_covered():
    assert {c.__name__ for c in VALUE_TYPES} == {
        "Admission", "BearerDecision", "FloorPolicy", "InterworkingRoute", "LocationContext",
        "PartnerRights", "PartnerRoute", "PathSpec", "PriorityDecision", "Resolution",
        "SessionDecision", "SessionRequest"}


@pytest.mark.vp("VP1-BND-004")
@pytest.mark.parametrize("cls", VALUE_TYPES, ids=lambda c: c.__name__)
def test_a_value_cannot_be_changed_in_place_or_through_the_callers_objects(cls):
    value, given = build(cls)
    before = dataclasses.astuple(value)
    for name, original in given.items():
        held = getattr(value, name)
        if isinstance(original, dict):
            assert isinstance(held, h.FrozenDict)
            for change in (lambda m: m.__setitem__("k", "changed"),
                           lambda m: m.__delitem__("k"), lambda m: m.update(k="changed"),
                           lambda m: m.pop("k"), lambda m: m.popitem(), lambda m: m.clear(),
                           lambda m: m.setdefault("new", "v"), lambda m: m.__ior__({"k": 0})):
                with pytest.raises(TypeError, match="read-only"):
                    change(held)                            # through the value
            assert held == {"k": original["k"]}
            original["k"] = "changed"                       # through the caller's dict
            original["new"] = "added"
            assert "new" not in held and held["k"] != "changed"
        else:
            assert isinstance(held, tuple)
            original.append(original[0])                    # through the caller's list
            assert len(held) == 1
    for f in dataclasses.fields(cls):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(value, f.name, None)
    assert dataclasses.astuple(value) == before


@pytest.mark.vp("VP1-BND-004")
@pytest.mark.parametrize("cls", VALUE_TYPES, ids=lambda c: c.__name__)
def test_a_frozen_value_still_serialises_copies_and_pickles(cls):
    """The side effect a read-only view would have had: asdict and deepcopy
    of a value holding one raise. Every value type still goes through them."""
    value, _ = build(cls)
    as_dict = dataclasses.asdict(value)
    json.dumps(as_dict, default=lambda o: o.value)            # enums by value
    assert copy.deepcopy(value) == value and copy.copy(value) == value
    assert pickle.loads(pickle.dumps(value)) == value
    for f in dataclasses.fields(cls):
        if "Mapping[" in str(f.type):
            assert isinstance(pickle.loads(pickle.dumps(value)).__dict__[f.name], h.FrozenDict)


@pytest.mark.vp("VP1-BND-004")
def test_replace_keeps_a_value_frozen():
    req, _ = build(h.SessionRequest)
    again = dataclasses.replace(req, attributes={"x": "1"}, participants=["sip:b@mcptt.example"])
    assert isinstance(again.attributes, h.FrozenDict)
    assert again.participants == ("sip:b@mcptt.example",)


@pytest.mark.vp("VP1-BND-004")
def test_a_string_is_not_taken_as_a_sequence_of_characters():
    with pytest.raises(TypeError, match="Resolution.members"):
        h.Resolution(kind=h.ResolutionKind.USER, members="sip:a@mcptt.example")
    with pytest.raises(TypeError, match="SessionRequest.media"):
        h.SessionRequest(request_id="r", initiator="i", target="t", call_type="c",
                         media=b"voice")


@pytest.mark.vp("VP1-BND-004")
@pytest.mark.parametrize("unordered", [{"sip:a@mcptt.example"}, frozenset({"x"}), {"k": "v"}])
def test_a_sequence_field_refuses_what_has_no_order(unordered):
    """RES-OP-06 review G4: a set would become an unindexable frozenset."""
    with pytest.raises(TypeError, match="ordered sequence"):
        h.Resolution(kind=h.ResolutionKind.GROUP, members=unordered, group_id="g")


@pytest.mark.vp("VP1-BND-004")
def test_a_sequence_field_takes_any_ordered_iterable_as_a_tuple():
    members = h.Resolution(kind=h.ResolutionKind.GROUP, group_id="g",
                           members=(f"sip:u{i}@mcptt.example" for i in range(2))).members
    assert members == ("sip:u0@mcptt.example", "sip:u1@mcptt.example")
    assert h.PartnerRights(scope=SCOPE, allowed_call_types={"a": 1}.keys()).allowed_call_types \
        == ("a",)
    assert h.SessionRequest(request_id="r", initiator="i", target="t", call_type="c",
                            media=range(0)).media == ()


@pytest.mark.vp("VP1-BND-004")
def test_freeze_trusts_only_a_value_that_really_is_frozen():
    """RES-OP-06 review G1: deriving from Value is not enough."""
    @dataclasses.dataclass
    class Loose(h.Value):
        d: int = 0

    @dataclasses.dataclass(frozen=True)
    class Overridden(h.Value):
        d: int = 0

        def __post_init__(self):
            pass

    for odd in (Loose(), Overridden()):
        with pytest.raises(TypeError, match="cannot hold"):
            h.freeze(odd)
        with pytest.raises(TypeError, match="cannot hold"):
            h.SessionRequest(request_id="r", initiator="i", target="t", call_type="c",
                             media=(), attributes={"x": odd})
    path = h.PathSpec("a", "lte", True)
    assert h.freeze(path) is path


def test_absent_optional_fields_stay_absent_and_defaults_are_frozen():
    loc = h.LocationContext()
    assert loc.attributes == {} and isinstance(loc.attributes, h.FrozenDict)
    assert h.PartnerRights(scope=SCOPE).allowed_call_types == ()


@pytest.mark.vp("VP1-BND-004")
def test_nothing_mutable_survives_at_any_depth():
    """RES-OP-06 review F2: freezing goes by the value, not the annotation,
    and reaches inside."""
    req = h.SessionRequest(request_id="r", initiator="i", target="t", call_type="c",
                           media=[h.MediaKind.VOICE],
                           attributes={"n": {"d": [1, {2}]}, "b": bytearray(b"x")})
    inner = req.attributes["n"]
    assert isinstance(inner, h.FrozenDict) and inner["d"] == (1, frozenset({2}))
    assert req.attributes["b"] == b"x"
    with pytest.raises(TypeError):
        inner["d"] = ()


@pytest.mark.vp("VP1-BND-004")
def test_a_field_declared_in_any_spelling_is_frozen():
    import typing

    @dataclasses.dataclass(frozen=True)
    class Probe(h.Value):
        a: typing.Optional[typing.Mapping[str, str]] = None
        b: "typing.Mapping[str, str]" = None
        c: typing.Iterable[str] = ()
        d: typing.Optional[typing.Sequence[str]] = None
    p = Probe(a={"x": "1"}, b={"y": "2"}, c=["z"], d=["w"])
    assert isinstance(p.a, h.FrozenDict) and isinstance(p.b, h.FrozenDict)
    assert p.c == ("z",) and p.d == ("w",)
    assert Probe().a is None and Probe().d is None          # absent stays absent


@pytest.mark.vp("VP1-BND-004")
@pytest.mark.parametrize("given,frozen", [
    ({"a": [1]}, h.FrozenDict({"a": (1,)})), ([1, [2]], (1, (2,))), ({1, 2}, frozenset({1, 2})),
    (bytearray(b"ab"), b"ab"), ("s", "s"), (3, 3), (None, None),
    (h.MediaKind.VOICE, h.MediaKind.VOICE),
])
def test_freeze(given, frozen):
    assert h.freeze(given) == frozen and type(h.freeze(given)) is type(frozen)


@pytest.mark.vp("VP1-BND-004")
@pytest.mark.parametrize("odd", [object(), [object()], {"k": object()}, lambda: 1,
                                 {object()}])
def test_freeze_refuses_what_it_cannot_prove_immutable(odd):
    with pytest.raises(TypeError, match="cannot hold"):
        h.freeze(odd)


@pytest.mark.vp("VP1-BND-004")
def test_a_frozendict_cannot_be_refilled_through_init():
    fd = h.FrozenDict({"k": 1})
    fd.__init__({"x": 2})
    assert fd == {"k": 1}
    made = h.FrozenDict.fromkeys(["a", "b"], 0)
    assert made == {"a": 0, "b": 0} and isinstance(made, h.FrozenDict)


@pytest.mark.vp("VP1-BND-004")
def test_a_frozendict_hashes_by_its_items_and_copies_as_itself():
    fd = h.FrozenDict({"a": 1, "b": (2,)})
    assert hash(fd) == hash(frozenset({("a", 1), ("b", (2,))}))
    assert hash(fd) != hash(h.FrozenDict({"a": 2, "b": (2,)}))
    for c in (copy.copy(fd), copy.deepcopy(fd)):
        assert c == fd and isinstance(c, h.FrozenDict)
        with pytest.raises(TypeError):
            c["a"] = 3


@pytest.mark.vp("VP1-BND-004")
def test_the_gateway_gets_a_read_only_copy_of_what_the_core_holds():
    """RES-OP-06 review F4: receive_inbound's mapping crosses the boundary as
    an argument, not in a value type."""
    from core import loader
    from core.audit import Auditor, MemorySink
    from core.session import SessionManager
    mcx = loader.load(ROOT / "profiles" / "mcx")
    seen = []

    class Gateway:
        def route(self, request, resolution):
            return None

        def map_outbound(self, request, route):
            return {}

        def map_inbound(self, foreign):
            seen.append(foreign)
            foreign["initiator"] = "sip:someone-else@mcptt.example"   # must fail

    hooks = dataclasses.replace(mcx.hooks, interworking_gateway=Gateway())
    lp = dataclasses.replace(mcx, hooks=hooks)
    mgr = SessionManager(lp, Auditor(MemorySink(), mcx.profile.identifier()))
    foreign = {"request_id": "x1", "initiator": "sip:a@mcptt.example", "target": "t",
               "call_type": "private"}
    session, _, refusal = mgr.receive_inbound(foreign)
    assert session is None and refusal.reason_code == "hook-error"
    assert foreign["initiator"] == "sip:a@mcptt.example"
    assert seen and dict(seen[0]) == foreign
