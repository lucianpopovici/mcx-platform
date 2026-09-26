"""core/codec.py: the call's codec and each party's payload type
(PLT-MED-001/002; PLT-VP-R1 VP1-MED-002, VP-OP-03, MED-OP-01).

The decided set (2026-09-25), in preference order, for every profile:
EVS, AMR-WB, AMR, G.722, PCMA, PCMU. No transcoding (R4).
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import codec  # noqa: E402
from core.codec import Choice, Offered, audio_payloads, choose, key_of, match  # noqa: E402

DECIDED = ("EVS/16000", "AMR-WB/16000", "AMR/8000", "G722/8000",
           "PCMA/8000", "PCMU/8000")


def sdp(*payloads, extra_m=None):
    """payloads: (pt, rtpmap or None, fmtp or None)."""
    lines = ["v=0", "o=- 0 0 IN IP4 192.0.2.1", "s=-", "c=IN IP4 192.0.2.1",
             "t=0 0",
             "m=audio 4000 RTP/AVP " + " ".join(str(p[0]) for p in payloads)]
    for pt, name, fmtp in payloads:
        if name:
            lines.append(f"a=rtpmap:{pt} {name}")
        if fmtp:
            lines.append(f"a=fmtp:{pt} {fmtp}")
    if extra_m:
        lines += extra_m
    return "\r\n".join(lines) + "\r\n"


# -- the protocol tables, pinned against their sources ----------------------

def test_static_payload_types_are_rfc_3551_table_4():
    assert dict(codec.STATIC_PAYLOAD_TYPES) == {
        0: "PCMU/8000", 8: "PCMA/8000", 9: "G722/8000"}


def test_must_match_parameters_and_defaults():
    amr = {"octet-align": "0", "crc": "0", "robust-sorting": "0", "interleaving": ""}
    assert dict(codec.MUST_MATCH["AMR"]) == amr          # RFC 4867 8.3.1
    assert dict(codec.MUST_MATCH["AMR-WB"]) == amr
    assert dict(codec.MUST_MATCH["EVS"]) == {"hf-only": "0", "evs-mode-switch": "0"}
    assert set(codec.MUST_MATCH) == {"AMR", "AMR-WB", "EVS"}


def test_key_of_compares_names_without_case_and_defaults_channels():
    assert key_of("amr-wb/16000") == ("AMR-WB", 16000, 1)
    assert key_of("AMR-WB/16000/1") == ("AMR-WB", 16000, 1)
    assert key_of("AMR/8000/2") == ("AMR", 8000, 2)


@pytest.mark.parametrize("name,ok", [
    ("EVS/16000", True), ("AMR/8000/1", True), ("telephone-event/8000", True),
    ("AMR", False), ("AMR/x", False), ("AMR WB/16000", False), ("", False)])
def test_name_pattern(name, ok):
    assert bool(codec.NAME.match(name)) is ok


# -- reading an offer --------------------------------------------------------

def test_audio_payloads_in_offer_order_with_fmtp():
    got = audio_payloads(sdp((97, "AMR-WB/16000", "mode-set=0,1,2"),
                             (8, None, None), (0, "PCMU/8000", None)))
    assert got == [Offered(97, "AMR-WB/16000", "mode-set=0,1,2"),
                   Offered(8, "PCMA/8000", ""), Offered(0, "PCMU/8000", "")]


def test_a_static_type_takes_its_rtpmap_when_one_is_given():
    assert audio_payloads(sdp((9, "G722/8000", None))) == [Offered(9, "G722/8000", "")]


def test_a_dynamic_type_without_rtpmap_names_no_codec():
    assert audio_payloads(sdp((96, None, None), (8, None, None))) == [
        Offered(8, "PCMA/8000", "")]


def test_an_unknown_static_type_names_no_codec():
    assert audio_payloads(sdp((18, None, None))) == []


def test_only_the_first_audio_line_counts():
    got = audio_payloads(sdp((0, None, None), extra_m=[
        "m=application 4001 udp MCPTT",
        "m=audio 4002 RTP/AVP 8", "a=rtpmap:96 EVS/16000"]))
    assert got == [Offered(0, "PCMU/8000", "")]


def test_attributes_after_the_audio_line_are_not_its():
    """An rtpmap under a later m-line redefines nothing on the audio line."""
    got = audio_payloads(sdp((97, "AMR-WB/16000", "mode-set=2"), extra_m=[
        "m=application 4001 udp MCPTT", "a=rtpmap:97 EVS/16000", "a=fmtp:97 hf-only=1"]))
    assert got == [Offered(97, "AMR-WB/16000", "mode-set=2")]


def test_an_rtpmap_redefining_a_static_number_is_the_sdps_word():
    assert audio_payloads(sdp((0, "AMR/8000", None))) == [Offered(0, "AMR/8000", "")]
    assert choose(sdp((0, "AMR/8000", None)), DECIDED).name == "AMR/8000"


@pytest.mark.parametrize("text,pt", [
    ("0", 0), ("127", 127), ("097", 97), ("128", None), ("300", None), ("-1", None),
    ("²", None), ("١", None), ("", None), ("0127", None), ("9x", None)])
def test_payload_type_is_7_bits_of_ascii_digits(text, pt):
    assert codec.payload_type(text) == pt


def test_numbers_rtp_cannot_carry_are_left_out():
    body = sdp((300, "AMR-WB/16000", None), (128, "AMR-WB/16000", None),
               (8, None, None))
    assert audio_payloads(body) == [Offered(8, "PCMA/8000", "")]
    assert audio_payloads(body.replace("RTP/AVP 300", "RTP/AVP ²")) == [
        Offered(8, "PCMA/8000", "")]


@pytest.mark.parametrize("parts,ok", [
    (["audio", "4000", "RTP/AVP", "0"], True),
    (["audio", "4000", "RTP/AVP"], False),                 # no format
    (["audio", "x", "RTP/AVP", "0"], False),
    (["audio", "²", "RTP/AVP", "0"], False),
    (["video", "4000", "RTP/AVP", "0"], False),
])
def test_is_audio_line(parts, ok):
    assert codec.is_audio_line(parts) is ok


def test_a_malformed_audio_line_is_skipped_as_parse_sdp_skips_it():
    """The codec and the address come from the same line (review F5)."""
    from core.sip import parse_sdp
    body = ("v=0\r\nc=IN IP4 192.0.2.1\r\n"
            "m=audio x RTP/AVP 97\r\nc=IN IP4 203.0.113.9\r\na=rtpmap:97 EVS/16000\r\n"
            "m=audio 4000 RTP/AVP 0\r\nc=IN IP4 192.0.2.5\r\n")
    assert audio_payloads(body) == [Offered(0, "PCMU/8000", "")]
    info = parse_sdp(body)
    assert (info.address, info.audio_port, info.payload_types) == ("192.0.2.5", 4000, (0,))


def test_parse_sdp_takes_the_address_of_the_audio_line_only():
    from core.sip import parse_sdp
    body = ("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n"
            "m=audio 4002 RTP/AVP 8\r\nc=IN IP4 203.0.113.9\r\n")
    assert parse_sdp(body).address == "192.0.2.1"            # the session's


def test_attributes_before_the_audio_line_are_not_its():
    body = ("v=0\r\nc=IN IP4 192.0.2.1\r\nm=application 4001 udp MCPTT\r\n"
            "a=rtpmap:96 EVS/16000\r\nm=audio 4000 RTP/AVP 96 0\r\n")
    assert audio_payloads(body) == [Offered(0, "PCMU/8000", "")]


def test_no_audio_line_no_payloads():
    assert audio_payloads("v=0\r\nm=application 4001 udp MCPTT\r\n") == []


def test_params_and_layout():
    o = Offered(97, "AMR-WB/16000", " Octet-Align=1; mode-set=0,2 ;crc=0")
    assert o.params() == {"octet-align": "1", "mode-set": "0,2", "crc": "0"}
    assert o.layout() == (("crc", "0"), ("interleaving", ""),
                          ("octet-align", "1"), ("robust-sorting", "0"))
    assert Offered(0, "PCMU/8000").layout() == ()
    assert Offered(96, "EVS/16000", "hf-only=1").layout() == (
        ("evs-mode-switch", "0"), ("hf-only", "1"))


# -- choosing the call's codec -----------------------------------------------

def test_the_profile_order_wins_over_the_offer_order():
    offer = sdp((0, None, None), (8, None, None), (97, "AMR-WB/16000", None),
                (96, "EVS/16000", None))
    c = choose(offer, DECIDED)
    assert c == Choice("EVS/16000", Offered(96, "EVS/16000", ""))


@pytest.mark.parametrize("payloads,name,pt", [
    ([(97, "AMR-WB/16000", None), (96, "AMR/8000", None)], "AMR-WB/16000", 97),
    ([(96, "AMR/8000", None), (0, None, None)], "AMR/8000", 96),
    ([(0, None, None), (9, None, None), (8, None, None)], "G722/8000", 9),
    ([(0, None, None), (8, None, None)], "PCMA/8000", 8),
    ([(0, None, None)], "PCMU/8000", 0),
])
def test_each_decided_codec_is_chosen_in_its_turn(payloads, name, pt):
    c = choose(sdp(*payloads), DECIDED)
    assert (c.name, c.offered.pt) == (name, pt)


def test_vp1_med_002_nothing_declared_in_the_offer_is_no_codec():
    assert choose(sdp((18, None, None), (111, "opus/48000/2", None)), DECIDED) is None
    assert choose(sdp((0, None, None)), ("AMR-WB/16000",)) is None


def test_names_match_without_case():
    c = choose(sdp((97, "amr-wb/16000", None)), DECIDED)
    assert c.name == "AMR-WB/16000" and c.offered.name == "amr-wb/16000"


def test_the_clock_rate_is_part_of_the_codec():
    assert choose(sdp((97, "AMR-WB/8000", None)), ("AMR-WB/16000",)) is None


def test_ts_26_179_the_bandwidth_efficient_layout_wins():
    offer = sdp((97, "AMR-WB/16000", "octet-align=1"),
                (98, "AMR-WB/16000", "mode-set=0,1,2"))
    c = choose(offer, DECIDED)
    assert c.offered == Offered(98, "AMR-WB/16000", "mode-set=0,1,2")
    offer = sdp((96, "AMR/8000", "octet-align=1"), (95, "AMR/8000", "octet-align=0"))
    assert choose(offer, DECIDED).offered.pt == 95


def test_octet_aligned_only_is_still_chosen():
    offer = sdp((97, "AMR-WB/16000", "octet-align=1"), (0, None, None))
    assert choose(offer, DECIDED).offered == Offered(97, "AMR-WB/16000", "octet-align=1")


def test_among_equal_variants_the_callers_first():
    offer = sdp((0, None, None), (100, "PCMU/8000", None))
    assert choose(offer, DECIDED).offered.pt == 0
    offer = sdp((96, "EVS/16000", "hf-only=1"), (97, "EVS/16000", None))
    assert choose(offer, DECIDED).offered.pt == 96


# -- matching an answer (or a later offer) to the call's codec ---------------

AMRWB = choose(sdp((97, "AMR-WB/16000", "mode-set=0,1,2")), DECIDED)


def test_match_returns_the_partys_own_payload_type():
    assert match(sdp((101, "AMR-WB/16000", None)), AMRWB) == 101


def test_match_ignores_parameters_that_do_not_change_the_payload():
    assert match(sdp((101, "AMR-WB/16000", "mode-set=2; mode-change-period=2")),
                 AMRWB) == 101


def test_explicit_defaults_match_absent_ones():
    assert match(sdp((101, "AMR-WB/16000",
                      "octet-align=0;crc=0;robust-sorting=0")), AMRWB) == 101


@pytest.mark.parametrize("fmtp", ["octet-align=1", "crc=1", "robust-sorting=1",
                                  "interleaving=4"])
def test_rfc_4867_a_different_layout_does_not_match(fmtp):
    assert match(sdp((101, "AMR-WB/16000", fmtp)), AMRWB) is None


def test_a_different_channel_count_does_not_match():
    assert match(sdp((101, "AMR-WB/16000/2", None)), AMRWB) is None
    assert match(sdp((101, "AMR-WB/16000/1", None)), AMRWB) == 101


def test_another_codec_does_not_match():
    assert match(sdp((96, "AMR/8000", None), (0, None, None)), AMRWB) is None


def test_the_first_matching_variant_is_used():
    body = sdp((100, "AMR-WB/16000", "octet-align=1"), (101, "AMR-WB/16000", None),
               (102, "AMR-WB/16000", None))
    assert match(body, AMRWB) == 101


@pytest.mark.parametrize("fmtp", ["hf-only=1", "evs-mode-switch=1"])
def test_evs_layout_parameters_must_match(fmtp):
    evs = choose(sdp((96, "EVS/16000", None)), DECIDED)
    assert match(sdp((110, "EVS/16000", fmtp)), evs) is None
    assert match(sdp((110, "EVS/16000", "br=13.2")), evs) == 110


def test_static_codecs_match_by_number_or_rtpmap():
    pcma = choose(sdp((8, None, None)), DECIDED)
    assert match(sdp((8, None, None)), pcma) == 8
    assert match(sdp((0, None, None)), pcma) is None
    g722 = choose(sdp((9, "G722/8000", None)), DECIDED)
    assert match(sdp((9, None, None)), g722) == 9


def test_parse_sdp_ignores_a_floor_port_of_non_ascii_digits():
    from core.sip import parse_sdp
    body = ("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n"
            "m=application \u00b2 udp MCPTT\r\n")
    assert parse_sdp(body).floor_port is None
