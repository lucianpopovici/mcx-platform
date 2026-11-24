# ENV-E2E — the end-to-end harness

PLT-VP-R1 §2: the real process, the repository's own independent MC client,
and a packet capture with the TLS keys to read it.

```
sudo python3 tools/e2e/run.py --workdir /tmp/e2e --results e2e.json
python3 tools/vp_results.py --interop ... --e2e e2e.json
```

Needs `tcpdump` (and the right to capture on `lo`), `tshark` (Wireshark 4.x,
for its SIP and RTCP/MCPTT dissectors) and the `cryptography` package.

## What runs

`run.py` starts `python -m service` over TLS on loopback, starts tcpdump on
`lo`, and drives two clients (`mcclient.py`) through four scenarios:

| Scenario | Cases | What happens |
|---|---|---|
| private-manual | VP1-CC-003, VP1-SIG-003 | u1 calls u2; u2 rings, then answers |
| private-auto | VP1-CC-004 | the same on a copy of mcx whose private call type sets `auto_answer: true` (no shipped profile does); u2 answers at once on `Priv-Answer-Mode: Auto` |
| group-floor | VP1-FC-001, VP1-MED-001, exit criterion 6 | a prearranged group call between u1 and u2: initial grant, a queued request, a queue position request, a revoke after talking past T2, a deny while revoked, release with the queue granted, release to idle. u1 offers opus (declared by no profile), AMR-WB and PCMU, and sends one RTP packet in each besides AMR-WB |
| codec-refused | VP1-MED-002 | u1 offers opus alone |

## How it decides

`analyse.py` reads the capture, not the clients' memory:

- tshark decrypts SIP with the clients' key logs (`keys-NN.log`, one per
  client, and `keys-00-*.log` for the readiness probe, merged into `keys.log`)
  and every message is written to `sip-decrypted.txt`. "Every message" is
  checked: each encrypted TLS record on the SIP ports must decrypt and all
  application data must be SIP;
- `tags.py` checks every SIP message against the feature-tag table of
  TS 24.379, the service identifiers included (P-Preferred-Service from a
  client, P-Asserted-Service from the platform); a message it does not list
  fails (VP1-SIG-003);
- `flows.py` holds the expected private call flows (VP1-CC-003, -004); the
  callee's own answers are also checked against TS 24.379 6.2.3 (Require:
  timer, Session-Expires refresher=uas), so the client is shown conformant;
- tshark decodes the group call's floor control (its ports only: the private
  calls have floor streams too) with Wireshark's own MCPTT dissector: message
  names, directions, mandatory fields (VP1-FC-001); the floor packets are also
  written to `floor-trace.jsonl` and run through `tools/trace_compare.py`;
- RTP is read by payload type on every client and relay port (VP1-MED-001).

`decode()` turns the capture into plain data (`decoded.json`) and `judge()`
decides from that alone; tests/test_e2e_tools.py feeds `judge()` a recorded
run (tests/data/e2e/) and doctored copies of it.

The run records its commit and whether the tree was dirty; `tools/vp_results.py`
refuses a dirty run, so commit first. tcpdump's "listening on" is waited for,
and a tcpdump without the right to capture stops the run with what it said.
`judge()` also reports exit criterion 6, which the register shows.

Nothing in tools/e2e, tools/interop or tools/trace_compare.py imports `core`,
`service` or `profiles` (pinned by tests/test_e2e_tools.py).

Wireshark 4.2's Info column labels a Floor Revoke's cause from the Floor Deny
table (cause 2 reads "Internal floor control server error"); its decoded field
`rtcp.app_data.mcptt.rej_cause.floor_revoke` gives "Media burst too long", and
that field is what the check reads.

## Interop capture (SIP-OP-02)

`tools/interop/run.py --capture` does the same for the interoperability run:
the agents' TLS keys and a capture, with the platform's messages as the core
delivered them checked against `tags.py` (reported as OBSERVED steps). Through a
proxy, the platform's requests are those whose bottom Via is its own (sent-by
`mcptt.example`) and its responses those whose Contact is its identity; a B2BUA
writes its own messages, so none is the platform's and the report counts the
untagged ones. Records left undecrypted must be on connections no agent made.
