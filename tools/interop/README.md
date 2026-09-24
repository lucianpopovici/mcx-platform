# tools/interop — VP1-SIG-001

Runs the real platform process against a third-party SIP core over TLS on
loopback, and reports each step as PASS, FAIL or OBSERVED.

    python3 tools/interop/run.py --core kamailio   [--workdir DIR]
    python3 tools/interop/run.py --core asterisk   [--workdir DIR]

It needs the `kamailio` and `kamailio-tls-modules` packages, or `asterisk`.
With `--workdir`, the run's configuration, every process log and a
`transcript.txt` of every message both user agents sent and received are
kept there.

| File | What it is |
|---|---|
| `run.py` | Starts the platform from its environment alone (no `platform=` injection), starts the core, drives the scenario |
| `ua.py` | The user agents. They import nothing from `core/` or `service/`, so agreement with the platform means agreement about the specification rather than about shared code |
| `pki.py` | A throwaway CA and one certificate per party |
| `kamailio.cfg.in` | Kamailio as a registrar and record-routing proxy. The in-dialog handling follows Kamailio's default configuration, deliberately not relaxed |
| `asterisk/` | Asterisk as a B2BUA that registers each user onward to the platform |

The two cores need different scenarios. A proxy forwards the platform's own
messages. A B2BUA terminates each call and originates a new one, so its
originating path cannot carry the MC info body (PLT-VP-R1 SIP-OP-12). The
recorded results are in PLT-VP-R1 §7.1.1.
