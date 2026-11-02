"""Slice 1 smoke test: tcpdump-line parsing + flow storage, no privilege, no
live capture. Runs against a throwaway DB so it never touches real engagement
data. Usage: uv run python scripts/test_netsensor.py
"""
import os
import tempfile

# isolate the DB before importing db
_tmp = tempfile.mkdtemp(prefix="redops-netsensor-")
os.environ["REDOPS_DATA"] = _tmp

from redops import db, netsensor  # noqa: E402


def _ok(cond, msg):
    print(("  ok  " if cond else " FAIL ") + msg)
    assert cond, msg


def test_parser():
    cases = [
        # (line, expected src, sport, dst, dport, proto)
        ("1687891234.123456 IP 10.10.14.5.54321 > 10.10.10.5.80: Flags [S], seq 0, length 0",
         "10.10.14.5", 54321, "10.10.10.5", 80, "tcp"),
        ("1687891234.223456 IP 10.10.10.5.80 > 10.10.14.5.54321: tcp 120",
         "10.10.10.5", 80, "10.10.14.5", 54321, "tcp"),
        ("1687891235.000000 IP 10.10.10.5 > 10.10.14.5: ICMP echo reply, id 1, seq 1, length 64",
         "10.10.10.5", None, "10.10.14.5", None, "icmp"),
        ("1687891236.000000 IP 10.10.14.5.53 > 10.10.10.5.53: UDP, length 40",
         "10.10.14.5", 53, "10.10.10.5", 53, "udp"),
        ("1687891237.000000 IP6 fe80::1.546 > fe80::2.547: UDP, length 20",
         "fe80::1", 546, "fe80::2", 547, "udp"),
    ]
    for line, s, sp, d, dp, pr in cases:
        f = netsensor.parse_line(line)
        _ok(f is not None, f"parse: {line[:50]}")
        _ok((f["src"], f["sport"], f["dst"], f["dport"], f["proto"]) == (s, sp, d, dp, pr),
            f"fields {f['src']}:{f['sport']} -> {f['dst']}:{f['dport']} {f['proto']}")
    _ok(netsensor.parse_line("12:00:00.0 ARP, Request who-has 10.0.0.1") is None,
        "non-IP line ignored")
    _ok(netsensor.parse_line("") is None, "blank line ignored")


def test_bytes():
    f = netsensor.parse_line("1.0 IP 10.0.0.1.80 > 10.0.0.2.5555: tcp 512")
    _ok(f["bytes"] == 512, "byte count from -q form")
    f = netsensor.parse_line("1.0 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, length 64")
    _ok(f["bytes"] == 64, "byte count from length field")


def test_storage_and_direction():
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "T", "scope": "10.10.10.0/24", "created_at": db.now()})
    db.set_state(conn, "active_engagement", str(eng))
    # a known target so the flow attributes to it
    tid = db.insert(conn, "targets", {"engagement_id": eng, "ip": "10.10.10.5"})
    conn.close()

    local = {"10.10.14.5"}
    lines = [
        "1.0 IP 10.10.14.5.54321 > 10.10.10.5.80: Flags [S], length 0",     # outbound
        "2.0 IP 10.10.14.5.54321 > 10.10.10.5.80: tcp 200",                 # same flow again
        "3.0 IP 10.10.10.5 > 10.10.14.5: ICMP echo reply, length 64",       # callback
    ]
    new = netsensor.ingest_lines(lines, eng, local)
    _ok(len(new) == 2, f"2 distinct flows (dupe collapsed), got {len(new)}")

    conn = db.connect()
    flows = db.rows(conn, "SELECT * FROM flows WHERE engagement_id=? ORDER BY id", (eng,))
    _ok(len(flows) == 2, "2 rows persisted")
    out = flows[0]
    _ok(out["direction"] == "out" and out["packets"] == 2,
        f"outbound flow coalesced: dir={out['direction']} packets={out['packets']}")
    _ok(out["target_id"] == tid, "outbound flow attributed to target 10.10.10.5")
    cb = flows[1]
    _ok(cb["direction"] == "in", "ICMP reply classified as callback (in)")
    _ok(cb["target_id"] == tid, "callback attributed to the target that called back")

    # the callback should have raised a distinct 'callback' event
    evs = db.rows(conn, "SELECT * FROM events WHERE engagement_id=? AND kind='callback'", (eng,))
    _ok(len(evs) == 1, "callback event emitted")
    flowevs = db.rows(conn, "SELECT * FROM events WHERE engagement_id=? AND kind='flow'", (eng,))
    _ok(len(flowevs) == 1, "outbound flow event emitted once")
    conn.close()


def test_connection_lifecycle():
    """A TCP connection: SYN (open) -> data (established) -> FIN (drop). The drop
    must surface as a close event so the board can show the connection dying."""
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "L", "scope": "10.10.10.0/24", "created_at": db.now()})
    db.set_state(conn, "active_engagement", str(eng))
    db.insert(conn, "targets", {"engagement_id": eng, "ip": "10.10.10.9"})
    conn.close()
    local = {"10.10.14.5"}
    # flags derivation
    _ok(netsensor.state_from_flags("S", "tcp") == "syn", "[S] -> syn")
    _ok(netsensor.state_from_flags("S.", "tcp") == "established", "[S.] -> established")
    _ok(netsensor.state_from_flags("F.", "tcp") == "closing", "[F.] -> closing")
    _ok(netsensor.state_from_flags("R", "tcp") == "reset", "[R] -> reset")
    _ok(netsensor.state_from_flags("", "udp") == "active", "udp -> active")

    syn = netsensor.ingest_lines(
        ["1.0 IP 10.10.14.5.55000 > 10.10.10.9.22: Flags [S], length 0"], eng, local)
    _ok(len(syn) == 1 and syn[0]["event"] == "open" and syn[0]["state"] == "syn",
        "SYN opens the flow in state=syn")
    # a data segment promotes it to established, no new event
    est = netsensor.ingest_lines(
        ["2.0 IP 10.10.10.9.22 > 10.10.14.5.55000: Flags [P.], length 40"], eng, local)
    # (this is a different direction/flow key; check the original established via a data pkt on same key)
    est2 = netsensor.ingest_lines(
        ["2.1 IP 10.10.14.5.55000 > 10.10.10.9.22: Flags [.], length 0"], eng, local)
    _ok(est2 == [], "data packet on a live flow emits no new event")
    conn = db.connect()
    f = db.row(conn, "SELECT state FROM flows WHERE src='10.10.14.5' AND dport=22", ())
    _ok(f["state"] == "established", f"flow promoted to established (got {f['state']})")
    conn.close()
    # FIN tears it down -> a close event
    fin = netsensor.ingest_lines(
        ["3.0 IP 10.10.14.5.55000 > 10.10.10.9.22: Flags [F.], length 0"], eng, local)
    _ok(len(fin) == 1 and fin[0]["event"] == "close", "FIN produces a close event")
    conn = db.connect()
    f = db.row(conn, "SELECT state FROM flows WHERE src='10.10.14.5' AND dport=22", ())
    _ok(f["state"] == "closed", "flow marked closed")
    ce = db.rows(conn, "SELECT * FROM events WHERE engagement_id=? AND kind='flowclose'", (eng,))
    _ok(len(ce) == 1, "flowclose event emitted for the drop")
    conn.close()
    # a closed port answering a scan: SYN then RST -> a *refused* close (the probe
    # never reached established). This is what makes closed-port hits visible.
    netsensor.ingest_lines(
        ["4.0 IP 10.10.14.5.55100 > 10.10.10.9.9999: Flags [S], length 0"], eng, local)
    ref = netsensor.ingest_lines(
        ["4.1 IP 10.10.10.9.9999 > 10.10.14.5.55100: Flags [R.], length 0"], eng, local)
    _ok(len(ref) == 1 and ref[0]["event"] == "close", "RST closes the probe")
    _ok(ref[0].get("refused") is True and ref[0].get("reset") is True,
        "closed port -> refused + reset (never established)")


def test_r13_callback_opportunity():
    """An unsolicited inbound connection (a callback) auto-surfaces as an R13
    vector on the worklist — the wire-state -> intel bridge."""
    from redops import correlate  # noqa: F401
    db.init_db()
    conn = db.connect()
    eng = db.insert(conn, "engagements",
                    {"name": "C", "scope": "10.0.0.0/8", "created_at": db.now()})
    db.set_state(conn, "active_engagement", str(eng))
    db.insert(conn, "targets", {"engagement_id": eng, "ip": "10.10.10.7"})
    conn.close()
    # a reverse shell: the target opens a connection back to us on 4444
    netsensor.ingest_lines(
        ["1 IP 10.10.10.7.4444 > 10.10.14.5.51000: Flags [S], length 0"],
        eng, {"10.10.14.5"})
    conn = db.connect()
    opps = db.rows(conn, "SELECT * FROM opportunities WHERE engagement_id=? AND rule='R13'", (eng,))
    _ok(len(opps) == 1, f"R13 vector auto-created for the callback (got {len(opps)})")
    _ok("callback" in (opps[0]["title"] or "").lower(), "vector titled as a callback")
    # re-ingesting the same callback must not duplicate the vector
    netsensor.ingest_lines(
        ["2 IP 10.10.10.7.4444 > 10.10.14.5.51000: Flags [.], length 0"], eng, {"10.10.14.5"})
    opps2 = db.rows(conn, "SELECT * FROM opportunities WHERE engagement_id=? AND rule='R13'", (eng,))
    _ok(len(opps2) == 1, "same callback does not duplicate the vector")
    conn.close()


def test_bpf():
    _ok(netsensor.build_bpf(["10.10.10.0/24", "10.10.11.5"], set())
        == "(net 10.10.10.0/24 or host 10.10.11.5)", "bpf from mixed scope")
    _ok(netsensor.build_bpf([], set()) == "ip", "empty scope -> all ip")


if __name__ == "__main__":
    print("parser:");        test_parser()
    print("bytes:");         test_bytes()
    print("storage:");       test_storage_and_direction()
    print("lifecycle:");     test_connection_lifecycle()
    print("r13 callback:");  test_r13_callback_opportunity()
    print("bpf:");           test_bpf()
    print("\nall passed.")
