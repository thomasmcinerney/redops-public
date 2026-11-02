"""Callback-as-verification + trust-derivation tests. No server, no privilege —
isolates via a throwaway REDOPS_DATA, same pattern as test_netsensor.py, so it
runs under `uv run python scripts/test_verification.py` or pytest.

Covers the invariants the feature exists to hold:
  - confidence is DERIVED from verification events, never left as typed
  - a callback (inbound flow) cited as proof moves a claim to live-verified
  - a service-banner change expires proof taken against the old fingerprint and
    demotes the finding (the live-network analogue of lab build drift)
  - a flow can be cited at most once per finding
  - the pending-callback queue is a queue, not an inference (no auto-attach)
  - every engagement-scoped table is purged (regression guard for `flows`)
"""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="redops-verif-")
os.environ["REDOPS_DATA"] = _TMP

from redops import db  # noqa: E402

_OPEN = []

try:
    import pytest

    @pytest.fixture(autouse=True)
    def _close_conns():
        yield
        while _OPEN:
            _OPEN.pop().close()
except ImportError:
    pass


def _fixture():
    db.use_data_dir(_TMP)
    db.init_db()
    c = db.connect()
    _OPEN.append(c)
    eng = db.insert(c, "engagements", {"name": "T", "scope": "10.0.0.0/24", "created_at": db.now()})
    c.commit()
    tid = db.insert(c, "targets", {"engagement_id": eng, "ip": "10.0.0.5"})
    c.commit()
    db.upsert_service(c, tid, 443, "tcp", {"name": "https", "product": "nginx", "version": "1.24"})
    fid = db.insert(c, "findings", {"engagement_id": eng, "target_id": tid,
                                    "title": "RCE via upload", "severity": "high",
                                    "created_at": db.now()})
    c.commit()
    return c, eng, tid, fid


def _callback_flow(c, eng, tid, dport=4444, opened=1):
    """A witnessed, established inbound callback (opened=1) unless told otherwise."""
    fl = db.insert(c, "flows", {"engagement_id": eng, "src": "10.0.0.5", "dst": "10.0.0.9",
                                "dport": dport, "proto": "tcp", "direction": "in",
                                "state": "established", "target_id": tid, "opened": opened,
                                "first_seen": db.now(), "last_seen": db.now(),
                                "packets": 5, "bytes": 200})
    c.commit()
    return fl


def test_confidence_starts_claimed():
    c, eng, tid, fid = _fixture()
    assert db.recompute_finding_trust(c, fid)["confidence"] == "claimed"


def test_callback_moves_to_live_verified():
    c, eng, tid, fid = _fixture()
    fl = _callback_flow(c, eng, tid)
    v = db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
    assert v["confidence"] == "live-verified" and not v["stale"]


def test_banner_change_demotes_and_stales():
    c, eng, tid, fid = _fixture()
    fl = _callback_flow(c, eng, tid)
    db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
    db.upsert_service(c, tid, 443, "tcp", {"version": "1.27"})   # surface moved
    moved = db.refresh_target_staleness(c, tid)
    assert fid in moved
    row = db.row(c, "SELECT confidence, stale FROM findings WHERE id=?", (fid,))
    assert row["confidence"] == "observed" and row["stale"] == 1


def test_flow_cited_once_per_finding():
    c, eng, tid, fid = _fixture()
    import sqlite3
    fl = _callback_flow(c, eng, tid)
    db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
    try:
        db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
        raise AssertionError("second cite of the same flow should be refused")
    except sqlite3.IntegrityError:
        pass


def test_pending_queue_does_not_auto_attach():
    c, eng, tid, fid = _fixture()
    fl = _callback_flow(c, eng, tid)
    pend = db.pending_callbacks(c, eng)
    assert len(pend) == 1
    # one open finding on the target -> suggested, but NOT auto-cited
    assert pend[0]["suggested_finding_id"] == fid
    assert db.recompute_finding_trust(c, fid)["verifications"] == 0
    # once cited, it leaves the queue
    db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
    assert db.pending_callbacks(c, eng) == []


def test_two_findings_no_suggestion():
    c, eng, tid, fid = _fixture()
    db.insert(c, "findings", {"engagement_id": eng, "target_id": tid, "title": "second",
                              "severity": "low", "created_at": db.now()})
    c.commit()
    _callback_flow(c, eng, tid)
    # ambiguous -> the queue refuses to guess
    assert db.pending_callbacks(c, eng)[0]["suggested_finding_id"] is None


def test_not_reproduced_stays_observed_not_claimed():
    c, eng, tid, fid = _fixture()
    fl = _callback_flow(c, eng, tid)
    v = db.add_verification(c, fid, "not-reproduced", method="callback", flow_id=fl)
    # a fired-and-died test is evidence too — it must not read as never-tested
    assert v["confidence"] == "observed" and v["contested"]


def test_bad_result_rejected():
    c, eng, tid, fid = _fixture()
    try:
        db.add_verification(c, fid, "worked", method="manual")
        raise AssertionError("invalid result should be refused")
    except ValueError:
        pass


# --- regression guards for the bugs Kimi's review found ---------------------

def test_B1_callback_requires_flow():
    """method='callback' with no flow_id must be refused — else 'callback' is a
    magic word that grants live-verified with nothing behind it."""
    c, eng, tid, fid = _fixture()
    try:
        db.add_verification(c, fid, "reproduced", method="callback")
        raise AssertionError("callback without flow_id should be refused")
    except ValueError as e:
        assert "flow_id" in str(e)


def test_B2_latest_negative_demotes():
    """A later not-reproduced must override an earlier reproduced. Trust is
    latest-wins, not any-success-ever-wins."""
    c, eng, tid, fid = _fixture()
    db.add_verification(c, fid, "reproduced", method="manual")
    v = db.add_verification(c, fid, "not-reproduced", method="manual")
    assert v["confidence"] == "observed" and v["contested"]


def test_B2_recovery_restores():
    """...and a fresh reproduced after a failure recovers live-verified."""
    c, eng, tid, fid = _fixture()
    db.add_verification(c, fid, "not-reproduced", method="manual")
    v = db.add_verification(c, fid, "reproduced", method="manual")
    assert v["confidence"] == "live-verified" and not v["contested"]


def test_B4_additive_port_does_not_stale():
    """Discovering a NEW port must not stale proof taken against an unchanged
    one — better scan coverage is not target drift."""
    c, eng, tid, fid = _fixture()
    db.add_verification(c, fid, "reproduced", method="manual")
    db.upsert_service(c, tid, 22, "tcp", {"name": "ssh", "product": "openssh", "version": "9.0"})
    assert db.refresh_target_staleness(c, tid) == []
    assert db.row(c, "SELECT confidence FROM findings WHERE id=?", (fid,))["confidence"] == "live-verified"


def test_B5_service_death_stales():
    """A port going open->closed IS drift — proof against a live service should
    not survive the service dying."""
    c, eng, tid, fid = _fixture()
    db.add_verification(c, fid, "reproduced", method="manual")
    db.upsert_service(c, tid, 443, "tcp", {"state": "closed", "name": "https",
                                           "product": "nginx", "version": "1.24"})
    assert fid in db.refresh_target_staleness(c, tid)


def test_B6_cross_target_flow_rejected():
    """A callback attributed to host A cannot prove a finding on host B."""
    c, eng, tid, fid = _fixture()
    t2 = db.insert(c, "targets", {"engagement_id": eng, "ip": "10.0.0.6"})
    c.commit()
    f2 = db.insert(c, "findings", {"engagement_id": eng, "target_id": t2, "title": "on .6",
                                   "severity": "high", "created_at": db.now()})
    c.commit()
    fl = _callback_flow(c, eng, tid)      # flow attributed to tid (.5)
    try:
        db.add_verification(c, f2, "reproduced", method="callback", flow_id=fl)
        raise AssertionError("cross-target callback should be refused")
    except ValueError as e:
        assert "different host" in str(e)


def test_B6_flow_proves_one_finding():
    """One flow cannot be spread across findings to manufacture N live-verifieds."""
    c, eng, tid, fid = _fixture()
    f2 = db.insert(c, "findings", {"engagement_id": eng, "target_id": tid, "title": "second",
                                   "severity": "high", "created_at": db.now()})
    c.commit()
    fl = _callback_flow(c, eng, tid)
    db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
    try:
        db.add_verification(c, f2, "reproduced", method="callback", flow_id=fl)
        raise AssertionError("same flow on a second finding should be refused")
    except Exception as e:
        assert "IntegrityError" in type(e).__name__


def test_B7_non_established_flow_rejected():
    """A lone inbound SYN / refused / closed flow is not proof an effect fired."""
    c, eng, tid, fid = _fixture()
    fl = db.insert(c, "flows", {"engagement_id": eng, "src": "10.0.0.5", "dst": "10.0.0.9",
                                "dport": 4444, "proto": "tcp", "direction": "in", "state": "syn",
                                "target_id": tid, "first_seen": db.now(), "last_seen": db.now(),
                                "packets": 1, "bytes": 0})
    c.commit()
    try:
        db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
        raise AssertionError("non-established callback should be refused")
    except ValueError as e:
        assert "established" in str(e)


def test_B8_unwitnessed_callback_rejected():
    """A flow picked up mid-stream (opened=0) may be our own outbound's return
    leg mislabelled inbound — it must not be citable as callback proof."""
    c, eng, tid, fid = _fixture()
    fl = _callback_flow(c, eng, tid, opened=0)
    try:
        db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
        raise AssertionError("unwitnessed (opened=0) callback should be refused")
    except ValueError as e:
        assert "not witnessed" in str(e)


def test_B8_witnessed_open_marked():
    """netsensor must mark opened=1 when it sees the remote's SYN open an inbound
    flow, and opened=0 when the first packet is already established."""
    from redops import netsensor
    c, eng, tid, fid = _fixture()
    local = {"10.0.0.9"}
    # remote opens a connection to us: lone SYN from remote -> witnessed
    netsensor.ingest_lines(["1.0 IP 10.0.0.5.4444 > 10.0.0.9.9001: Flags [S], length 0"],
                           eng, local)
    w = db.row(c, "SELECT opened, direction FROM flows WHERE dport=9001")
    assert w["direction"] == "in" and w["opened"] == 1
    # we join a connection mid-stream: first packet already push+ack -> not witnessed
    netsensor.ingest_lines(["1.0 IP 10.0.0.5.4445 > 10.0.0.9.9002: Flags [P.], length 20"],
                           eng, local)
    m = db.row(c, "SELECT opened FROM flows WHERE dport=9002")
    assert m["opened"] == 0


def test_B9_errored_is_not_evidence():
    """An errored run (the test did not execute) must not move trust off claimed."""
    c, eng, tid, fid = _fixture()
    v = db.add_verification(c, fid, "errored", method="manual")
    assert v["confidence"] == "claimed"


# --- second-pass guards: drift driven through the REAL nmap persist path -----
# Kimi's N1/N2 were invisible to hand-built rows; these go through
# _parse_nmap_xml + _persist_results, the path a queued -sV actually takes.

def _nmap_xml(path, ports, scanned=None, extraports=None):
    """Minimal nmap XML. `ports` = [(port, state, product, version)]. `scanned` =
    the port set scaninfo claims to have covered (defaults to the listed ports).
    `extraports` = (state, count) bulk collapse, e.g. ('closed', 998)."""
    rows_ = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="{st}"/>'
        f'<service name="https" product="{prod}" version="{ver}"/></port>'
        for (p, st, prod, ver) in ports)
    scanned = scanned if scanned is not None else [p for (p, *_r) in ports]
    services = ",".join(str(p) for p in scanned)
    extra = (f'<extraports state="{extraports[0]}" count="{extraports[1]}"/>'
             if extraports else "")
    open(path, "w").write(
        f'<?xml version="1.0"?><nmaprun>'
        f'<scaninfo type="syn" protocol="tcp" services="{services}"/>'
        f'<host><status state="up"/><ports>{extra}{rows_}</ports></host></nmaprun>')


def _rescan(c, eng, tid, ip, ports, scanned=None, extraports=None):
    from redops import tools
    xml = os.path.join(os.environ["REDOPS_DATA"], f"scan_{ports[0][0]}_{ports[0][1]}.xml")
    _nmap_xml(xml, ports, scanned=list(scanned) if scanned is not None else None,
              extraports=extraports)
    parsed = tools._parse_nmap_xml(xml)
    rid = db.insert(c, "tool_runs", {"engagement_id": eng, "target_id": tid, "tool": "nmap",
                                     "command": "nmap -sV", "status": "done", "started_at": db.now()})
    c.commit()
    tools._persist_results(c, eng, tid, ip, parsed, "", "done", rid, "user", "nmap")
    return parsed


def test_N1_sv_learning_banner_does_not_stale():
    """Register a port BARE, verify, then a -sV that LEARNS the banner. The proof
    must survive — we only learned detail, the service did not change."""
    c, eng, tid, fid = _fixture()
    # override the fixture's fully-specified service with a bare one
    c.execute("DELETE FROM services WHERE target_id=?", (tid,)); c.commit()
    db.upsert_service(c, tid, 443, "tcp", {"name": "https"})   # bare: no product/version
    db.add_verification(c, fid, "reproduced", method="manual")
    _rescan(c, eng, tid, "10.0.0.5", [(443, "open", "nginx", "1.24")])   # -sV fills it in
    assert db.row(c, "SELECT confidence FROM findings WHERE id=?", (fid,))["confidence"] == "live-verified"


def test_N2_dead_service_stales_via_scan():
    """A -sV that finds a previously-open port now CLOSED must stale proof taken
    against it — through the scanner path, not a hand-written state='closed'."""
    c, eng, tid, fid = _fixture()   # fixture registers 443 nginx/1.24
    db.add_verification(c, fid, "reproduced", method="manual")
    assert db.row(c, "SELECT confidence FROM findings WHERE id=?", (fid,))["confidence"] == "live-verified"
    _rescan(c, eng, tid, "10.0.0.5", [(443, "closed", "", "")])   # service died
    row = db.row(c, "SELECT confidence, stale FROM findings WHERE id=?", (fid,))
    assert row["confidence"] == "observed" and row["stale"] == 1


def test_N3_closed_flow_does_not_absorb_callback():
    """A reverse shell from a port we earlier touched (T.443 -> our ephemeral port)
    must NOT fold into the now-closed outbound row — it is a new inbound flow."""
    from redops import netsensor
    c, eng, tid, fid = _fixture()
    local = {"10.0.0.9"}
    # we connect out to T:443, then it tears down (closed)
    netsensor.ingest_lines([
        "1.0 IP 10.0.0.9.50000 > 10.0.0.5.443: Flags [S], length 0",
        "2.0 IP 10.0.0.5.443 > 10.0.0.9.50000: Flags [S.], length 0",
        "3.0 IP 10.0.0.9.50000 > 10.0.0.5.443: Flags [F.], length 0",
        "4.0 IP 10.0.0.5.443 > 10.0.0.9.50000: Flags [R.], length 0",
    ], eng, local)
    # later: target opens a NEW connection back from :443 to our old ephemeral port
    netsensor.ingest_lines([
        "5.0 IP 10.0.0.5.443 > 10.0.0.9.50000: Flags [S], length 0",
        "6.0 IP 10.0.0.9.50000 > 10.0.0.5.443: Flags [S.], length 0",
    ], eng, local)
    c2 = db.connect(); _OPEN.append(c2)      # fresh snapshot: ingest committed on its own conn
    inbound = db.rows(c2, "SELECT * FROM flows WHERE engagement_id=? AND direction='in' "
                      "AND state='established'", (eng,))
    assert len(inbound) == 1 and inbound[0]["opened"] == 1


def test_N2_parse_distinguishes_closed_filtered_scanned():
    """_parse_nmap_xml records open ports, per-port nonopen states, and the scanned
    coverage — the inputs death-detection needs."""
    from redops import tools
    xml = os.path.join(os.environ["REDOPS_DATA"], "mix.xml")
    _nmap_xml(xml, [(80, "open", "nginx", "1.24"), (443, "closed", "", ""), (22, "filtered", "", "")])
    parsed = tools._parse_nmap_xml(xml)
    assert [p["port"] for p in parsed["ports"]] == [80]
    assert parsed["nonopen"] == {("tcp", 443): "closed", ("tcp", 22): "filtered"}
    assert {("tcp", 80), ("tcp", 443), ("tcp", 22)} <= parsed["scanned"]


def test_N2_cross_protocol_no_false_close():
    """A TCP scan reporting a port closed must NOT close a live UDP service on the
    same port number — the dangerous data-corruption direction."""
    from redops import tools
    c, eng, tid, fid = _fixture()
    db.upsert_service(c, tid, 53, "udp", {"name": "dns", "product": "dnsmasq"})   # live UDP/53
    xml = os.path.join(os.environ["REDOPS_DATA"], "tcp_scan.xml")
    # TCP scan: 53/tcp closed (no TCP listener), 80/tcp open — says nothing re UDP
    open(xml, "w").write(
        '<?xml version="1.0"?><nmaprun>'
        '<scaninfo type="connect" protocol="tcp" services="53,80"/>'
        '<host><status state="up"/><ports>'
        '<port protocol="tcp" portid="53"><state state="closed"/></port>'
        '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
        '</ports></host></nmaprun>')
    parsed = tools._parse_nmap_xml(xml)
    rid = db.insert(c, "tool_runs", {"engagement_id": eng, "target_id": tid, "tool": "nmap",
                                     "command": "-sT", "status": "done", "started_at": db.now()})
    c.commit()
    tools._persist_results(c, eng, tid, "10.0.0.5", parsed, "", "done", rid, "user", "nmap")
    assert db.row(c, "SELECT state FROM services WHERE target_id=? AND port=53 AND proto='udp'",
                  (tid,))["state"] == "open"


def test_H2_status_vocabulary_enforced_and_flagged():
    """Finding status is a closed vocabulary, and a status that CLAIMS proof
    (confirmed/exploited) while confidence isn't live-verified is flagged in the
    report — closing the free-text 'proven'/'root' escape hatch."""
    from redops import export
    assert "root" not in db.FINDING_STATUSES and "confirmed" in db.FINDING_STATUSES
    assert "confirmed" in db.STATUS_ASSERTS_PROOF
    c, eng, tid, fid = _fixture()
    # operator asserts 'confirmed' but there is NO verification -> report must flag it
    c.execute("UPDATE findings SET status='confirmed' WHERE id=?", (fid,)); c.commit()
    line = " ".join(export._finding_trust(c, db.row(c, "SELECT * FROM findings WHERE id=?", (fid,))))
    assert "CLAIMED" in line and "not backed by a live verification" in line


def test_N2_default_scan_extraports_death_detected():
    """A death collapsed into <extraports state='closed'> on a DEFAULT scan (no
    per-port element) is still detected via scaninfo coverage — this was the
    common-case miss."""
    c, eng, tid, fid = _fixture()   # fixture registers 443 open, verified below
    db.add_verification(c, fid, "reproduced", method="manual")
    # a broad scan that covers 443 but reports it only inside extraports closed
    _rescan(c, eng, tid, "10.0.0.5", [(80, "open", "nginx", "1.24")],
            scanned=range(1, 1001), extraports=("closed", 998))
    row = db.row(c, "SELECT confidence, stale FROM findings WHERE id=?", (fid,))
    assert row["confidence"] == "observed" and row["stale"] == 1


def test_R1_reused_tuple_reconnect_no_crash():
    """A NEW connection reusing a closed 4-tuple (retried/repeat reverse shell)
    must not throw the flows UNIQUE index and kill the capture thread — the dead
    row is resurrected into a fresh connection."""
    from redops import netsensor
    c, eng, tid, fid = _fixture()
    local = {"10.0.0.9"}
    seq1 = ["1 IP 10.0.0.5.443 > 10.0.0.9.4444: Flags [S], length 0",
            "2 IP 10.0.0.9.4444 > 10.0.0.5.443: Flags [S.], length 0",
            "3 IP 10.0.0.5.443 > 10.0.0.9.4444: Flags [F.], length 0",
            "4 IP 10.0.0.9.4444 > 10.0.0.5.443: Flags [R.], length 0"]
    netsensor.ingest_lines(seq1, eng, local)
    # identical tuple again — pre-fix this threw IntegrityError
    netsensor.ingest_lines(["5 IP 10.0.0.5.443 > 10.0.0.9.4444: Flags [S], length 0",
                            "6 IP 10.0.0.9.4444 > 10.0.0.5.443: Flags [S.], length 0"], eng, local)
    c2 = db.connect(); _OPEN.append(c2)
    rows_ = db.rows(c2, "SELECT * FROM flows WHERE engagement_id=? AND src='10.0.0.5' "
                    "AND dst='10.0.0.9' AND dport=4444", (eng,))
    assert len(rows_) == 1 and rows_[0]["state"] == "established" and rows_[0]["opened"] == 1


def test_A_inbound_syn_not_swallowed_by_outbound():
    """A lone inbound SYN sourced from a port matching a live outbound connection
    (reverse shell from :443, blend-in tradecraft) must surface as its own witnessed
    callback, NOT fold into the outbound flow and vanish."""
    from redops import netsensor
    c, eng, tid, fid = _fixture()
    local = {"10.0.0.9"}
    # live outbound you:50000 -> target:443
    netsensor.ingest_lines([
        "1 IP 10.0.0.9.50000 > 10.0.0.5.443: Flags [S], length 0",
        "2 IP 10.0.0.5.443 > 10.0.0.9.50000: Flags [S.], length 0",
        "3 IP 10.0.0.9.50000 > 10.0.0.5.443: Flags [P.], length 50",
    ], eng, local)
    # genuine inbound SYN on the reverse tuple — must NOT fold into the outbound row
    rec = netsensor.ingest_lines(
        ["4 IP 10.0.0.5.443 > 10.0.0.9.50000: Flags [S], length 0"], eng, local)
    assert rec and rec[0]["direction"] == "in", "inbound SYN was swallowed by the outbound flow"
    c2 = db.connect(); _OPEN.append(c2)
    ins = db.rows(c2, "SELECT * FROM flows WHERE engagement_id=? AND direction='in'", (eng,))
    assert len(ins) == 1 and ins[0]["opened"] == 1


def test_E_resurrect_keeps_endpoints_matching_direction():
    """Resurrection happens only on the exact reused tuple, so a resurrected row's
    stored src/dst never contradict its direction."""
    from redops import netsensor
    c, eng, tid, fid = _fixture()
    local = {"10.0.0.9"}
    # inbound callback opens, then tears down (closed)
    netsensor.ingest_lines([
        "1 IP 10.0.0.5.443 > 10.0.0.9.4444: Flags [S], length 0",
        "2 IP 10.0.0.9.4444 > 10.0.0.5.443: Flags [S.], length 0",
        "3 IP 10.0.0.5.443 > 10.0.0.9.4444: Flags [R.], length 0",
    ], eng, local)
    # same tuple reconnects -> resurrect
    netsensor.ingest_lines(["4 IP 10.0.0.5.443 > 10.0.0.9.4444: Flags [S], length 0"], eng, local)
    c2 = db.connect(); _OPEN.append(c2)
    r = db.row(c2, "SELECT * FROM flows WHERE engagement_id=? AND dport=4444", (eng,))
    # direction 'in' means src is the remote (target), not us
    assert r["direction"] == "in" and r["src"] == "10.0.0.5" and r["opened"] == 1


def test_staleness_heals_when_service_returns():
    """A demoted finding must RECOVER if a later scan shows the surface back —
    staleness is derived live, not a one-way latch (the flaky-filtered problem)."""
    c, eng, tid, fid = _fixture()
    db.add_verification(c, fid, "reproduced", method="manual")
    # service dies -> demoted
    db.upsert_service(c, tid, 443, "tcp", {"state": "closed", "name": "https",
                                           "product": "nginx", "version": "1.24"})
    db.refresh_target_staleness(c, tid)
    assert db.row(c, "SELECT confidence FROM findings WHERE id=?", (fid,))["confidence"] == "observed"
    # service comes back with the SAME banner -> should heal to live-verified
    db.upsert_service(c, tid, 443, "tcp", {"state": "open", "name": "https",
                                           "product": "nginx", "version": "1.24"})
    db.refresh_target_staleness(c, tid)
    assert db.row(c, "SELECT confidence FROM findings WHERE id=?", (fid,))["confidence"] == "live-verified"


def test_purge_completeness():
    """Every engagement-scoped table must be purged — either directly via
    _ENG_DIRECT or through a special-case delete in _purge_engagement_data (some
    tables, e.g. credentials/services, are scoped through a parent). A new table
    that is handled by neither is exactly how `flows` leaked. Enumerate the
    schema and diff against both purge paths."""
    import inspect
    c, eng, tid, fid = _fixture()
    all_tables = {r["name"] for r in db.rows(
        c, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    scoped = {t for t in all_tables
              if "engagement_id" in {col[1] for col in c.execute(f"PRAGMA table_info({t})")}}
    purge_src = inspect.getsource(db._purge_engagement_data)
    # tolerate `FROM t ` and `FROM t\n` (multi-line deletes) so the guard doesn't
    # have its own blind spot
    import re as _re
    handled = set(db._ENG_DIRECT) | {t for t in scoped
                                     if _re.search(rf"\bFROM {t}\b", purge_src)}
    missing = scoped - handled - {"engagements"}
    assert not missing, f"engagement-scoped tables purged by nothing: {missing}"


def test_reset_removes_flows_and_verifications():
    c, eng, tid, fid = _fixture()
    fl = _callback_flow(c, eng, tid)
    db.add_verification(c, fid, "reproduced", method="callback", flow_id=fl)
    db.reset_engagement(c, eng)
    assert db.row(c, "SELECT COUNT(*) n FROM flows WHERE engagement_id=?", (eng,))["n"] == 0
    assert db.row(c, "SELECT COUNT(*) n FROM verifications WHERE engagement_id=?", (eng,))["n"] == 0


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {type(e).__name__}: {e}")
        finally:
            while _OPEN:                      # a leaked WAL write conn locks the next test
                _OPEN.pop().close()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
