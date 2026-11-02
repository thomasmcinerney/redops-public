"""Live connectivity sensor — observed edges, not inferred ones.

The scope map's beams today are *inferred*: a host lights up when any event is
attributed to it (heat), and cross-host links come from correlation near-misses.
This sensor makes edges *observed*: it tails `tcpdump` and upserts one row per
(src, dst, dport, proto) flow it actually sees on the wire.

Vantage point: tcpdump runs on the operator box, so it sees your box <-> targets
plus **callbacks** (target -> you: reverse shells, exfil, the ICMP side effect
from an xp_cmdshell-style blind command). It does NOT see target <-> target
internal traffic. Callbacks are the high-signal case — they are ground truth
that an effect fired, the exact out-of-band confirmation the AI labs demand.

Slice 1 (this file) is the parser + storage, driven either by a live tcpdump
subprocess or, for tests, by any iterable of tcpdump text lines — so the whole
thing is exercisable without privilege or a live capture.

Privilege: on Linux/Kali, `setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)`
once — then no sudo, no prompt. (Running as root needs nothing.)
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import threading
from typing import Iterable

from . import db

# `IP` / `IP6` <src-endpoint> > <dst-endpoint>: <rest>
_LINE = re.compile(r"\bIP6?\s+(\S+)\s+>\s+(\S+):\s*(.*)$")
_LEN = re.compile(r"\blength (\d+)")
_QLEN = re.compile(r"\b(?:tcp|udp) (\d+)\b", re.I)
_FLAGS = re.compile(r"Flags \[([^\]]*)\]")


def _split_endpoint(ep: str) -> tuple[str, int | None]:
    """`10.0.0.5.443` -> ('10.0.0.5', 443); `10.0.0.5` -> ('10.0.0.5', None);
    `fe80::1.546` -> ('fe80::1', 546). tcpdump renders the port as a trailing
    `.port`, so an IPv4 address+port is five dot-parts and a bare address four."""
    if ":" in ep:  # IPv6 — port (if any) is after the last dot
        if "." in ep:
            host, _, port = ep.rpartition(".")
            return (host, int(port)) if port.isdigit() else (ep, None)
        return ep, None
    parts = ep.split(".")
    if len(parts) == 5 and parts[4].isdigit():  # a.b.c.d.port
        return ".".join(parts[:4]), int(parts[4])
    return ep, None


def _proto(rest: str) -> str:
    low = rest.lower()
    if "icmp" in low:
        return "icmp"
    if low.startswith("udp"):
        return "udp"
    if low.startswith("tcp") or "flags" in low:
        return "tcp"
    head = low.split(",")[0].split()[0] if low.strip() else "ip"
    return re.sub(r"[^a-z0-9]", "", head) or "ip"


def parse_line(line: str) -> dict | None:
    """One tcpdump line -> {src, sport, dst, dport, proto, bytes}, or None for
    lines that aren't a parseable IP packet (ARP, listener banners, blanks)."""
    m = _LINE.search(line)
    if not m:
        return None
    src, dst, rest = m.group(1), m.group(2), m.group(3)
    shost, sport = _split_endpoint(src)
    dhost, dport = _split_endpoint(dst)
    if not shost or not dhost:
        return None
    lm = _LEN.search(rest) or _QLEN.search(rest)
    fm = _FLAGS.search(rest)
    return {"src": shost, "sport": sport, "dst": dhost, "dport": dport,
            "proto": _proto(rest), "bytes": int(lm.group(1)) if lm else 0,
            "flags": fm.group(1) if fm else ""}


# TCP connection lifecycle read off the flags tcpdump prints (needs non-`-q`
# capture). SYN alone = an attempt; SYN|ACK ([S.]) = the handshake completing;
# FIN/RST = teardown (the "connection dropped" the operator wants to see). UDP /
# ICMP are stateless — treated as momentary 'active'.
def state_from_flags(flags: str, proto: str) -> str:
    if proto != "tcp":
        return "active"
    if "R" in flags:
        return "reset"
    if "F" in flags:
        return "closing"
    if "S" in flags and "." in flags:
        return "established"
    if "S" in flags:
        return "syn"
    return "established"  # a bare ACK / data segment ([.] or [P.]) on a live conn


def classify(flow: dict, local_ips: set[str]) -> str:
    """Direction relative to the operator box: out (you->target),
    in (a callback, target->you), or transit (neither endpoint is ours)."""
    if flow["src"] in local_ips:
        return "out"
    if flow["dst"] in local_ips:
        return "in"
    return "transit"


def _target_id(conn, engagement_id, ip: str):
    r = db.row(conn, "SELECT id FROM targets WHERE engagement_id=? AND ip=?",
               (engagement_id, ip))
    return r["id"] if r else None


def record_flow(conn, engagement_id, flow: dict, local_ips: set[str]) -> dict | None:
    """Upsert a flow and advance its connection state. Returns a record with
    `event`='open' on first sight, `event`='close' when a live connection tears
    down (FIN/RST) — so callers can beam it or animate the drop — or None for a
    packet that merely refreshes an already-known flow."""
    direction = classify(flow, local_ips)
    # attribute the edge to the non-operator host (the target we care about)
    remote = flow["dst"] if direction == "out" else flow["src"]
    tid = _target_id(conn, engagement_id, remote)
    ts = db.now()
    st = state_from_flags(flow.get("flags", ""), flow["proto"])

    # A SYN-bearing packet (bare SYN or SYN-ACK) OPENS a connection.
    opening = "S" in flow.get("flags", "")

    def find(src, dst, dport, live_only=False):
        q = ("SELECT id, state, direction FROM flows WHERE engagement_id=? AND src=? "
             "AND dst=? AND ((dport IS NULL AND ? IS NULL) OR dport=?) AND proto=?")
        if live_only:
            q += " AND state!='closed'"
        # a LIVE row is the continuation; a closed one only matches teardown
        # remnants — prefer live so data/FIN never lands on a stale dead row.
        q += " ORDER BY (state='closed') ASC, id DESC LIMIT 1"
        return db.row(conn, q, (engagement_id, src, dst, dport, dport, flow["proto"]))

    # A connection is bidirectional: this packet may be the reverse leg of a flow
    # we already track (the server's replies to our own outbound socket). Fold it
    # into that LIVE row rather than minting a phantom mirror — otherwise our own
    # return traffic masquerades as an unsolicited inbound "callback". We fold only
    # into a LIVE flow (either direction); a closed row is a finished connection
    # and never continues.
    # The forward tuple is a continuation of a same-direction flow (a retransmit).
    # The reverse tuple is the REPLY leg of an existing connection — but a lone SYN
    # (st='syn') is never a reply: it OPENS a connection. So a bare inbound SYN must
    # not reverse-fold into your outbound flow, or a reverse shell sourced from a
    # port that coincides with your outbound (T:443 -> you, standard blend-in
    # tradecraft) gets silently swallowed with no event and no citable row. A
    # SYN-ACK ([S.], st='established') IS a reply and still folds correctly.
    existing = find(flow["src"], flow["dst"], flow["dport"], live_only=True)
    if not existing and st != "syn":
        existing = find(flow["dst"], flow["src"], flow["sport"], live_only=True)

    if existing:
        conn_dir = existing["direction"]                # the initiator's direction
        tearing = st in ("closing", "reset")
        new_state = "closed" if tearing else ("established" if st == "established" else existing["state"])
        conn.execute(
            "UPDATE flows SET last_seen=?, packets=packets+1, bytes=bytes+?, "
            "state=?, target_id=COALESCE(target_id, ?) WHERE id=?",
            (ts, flow["bytes"], new_state, tid, existing["id"]))
        conn.commit()
        if tearing and existing["state"] != "closed":
            return {"id": existing["id"], "engagement_id": engagement_id, "direction": conn_dir,
                    "src": flow["src"], "dst": flow["dst"], "dport": flow["dport"],
                    "proto": flow["proto"], "target_id": tid, "remote": remote,
                    "state": "closed", "event": "close",
                    # 'refused' = a probe that never completed the handshake before the
                    # RST/FIN (a closed port answering a scan), vs a real live drop.
                    "refused": existing["state"] != "established",
                    "reset": st == "reset"}
        return None

    def rec(event, fid, state):
        return {"id": fid, "engagement_id": engagement_id, "direction": direction,
                "src": flow["src"], "dst": flow["dst"], "dport": flow["dport"],
                "proto": flow["proto"], "target_id": tid, "remote": remote,
                "state": state, "event": event}

    # No LIVE flow to fold into. What we do next depends on whether this packet
    # opens a connection:
    #
    #  - A non-opening packet (data/FIN/RST) with no live flow but a CLOSED row on
    #    its tuple is a last-gasp remnant of that finished connection — ignore it,
    #    exactly as before.
    #  - A non-opening packet with no flow at all is a mid-stream pickup — insert
    #    it (opened=0: we did not witness the open).
    #  - An OPENING packet whose tuple already holds a CLOSED row is a genuine NEW
    #    connection reusing the 4-tuple (a retried/repeat reverse shell). It cannot
    #    INSERT — the (eng,src,dst,dport,proto) unique index would throw and take
    #    the capture thread down — so RESURRECT the dead row into a fresh
    #    connection instead.
    # A witnessed open: an inbound flow whose first packet is the remote's lone SYN
    # (we watched them initiate TO us). Only that is trustworthy callback proof — a
    # mid-stream pickup may be our own outbound's return leg mislabelled inbound.
    opened = 1 if (direction == "in" and st == "syn") else 0
    dead_fwd = find(flow["src"], flow["dst"], flow["dport"])          # exact tuple
    dead_rev = find(flow["dst"], flow["src"], flow["sport"])          # reverse tuple
    if not opening and (dead_fwd or dead_rev):
        return None                                     # teardown remnant of a closed flow
    if opening and dead_fwd:
        # a NEW connection reusing the EXACT 4-tuple (a retried/repeat reverse
        # shell): INSERT would throw the (eng,src,dst,dport,proto) unique index and
        # take the capture thread down, so resurrect the dead row in place. Only the
        # exact-tuple case can collide; a reverse-tuple dead row is a different key
        # and is left alone (inserting the new flow below is correct and keeps the
        # row's endpoints matching its direction).
        conn.execute(
            "UPDATE flows SET direction=?, state=?, opened=?, target_id=?, "
            "packets=1, bytes=?, first_seen=?, last_seen=?, sport=? WHERE id=?",
            (direction, st, opened, tid, flow["bytes"], ts, ts, flow["sport"], dead_fwd["id"]))
        conn.commit()
        return rec("open", dead_fwd["id"], st)
    rid = db.insert(conn, "flows", {
        "engagement_id": engagement_id, "src": flow["src"], "sport": flow["sport"],
        "dst": flow["dst"], "dport": flow["dport"], "proto": flow["proto"],
        "direction": direction, "target_id": tid, "state": st, "opened": opened,
        "first_seen": ts, "last_seen": ts, "packets": 1, "bytes": flow["bytes"]})
    return rec("open", rid, st)


def _flow_event_text(rec: dict) -> str:
    port = f":{rec['dport']}" if rec["dport"] is not None else ""
    if rec["event"] == "close":
        if rec.get("refused"):
            verb = "port closed (refused)" if rec.get("reset") else "probe closed"
            return f"[wire] {verb} {rec['dst']}{port} ({rec['proto']})"
        return f"[wire] connection dropped {rec['src']} → {rec['dst']}{port} ({rec['proto']})"
    if rec["direction"] == "in":
        return f"[wire] callback {rec['src']} → you{port} ({rec['proto']})"
    return f"[wire] {rec['src']} → {rec['dst']}{port} ({rec['proto']})"


def ingest_lines(lines: Iterable[str], engagement_id, local_ips: set[str],
                 emit_events: bool = True) -> list[dict]:
    """Feed tcpdump text lines through the parser into the flows table. Returns
    the newly-seen flow records. Used both by the live Sensor and by tests."""
    new: list[dict] = []
    conn = db.connect()
    try:
        for line in lines:
            flow = parse_line(line)
            if not flow:
                continue
            rec = record_flow(conn, engagement_id, flow, local_ips)
            if not rec:
                continue
            new.append(rec)
            if emit_events:
                if rec["event"] == "close":
                    kind = "flowclose"
                elif rec["direction"] == "in":
                    kind = "callback"
                else:
                    kind = "flow"
                db.add_event(conn, "user", kind, _flow_event_text(rec),
                             target_id=rec["target_id"], engagement_id=engagement_id,
                             meta={"flow": rec["id"], "direction": rec["direction"],
                                   "src": rec["src"], "dst": rec["dst"],
                                   "dport": rec["dport"], "proto": rec["proto"],
                                   "remote": rec["remote"], "event": rec["event"],
                                   "state": rec["state"], "refused": rec.get("refused", False),
                                   "reset": rec.get("reset", False)})
        # a fresh callback is high-signal — surface it on the worklist right away
        if emit_events and any(r["direction"] == "in" and r["event"] == "open" for r in new):
            try:
                from . import correlate
                correlate.run(conn, engagement_id)
            except Exception:
                pass
    finally:
        conn.close()
    return new


def build_bpf(scope_cidrs: list[str], local_ips: set[str]) -> str:
    """A BPF filter that keeps only in-scope hosts and drops our own control
    traffic. Empty scope -> capture all IP (the caller decided that was fine)."""
    terms = [f"net {c}" if "/" in c else f"host {c}" for c in scope_cidrs if c.strip()]
    scope = f"({' or '.join(terms)})" if terms else "ip"
    return scope


class Sensor:
    """Manages a long-running tcpdump, streaming its lines into the flows table.
    Slice 2 wires start/stop into the API; here it is a self-contained manager
    so the capture path is real and reviewable. `feed()` bypasses the subprocess
    for tests."""

    def __init__(self, engagement_id, local_ips: set[str], iface: str,
                 scope_cidrs: list[str] | None = None):
        self.engagement_id = engagement_id
        self.local_ips = set(local_ips)
        self.iface = iface
        self.bpf = build_bpf(scope_cidrs or [], self.local_ips)
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._error: str | None = None
        self._capturing = False

    def argv(self) -> list[str]:
        # -l line-buffered, -n no DNS, -tt epoch ts. NOT -q: we need TCP Flags to
        # track connection state (SYN/established/FIN/RST). setcap means no sudo.
        return ["tcpdump", "-l", "-n", "-tt", "-i", self.iface, self.bpf]

    def feed(self, lines: Iterable[str]) -> list[dict]:
        return ingest_lines(lines, self.engagement_id, self.local_ips)

    def start(self) -> None:
        if shutil.which("tcpdump") is None:
            raise RuntimeError("tcpdump not on PATH")
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="netsensor")
        self._thread.start()

    def _run(self) -> None:
        import time
        try:
            self._proc = subprocess.Popen(self.argv(), stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True, bufsize=1)
        except Exception as e:
            self._error = f"could not launch tcpdump: {e}"
            return
        # tcpdump dies fast on the common failures (no privilege, bad interface);
        # give it a beat, then surface stderr so the UI can say WHY instead of
        # silently showing nothing.
        time.sleep(0.5)
        if self._proc.poll() is not None:
            err = (self._proc.stderr.read() or "").strip().splitlines()
            msg = err[-1] if err else f"tcpdump exited ({self._proc.returncode})"
            if "permission" in msg.lower() or "denied" in msg.lower() or self._proc.returncode == 1:
                msg = "needs privilege — setcap cap_net_raw,cap_net_admin+eip $(which tcpdump), or run as root"
            self._error = msg
            self._proc = None
            return
        self._error = None
        self._capturing = True
        try:
            for line in self._proc.stdout:  # type: ignore[union-attr]
                if self._stop.is_set():
                    break
                ingest_lines([line], self.engagement_id, self.local_ips)
        finally:
            self._capturing = False
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


# ---- local IP / interface discovery -------------------------------------

def primary_ip() -> str | None:
    """The address the OS would source outbound traffic from — no packet sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, unroutable; just sets src
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def iface_ips(iface: str) -> set[str]:
    """IPv4 addresses bound to an interface (Linux `ip`); falls back to macOS
    `ifconfig`. Empty set if neither is available (caller can pass ips instead)."""
    ips: set[str] = set()
    for argv in (["ip", "-4", "-o", "addr", "show", "dev", iface],
                 ["ifconfig", iface]):
        if shutil.which(argv[0]) is None:
            continue
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        ips.update(re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", out))
        if ips:
            break
    return ips


def default_iface() -> str:
    return os.environ.get("REDOPS_SNIFF_IFACE") or ("en0" if os.uname().sysname == "Darwin" else "eth0")


def list_interfaces() -> list[dict]:
    """Every non-loopback interface with an IPv4 address, as
    [{"iface": "tun0", "ips": ["10.10.10.166"]}]. Used to populate the
    sensor's interface selector so the operator picks the right vantage point."""
    by: dict[str, list[str]] = {}
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                m = re.match(r"\d+:\s+(\S+)\s+inet (\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    by.setdefault(m.group(1), []).append(m.group(2))
        except (OSError, subprocess.SubprocessError):
            pass
    elif shutil.which("ifconfig"):
        try:
            out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5).stdout
            cur = None
            for line in out.splitlines():
                h = re.match(r"(\S+):", line)
                if h:
                    cur = h.group(1)
                ip = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", line)
                if cur and ip:
                    by.setdefault(cur, []).append(ip.group(1))
        except (OSError, subprocess.SubprocessError):
            pass
    return [{"iface": i, "ips": ips} for i, ips in by.items() if i != "lo"]


def route_iface(dst_ip: str) -> tuple[str | None, str | None]:
    """(iface, src_ip) the OS would use to reach dst_ip — so the UI can flag
    which interface actually carries traffic to the engagement's scope. No packet
    is sent (`ip route get` is a routing-table query)."""
    if shutil.which("ip") is None:
        return (None, None)
    try:
        out = subprocess.run(["ip", "route", "get", dst_ip],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return (None, None)
    dev = re.search(r"dev (\S+)", out)
    src = re.search(r"src (\d+\.\d+\.\d+\.\d+)", out)
    return (dev.group(1) if dev else None, src.group(1) if src else None)
def all_local_ips() -> set[str]:
    """Every IPv4 bound to any local interface — the operator's own addresses,
    which are never a scope target (your box, your callback/LHOST). Parses
    `ip -4 -o addr`; falls back to the primary source address."""
    ips: set[str] = set()
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True,
                                 text=True, timeout=5).stdout
            ips.update(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out))
        except (OSError, subprocess.SubprocessError):
            pass
    p = primary_ip()
    if p:
        ips.add(p)
    ips.discard("127.0.0.1")     # loopback is handled separately
    return ips


# ---- process-level manager (one live capture per server) ----------------

_sensor: Sensor | None = None
_lock = threading.Lock()


def local_ip_set(iface: str) -> set[str]:
    ips = iface_ips(iface)
    p = primary_ip()
    if p:
        ips.add(p)
    return ips


def start(engagement_id, scope_cidrs: list[str], iface: str | None = None,
          local_ips: set[str] | None = None) -> dict:
    global _sensor
    with _lock:
        if _sensor and _sensor.running:
            _sensor.stop()
        ifc = iface or default_iface()
        ips = local_ips or local_ip_set(ifc)
        _sensor = Sensor(engagement_id, ips, ifc, scope_cidrs)
        _sensor.start()
    import time
    time.sleep(0.6)   # let it either come up or report why it couldn't
    return status()


def stop() -> dict:
    global _sensor
    with _lock:
        if _sensor:
            _sensor.stop()
        return status()


def ensure(engagement_id, scope_cidrs: list[str]) -> dict:
    """Best-effort: capture should be running. Start it if it isn't (and hasn't
    already failed for a reason a retry won't fix). Called when a scan fires so
    the operator's own traffic is captured without a manual step."""
    s = _sensor
    if s and (s.running or s._error):     # already up, or already told us why not
        return status()
    return start(engagement_id, scope_cidrs)


def status() -> dict:
    have = shutil.which("tcpdump") is not None
    s = _sensor
    if not s:
        return {"running": False, "capturing": False, "available": have,
                "error": None if have else "tcpdump not installed"}
    return {"running": s.running, "capturing": s._capturing, "available": have,
            "error": s._error, "iface": s.iface, "bpf": s.bpf,
            "engagement_id": s.engagement_id, "local_ips": sorted(s.local_ips)}
