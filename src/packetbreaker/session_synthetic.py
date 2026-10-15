"""Two-point L2 replica of a session-behaviour incident; synthetic addresses only.

Point A sits on the client side and point B on the server side of a transparent device (TTL is
not decremented between them). Point B loses a share of server-to-client data (capture loss
that the client's ACKs prove delivered). Ground truth covers peer-side reset storms, a
client-initiated close and reconnect of the main stream, a sender rate drop, and distractors
that must not be reported as any of those.
"""

import json
from pathlib import Path
import random

from .synthetic import tcp_packet, write_pcap

CLIENT, SERVER, SERVER_PORT = "198.51.100.10", "203.0.113.80", 443
CLIENT6, SERVER6 = "2001:db8:10::10", "2001:db8:80::80"
CLIENT_TTL, SERVER_TTL = 54, 58
DEVICE_US = 30e-6
RTT = 0.045
BASE = 1700000000.0
MSS = 1300
FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16


class Conn:
    def __init__(self, case, port, opened, window=2000):
        self.case, self.port, self.window = case, port, window
        self.client_ip, self.server_ip = case.client_ip, case.server_ip
        self.cseq, self.sseq = 1000 + port * 7919 % 100000, 5000 + port * 104729 % 100000
        self.cid, self.sid = port * 3 % 60000 + 1, port * 5 % 60000 + 1
        self.handshake(opened)

    def client(self, t, flags, payload=b"", *, window=None, ipid=None, skip_b=False, skip_a=False):
        ipid = self._next("cid") if ipid is None else ipid
        frame = tcp_packet(
            self.client_ip,
            self.server_ip,
            self.port,
            SERVER_PORT,
            self.cseq,
            self.sseq,
            flags,
            payload,
            ipid,
            ttl=CLIENT_TTL,
            window=self.window if window is None else window,
        )
        self.case.emit(t, frame, client_side=True, skip_a=skip_a, skip_b=skip_b)
        self.cseq = (self.cseq + len(payload) + (1 if flags & (SYN | FIN) else 0)) % 2**32

    def server(self, t, flags, payload=b"", *, ipid=None, seq=None, ack=None, skip_b=False, skip_a=False):
        ipid = self._next("sid") if ipid is None else ipid
        frame = tcp_packet(
            self.server_ip,
            self.client_ip,
            SERVER_PORT,
            self.port,
            self.sseq if seq is None else seq,
            self.cseq if ack is None else ack,
            flags,
            payload,
            ipid,
            ttl=SERVER_TTL,
            window=2000,
        )
        self.case.emit(t, frame, client_side=False, skip_a=skip_a, skip_b=skip_b)
        if seq is None:
            self.sseq = (self.sseq + len(payload) + (1 if flags & (SYN | FIN) else 0)) % 2**32

    def _next(self, name):
        value = getattr(self, name)
        setattr(self, name, (value + 1) % 65536 or 1)
        return value

    def handshake(self, t):
        self.client(t, SYN)
        self.server(t + RTT, SYN | ACK)
        self.client(t + RTT + 0.0005, ACK)

    def exchange(self, t, request=120, response=200):
        self.client(t, PSH | ACK, b"q" * request)
        self.server(t + RTT, PSH | ACK, b"r" * response)
        self.client(t + RTT + 0.040, ACK)

    def server_close_then_late_client_close(self, fin_t, close_t, record_skip_b=False):
        """Server closes with FIN; the client acknowledges but closes its side late (TLS-close-like
        record + FIN). The server already released the socket, so it answers with RSTs."""
        self.server(fin_t, FIN | ACK)
        self.client(fin_t + RTT, ACK)
        self.client(close_t, PSH | ACK, b"a" * 40, skip_b=record_skip_b)
        self.client(close_t + 0.00005, FIN | ACK)
        self.server(close_t + RTT, RST, ipid=0, seq=self.sseq, ack=0)
        self.server(close_t + RTT + 0.00005, RST, ipid=0, seq=self.sseq, ack=0)

    def no_socket_reset(self, t, trigger_skip_b=False):
        """Peer lost the connection state: the next client segment gets RST(seq=its ack), no ACK."""
        self.client(t, PSH | ACK, b"t" * 40, skip_b=trigger_skip_b)
        self.server(t + RTT, RST, ipid=0, seq=self.sseq, ack=0)


class Case:
    def __init__(self, seed, ipv6=False):
        self.rng = random.Random(seed)
        self.client_ip, self.server_ip = (CLIENT6, SERVER6) if ipv6 else (CLIENT, SERVER)
        self.a, self.b = [], []

    def emit(self, t, frame, *, client_side, skip_a=False, skip_b=False):
        first, second = (self.a, self.b) if client_side else (self.b, self.a)
        skip_first, skip_second = (skip_a, skip_b) if client_side else (skip_b, skip_a)
        if not skip_first:
            first.append((BASE + t, frame))
        if not skip_second:
            second.append((BASE + t + DEVICE_US, frame))


def make_session_case(directory, *, seed=7, capture_loss_b=0.30, ipv6=False):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    case = Case(seed, ipv6)
    rng = case.rng
    truth = dict(storms=[], reconnect=None, sender_drop=None, distractors={})

    # Main stream: bulk server-to-client feed, client ACKs every second segment.
    main = Conn(case, 40001, 0.0)

    def feed(conn, start, end, rate_for, *, skip_rate=0.0, window_for=None):
        t, n = start, 0
        while t < end:
            rate = rate_for(t)
            conn.server(t, PSH | ACK, b"d" * MSS, skip_b=rng.random() < skip_rate, skip_a=rng.random() < 0.02)
            n += 1
            if n % 2 == 0:
                win = window_for(t) if window_for else None
                conn.client(t + RTT / 2, ACK, window=win)
            t += rng.uniform(0.6, 1.4) / rate
        return t

    halved = (120.0, 240.0)
    feed(main, 0.1, 400.0, lambda t: 20 if halved[0] <= t < halved[1] else 40, skip_rate=capture_loss_b)
    truth["sender_drop"] = dict(start=BASE + halved[0], end=BASE + halved[1], port=40001)

    # Client closes the main stream: small TLS-close-like record, FIN, then RST on late data.
    main.client(400.0, PSH | ACK, b"c" * 54)
    main.client(400.002, FIN | ACK)
    main.server(400.004, PSH | ACK, b"d" * MSS)
    main.client(400.0045, RST, ipid=0)
    main.server(400.050, FIN | ACK)
    main.client(400.0505, RST, ipid=0)
    reopened = Conn(case, 40099, 413.6)
    feed(reopened, 413.7, 500.0, lambda t: 40, skip_rate=capture_loss_b)
    truth["reconnect"] = dict(
        close=BASE + 400.0, reopen=BASE + 413.6, gap_s=13.6, old_port=40001, new_port=40099
    )

    # Distractor: receiver-window-limited slowdown on a second bulk stream (not a sender drop).
    limited = Conn(case, 40002, 1.0)
    feed(
        limited,
        1.1,
        480.0,
        lambda t: 6 if 250 <= t < 350 else 12,
        window_for=lambda t: 120 if 250 <= t < 350 else 2000,
    )
    truth["distractors"]["receiver_limited"] = dict(start=BASE + 250, end=BASE + 350, port=40002)

    # Control connections with periodic request/response exchanges.
    controls = {port: Conn(case, port, 2.0 + i * 0.37) for i, port in enumerate(range(41001, 41008))}
    for port, conn in controls.items():
        stop = {41001: 270, 41002: 270, 41003: 270, 41004: 270, 41005: 170, 41006: 140, 41007: 175}[port]
        t = 5.0 + (port - 41001) * 0.9
        while t < stop:
            conn.exchange(t)
            t += rng.uniform(8, 12)

    # Storm 1: four control connections lost their state on the server side; the client sends on all
    # four at once after ~30 s of silence. Connection 41001's trigger is a capture miss at point B.
    for i, port in enumerate((41001, 41002, 41003, 41004)):
        controls[port].no_socket_reset(300.0 + i * 0.0001)
    truth["storms"].append(dict(time=BASE + 300.0 + RTT, ports=[41001, 41002, 41003, 41004], side="server"))

    # Distractor: a single no-socket RST on one connection is not a storm.
    controls[41005].no_socket_reset(200.0)
    truth["distractors"]["single_no_socket_rst"] = dict(port=41005, time=BASE + 200.0 + RTT)
    # Distractor: an application abort (RST|ACK, normal IP ID) is not a state-loss reset.
    controls[41006].server(150.0, RST | ACK)
    truth["distractors"]["application_abort"] = dict(port=41006, time=BASE + 150.0)
    # Distractor: a normal server-initiated FIN close.
    controls[41007].server(180.0, FIN | ACK)
    controls[41007].client(180.0 + RTT, FIN | ACK)
    controls[41007].server(180.0 + 2 * RTT, ACK)
    truth["distractors"]["server_fin"] = dict(port=41007, time=BASE + 180.0)

    # Distractor: the client aborts two connections at once without any trigger from the server
    # (application RSTs without ACK). That is a client decision, not peer-side state loss.
    aborted = {port: Conn(case, port, 120.0 + i * 0.3) for i, port in enumerate((41008, 41009))}
    for port, conn in aborted.items():
        conn.exchange(125.0 + (port - 41008))
    for port, conn in aborted.items():
        conn.client(160.0 + (port - 41008) * 0.0002, RST, ipid=0)
    truth["distractors"]["client_abort_cluster"] = dict(ports=list(aborted), time=BASE + 160.0)

    # Late close (the real-case pattern): the server closed three connections with FIN; the client
    # closes them together 20-30 s later and gets RSTs. Expected answer, not state loss.
    lazy = {port: Conn(case, port, 190.0 + i * 0.2) for i, port in enumerate((41021, 41022, 41023))}
    for i, (port, conn) in enumerate(lazy.items()):
        conn.exchange(195.0 + i * 0.4)
        conn.server_close_then_late_client_close(
            205.0 + i * 3.0, 230.0 + i * 0.0002, record_skip_b=port == 41021
        )
    truth["late_close"] = dict(time=BASE + 230.0 + RTT, ports=list(lazy), side="server")
    # The late-close record of 41021 is a capture miss at point B; the server's RST proves delivery.
    truth["capture_miss_trigger"] = dict(port=41021, time=BASE + 230.0)

    # Storm 2 (recurring): three later control connections.
    late = {port: Conn(case, port, 330.0 + i * 0.2) for i, port in enumerate((41011, 41012, 41013))}
    for port, conn in late.items():
        conn.exchange(335.0 + (port - 41011) * 0.5)
        conn.exchange(345.0 + (port - 41011) * 0.5)
    for i, port in enumerate(late):
        late[port].no_socket_reset(450.0 + i * 0.00015)
    truth["storms"].append(dict(time=BASE + 450.0 + RTT, ports=list(late), side="server"))

    write_pcap(directory / "client_side.pcap", case.a)
    write_pcap(directory / "server_side.pcap", case.b)
    truth.update(client=case.client_ip, server=case.server_ip, base=BASE)
    (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    return truth
