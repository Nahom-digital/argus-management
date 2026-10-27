"""Per-socket Network detail parsing and rates.

The overview card gets interface totals from psutil. The detail table needs
something psutil does not expose: the cumulative byte counters in tcp_info.
These tests pin the ss parser and the delta math without opening a socket.
"""
from types import SimpleNamespace

import psutil

import System


SS_SAMPLE = (
    '0 0 127.0.0.1:2000 127.0.0.1:58778 users:(("python3",pid=1224,fd=4))\n'
    '\t cubic rtt:0.1/0.1 bytes_sent:277299 bytes_acked:277300 '
    'bytes_received:7380 segs_out:900 segs_in:300\n'
    '0 0 [::1]:2000 [::1]:62000 users:(("python3",pid=7,fd=9))\n'
    '\t cubic bytes_received:10 bytes_sent:20\n'
)


def _addr(ip, port):
    return SimpleNamespace(ip=ip, port=port)


def test_parse_ss_established_reads_counters_and_owner():
    rows = System._parse_ss_established(SS_SAMPLE)
    assert rows == [
        {
            "local": "127.0.0.1:2000",
            "peer": "127.0.0.1:58778",
            "pid": 1224,
            "fd": 4,
            "sent": 277299,
            "recv": 7380,
        },
        {
            "local": "[::1]:2000",
            "peer": "[::1]:62000",
            "pid": 7,
            "fd": 9,
            "sent": 20,
            "recv": 10,
        },
    ]


def test_parse_ss_established_ignores_sockets_without_tcp_counters():
    text = (
        '0 0 127.0.0.1:2000 127.0.0.1:1 users:(("x",pid=2,fd=3))\n'
        '\t cubic rtt:1/1\n'
    )
    assert System._parse_ss_established(text) == []


def test_ipv6_endpoints_are_normalized_to_psutil_form():
    assert System._norm_endpoint("[::1]:2000") == "::1:2000"
    assert System._norm_endpoint("[::ffff:127.0.0.1]:22") == "::ffff:127.0.0.1:22"
    assert System._norm_endpoint("127.0.0.1:22") == "127.0.0.1:22"


def test_connection_rates_use_the_previous_counter_sample(monkeypatch):
    monkeypatch.setattr(System, "_conn_last", {
        "pid:4:127.0.0.1:2000->127.0.0.1:5000": {
            "t": 10.0,
            "recv": 1000,
            "sent": 2000,
        },
    })
    rows = [{
        "_rate_key": "pid:4:127.0.0.1:2000->127.0.0.1:5000",
        "bytes_in": 3000,
        "bytes_out": 6000,
    }]
    System._attach_conn_rates(rows, now=12.0)
    assert rows[0]["rate_in"] == 1000.0
    assert rows[0]["rate_out"] == 2000.0
    assert System._conn_last[rows[0]["_rate_key"]]["recv"] == 3000
    assert System._conn_last[rows[0]["_rate_key"]]["sent"] == 6000


def test_the_first_connection_sample_says_rates_are_not_ready(monkeypatch):
    monkeypatch.setattr(System, "_conn_last", {})
    rows = [{"_rate_key": "a", "bytes_in": 10, "bytes_out": 20}]
    System._attach_conn_rates(rows, now=10.0)
    assert rows[0]["rate_in"] is None
    assert rows[0]["rate_out"] is None


def test_a_counter_reset_never_produces_a_negative_rate(monkeypatch):
    monkeypatch.setattr(System, "_conn_last", {
        "a": {"t": 10.0, "recv": 5000, "sent": 9000},
    })
    rows = [{"_rate_key": "a", "bytes_in": 100, "bytes_out": 200}]
    System._attach_conn_rates(rows, now=12.0)
    assert rows[0]["rate_in"] == 0.0
    assert rows[0]["rate_out"] == 0.0


def test_established_only_filters_sockets_and_attaches_ss_counters(monkeypatch):
    import socket

    connections = [
        SimpleNamespace(
            pid=None,
            fd=None,
            type=socket.SOCK_STREAM,
            laddr=_addr("127.0.0.1", 2000),
            raddr=_addr("127.0.0.1", 5000),
            status="ESTABLISHED",
        ),
        SimpleNamespace(
            pid=None,
            fd=None,
            type=socket.SOCK_STREAM,
            laddr=_addr("0.0.0.0", 22),
            raddr=(),
            status="LISTEN",
        ),
        SimpleNamespace(
            pid=None,
            fd=None,
            type=socket.SOCK_DGRAM,
            laddr=_addr("0.0.0.0", 68),
            raddr=(),
            status="NONE",
        ),
        SimpleNamespace(
            pid=None,
            fd=None,
            type=socket.SOCK_DGRAM,
            laddr=_addr("127.0.0.1", 5001),
            raddr=_addr("127.0.0.1", 5002),
            status="ESTABLISHED",
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind: connections)
    monkeypatch.setattr(System, "_ss_established", lambda: ([{
        "local": "127.0.0.1:2000",
        "peer": "127.0.0.1:5000",
        "pid": None,
        "fd": None,
        "sent": 123,
        "recv": 456,
    }], ""))
    monkeypatch.setattr(System, "_conn_last", {})

    result = System.net_connections(established_only=True)
    assert result.get("rate_error") is None
    assert [c["status"] for c in result["connections"]] == ["ESTABLISHED"]
    row = result["connections"][0]
    assert row["bytes_in"] == 456
    assert row["bytes_out"] == 123
    assert row["rate_in"] is None
    assert row["rate_out"] is None
    assert "_rate_key" not in row


def test_the_all_sockets_view_keeps_listeners_without_fake_rates(monkeypatch):
    import socket

    connections = [
        SimpleNamespace(
            pid=None,
            fd=None,
            type=socket.SOCK_STREAM,
            laddr=_addr("0.0.0.0", 22),
            raddr=(),
            status="LISTEN",
        ),
        SimpleNamespace(
            pid=None,
            fd=None,
            type=socket.SOCK_STREAM,
            laddr=_addr("127.0.0.1", 2000),
            raddr=_addr("127.0.0.1", 5000),
            status="ESTABLISHED",
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind: connections)
    monkeypatch.setattr(System, "_ss_established", lambda: ([{
        "local": "127.0.0.1:2000",
        "peer": "127.0.0.1:5000",
        "pid": None,
        "fd": None,
        "sent": 1,
        "recv": 2,
    }], ""))
    monkeypatch.setattr(System, "_conn_last", {})

    result = System.net_connections(established_only=False)
    assert [c["status"] for c in result["connections"]] == ["LISTEN", "ESTABLISHED"]
    assert result["connections"][0]["bytes_in"] is None
    assert result["connections"][0]["rate_in"] is None
    assert result["connections"][1]["bytes_in"] == 2


def test_ss_failure_is_reported_without_breaking_the_socket_list(monkeypatch):
    import socket

    connections = [SimpleNamespace(
        pid=None,
        fd=None,
        type=socket.SOCK_STREAM,
        laddr=_addr("127.0.0.1", 2000),
        raddr=_addr("127.0.0.1", 5000),
        status="ESTABLISHED",
    )]
    monkeypatch.setattr(psutil, "net_connections", lambda kind: connections)
    monkeypatch.setattr(System, "_ss_established", lambda: ([], "Per-socket counters are unavailable: FileNotFoundError"))
    monkeypatch.setattr(System, "_conn_last", {})

    result = System.net_connections(established_only=True)
    assert len(result["connections"]) == 1
    assert result["rate_error"].startswith("Per-socket counters")
    assert result["connections"][0]["bytes_in"] is None
