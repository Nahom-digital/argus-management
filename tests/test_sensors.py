"""The hardware sensor and network identity helpers in System.py.

Each helper reads a directory tree that exists on some machines and not on
others, so every test builds the tree it wants under tmp_path. Nothing here
reads the real /sys or /proc, and nothing blocks on the network: the public
IP cache is fed directly, and the fetch itself is exercised with a stubbed
urlopen.
"""
import time

import System


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _chip(hwmon, index, name, files):
    root = hwmon / f"hwmon{index}"
    _write(root / "name", name)
    for entry, value in files.items():
        _write(root / entry, str(value))
    return root


# --- CPU temperature ----------------------------------------------------------

def test_cpu_temp_prefers_a_cpu_chip_over_other_hwmon_chips(tmp_path):
    hwmon = tmp_path / "hwmon"
    thermal = tmp_path / "thermal"
    _chip(hwmon, 0, "pch", {"temp1_input": 99000})
    _chip(hwmon, 1, "coretemp", {"temp1_input": 47000})
    got = System.cpu_temp(hwmon=str(hwmon), thermal=str(thermal))
    assert got == {"c": 47.0, "label": "coretemp"}


def test_cpu_temp_prefers_coretemp_over_acpitz_in_either_order(tmp_path):
    hwmon = tmp_path / "hwmon"
    thermal = tmp_path / "thermal"
    _chip(hwmon, 0, "acpitz", {"temp1_input": 66000})
    _chip(hwmon, 1, "coretemp", {"temp1_input": 51000})
    got = System.cpu_temp(hwmon=str(hwmon), thermal=str(thermal))
    assert got == {"c": 51.0, "label": "coretemp"}


def test_cpu_temp_uses_acpitz_when_no_cpu_chip_is_present(tmp_path):
    hwmon = tmp_path / "hwmon"
    thermal = tmp_path / "thermal"
    _chip(hwmon, 0, "acpitz", {"temp1_input": 66000})
    got = System.cpu_temp(hwmon=str(hwmon), thermal=str(thermal))
    assert got == {"c": 66.0, "label": "acpitz"}


def test_cpu_temp_falls_back_to_a_thermal_zone(tmp_path):
    hwmon = tmp_path / "hwmon"
    thermal = tmp_path / "thermal"
    hwmon.mkdir()
    _write(thermal / "thermal_zone0" / "type", "x86_pkg_temp")
    _write(thermal / "thermal_zone0" / "temp", "52000")
    got = System.cpu_temp(hwmon=str(hwmon), thermal=str(thermal))
    assert got == {"c": 52.0, "label": "x86_pkg_temp"}


def test_cpu_temp_ignores_implausible_readings(tmp_path):
    hwmon = tmp_path / "hwmon"
    thermal = tmp_path / "thermal"
    _chip(hwmon, 0, "coretemp", {"temp1_input": 0, "temp2_input": 200000})
    assert System.cpu_temp(hwmon=str(hwmon), thermal=str(thermal)) is None


def test_cpu_temp_returns_none_without_sensors(tmp_path):
    assert System.cpu_temp(hwmon=str(tmp_path / "hwmon"),
                           thermal=str(tmp_path / "thermal")) is None


# --- Fans ---------------------------------------------------------------------

def test_fan_speeds_reports_rpm_percent_and_label(tmp_path):
    hwmon = tmp_path / "hwmon"
    _chip(hwmon, 0, "thinkpad", {"fan1_input": 3000, "fan1_max": 6000,
                                 "fan1_label": "CPU fan",
                                 "fan2_input": 4500})
    readings, not_reported = System.fan_speeds(
        hwmon=str(hwmon), thinkpad=str(tmp_path / "ibm-fan"))
    assert readings == [
        {"rpm": 3000, "label": "CPU fan", "percent": 50},
        {"rpm": 4500, "label": "thinkpad", "percent": None},
    ]
    assert not_reported is False


def test_fan_speeds_uses_the_thinkpad_tachometer_when_hwmon_has_none(tmp_path):
    hwmon = tmp_path / "hwmon"
    hwmon.mkdir()
    thinkpad = tmp_path / "ibm-fan"
    _write(thinkpad, "status: enabled\nspeed: 4200\n")
    readings, not_reported = System.fan_speeds(
        hwmon=str(hwmon), thinkpad=str(thinkpad))
    assert readings == [{"rpm": 4200, "label": "thinkpad", "percent": None}]
    assert not_reported is False


def test_fan_speeds_flags_the_not_reported_sentinel(tmp_path):
    hwmon = tmp_path / "hwmon"
    _chip(hwmon, 0, "thinkpad", {"fan1_input": System.FAN_NOT_REPORTED})
    readings, not_reported = System.fan_speeds(
        hwmon=str(hwmon), thinkpad=str(tmp_path / "ibm-fan"))
    assert readings == []
    assert not_reported is True


def test_fan_speeds_without_any_sensor(tmp_path):
    hwmon = tmp_path / "hwmon"
    hwmon.mkdir()
    readings, not_reported = System.fan_speeds(
        hwmon=str(hwmon), thinkpad=str(tmp_path / "ibm-fan"))
    assert readings == []
    assert not_reported is False


# --- Battery ------------------------------------------------------------------

def test_battery_reads_the_first_battery_that_has_a_capacity(tmp_path):
    base = tmp_path / "power_supply"
    _write(base / "AC" / "online", "1")
    _write(base / "BAT0" / "status", "Unknown")
    _write(base / "BAT1" / "capacity", "84")
    _write(base / "BAT1" / "status", "Discharging")
    assert System.battery(base=str(base)) == {"percent": 84, "state": "Discharging"}


def test_battery_state_may_be_missing(tmp_path):
    base = tmp_path / "power_supply"
    _write(base / "BAT0" / "capacity", "77")
    assert System.battery(base=str(base)) == {"percent": 77, "state": ""}


def test_battery_returns_none_on_a_desktop(tmp_path):
    base = tmp_path / "power_supply"
    base.mkdir()
    assert System.battery(base=str(base)) is None


# --- Network identity ---------------------------------------------------------

def test_private_ip_is_an_address_and_interface_or_nothing():
    priv = System.private_ip()
    assert priv is None or (priv["ip"] and isinstance(priv["iface"], str))


class _Resp:
    def __init__(self, body):
        self._body = body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_public_ip_parses_the_cloudflare_trace(monkeypatch):
    import urllib.request

    def fake(req, timeout=0):
        return _Resp(b"fl=abc\nip=203.0.113.9\nts=1\n")

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    assert System._fetch_public_ip() == "203.0.113.9"


def test_fetch_public_ip_falls_back_to_a_plain_echo(monkeypatch):
    import urllib.request

    def fake(req, timeout=0):
        if "cloudflare" in req.full_url:
            raise OSError("no route")
        return _Resp(b"198.51.100.7\n")

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    assert System._fetch_public_ip() == "198.51.100.7"


def test_fetch_public_ip_returns_none_when_offline(monkeypatch):
    import urllib.request

    def fake(req, timeout=0):
        raise OSError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    assert System._fetch_public_ip() is None


def test_public_ip_serves_a_fresh_cache_without_a_fetch(monkeypatch):
    cache = {"value": "198.51.100.7", "t": time.time(), "busy": False}
    monkeypatch.setattr(System, "_public_ip", cache)
    assert System.public_ip() == "198.51.100.7"
    assert cache["busy"] is False      # a fresh answer starts no thread


# --- The grid data ------------------------------------------------------------

def test_static_info_carries_the_sensor_fields(monkeypatch):
    monkeypatch.setattr(System, "public_ip", lambda: "203.0.113.9")
    info = System.static_info()
    assert info["public_ip"] == "203.0.113.9"
    assert info["cpu_temp_c"] is None or isinstance(info["cpu_temp_c"], float)
    assert isinstance(info["cpu_temp_label"], str)
    assert isinstance(info["fans"], list)
    assert isinstance(info["fan_not_reported"], bool)
    assert info["battery"] is None or isinstance(info["battery"], dict)
    assert isinstance(info["private_ip"], str)
    assert isinstance(info["private_ip_iface"], str)
