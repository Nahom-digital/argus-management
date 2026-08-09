"""The grant registry is the single definition of what a permission is. These
tests pin its shape, and pin that normalize_grants can only ever narrow a
hostile payload, never widen it."""
import json

import panel_users as pu


def test_registry_covers_all_seven_groups():
    groups = {g.group for g in pu.PERMISSIONS}
    assert groups == {"terminal", "disk", "database", "network",
                      "compute", "services", "logs"}
    assert len(pu.PERMISSIONS) == 15


def test_group_order_lists_every_group_once():
    assert set(pu.GROUP_ORDER) == {g.group for g in pu.PERMISSIONS}
    assert len(pu.GROUP_ORDER) == len(set(pu.GROUP_ORDER))
    assert set(pu.GROUP_LABELS) == set(pu.GROUP_ORDER)


def test_normalize_fills_every_key_with_defaults():
    out = pu.normalize_grants({})
    assert set(out) == set(pu.GRANT_KEYS)
    assert out["terminal"] == "none"
    assert out["disk_scope"] == "none"
    assert out["db_read"] is False


def test_normalize_drops_unknown_keys():
    out = pu.normalize_grants({"db_read": True, "root": True, "__proto__": True})
    assert out["db_read"] is True
    assert "root" not in out
    assert "__proto__" not in out


def test_normalize_rejects_invalid_choice():
    assert pu.normalize_grants({"terminal": "wheel"})["terminal"] == "none"
    assert pu.normalize_grants({"disk_scope": "/etc"})["disk_scope"] == "none"


def test_normalize_coerces_values_to_real_bools():
    out = pu.normalize_grants({"db_read": "yes", "db_write": 0, "db_log": None})
    assert out["db_read"] is True
    assert out["db_write"] is False
    assert out["db_log"] is False


def test_normalize_survives_a_non_dict():
    assert pu.normalize_grants(None) == pu.normalize_grants({})
    assert pu.normalize_grants("db_read") == pu.normalize_grants({})
    assert pu.normalize_grants([("db_read", True)]) == pu.normalize_grants({})


def test_describe_grants_is_json_safe_and_complete():
    payload = pu.describe_grants()
    json.dumps(payload)
    assert {g["key"] for g in payload} == set(pu.GRANT_KEYS)
    for g in payload:
        assert g["label"] and g["help"]
        assert g["kind"] in ("bool", "choice")
        if g["kind"] == "choice":
            assert g["default"] in g["choices"]
