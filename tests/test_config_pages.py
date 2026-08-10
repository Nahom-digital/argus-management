"""What Config contains for each account.

Every grant that unlocks something has to unlock a way in to it. Proxy,
Cloudflare and the firewall used to share the proxy page, so an account granted
only Cloudflare tunnels opened Config and found nothing but My Account: the
permission worked and the page to use it did not exist. These tests pin one card
per grant, and pin that the page behind each card is only built for the accounts
that hold it.
"""
import re

import panel
import panel_users as pu

# The grant that unlocks a card, and something only that card's page contains.
CARDS = {
    "service":  ("svc_status", "svc-list"),
    "database": ("db_read", "db-table-sel"),
    "proxy":    ("net_proxy", "proxy-list"),
    "tunnel":   ("tunnel_manage", "cf-card"),
    "firewall": ("firewall_manage", "px-fw-add"),
}


def staff(**grants):
    perms = dict(pu.all_grants(False))
    perms.update({"role": "staff", "username": "staffer", "os_username": "staffer"})
    perms.update(grants)
    return perms


def admin():
    perms = dict(pu.all_grants(True))
    perms.update({"role": "admin", "username": "admin", "os_username": None})
    return perms


def cards_in(html):
    return re.findall(r'data-cfgnav="([a-z]+)"', html)


def test_each_grant_puts_its_own_card_on_the_config_page():
    for card, (grant, _marker) in CARDS.items():
        html = panel._config_pane_html(staff(**{grant: True}))
        assert card in cards_in(html), f"{grant} did not produce the {card} card"


def test_a_grant_only_puts_its_own_card_there():
    for card, (grant, _marker) in CARDS.items():
        html = panel._config_pane_html(staff(**{grant: True}))
        others = set(cards_in(html)) - {card, "account"}
        assert not others, f"{grant} also produced {others}"


def test_the_page_behind_a_card_is_only_built_when_the_card_is():
    for card, (grant, marker) in CARDS.items():
        with_grant = panel._config_pane_html(staff(**{grant: True}))
        without = panel._config_pane_html(staff())
        assert marker in with_grant, f"{card} page missing for {grant}"
        assert marker not in without, f"{card} page rendered without {grant}"


def test_an_account_with_no_grants_still_has_its_own_page():
    html = panel._config_pane_html(staff())
    assert cards_in(html) == ["account"]


def test_the_admin_gets_every_page():
    html = panel._config_pane_html(admin())
    listed = cards_in(html)
    for card in list(CARDS) + ["users", "server"]:
        assert card in listed, f"the admin has no {card} card"
    for card, (_grant, marker) in CARDS.items():
        assert marker in html


def test_every_card_has_a_page_and_a_description():
    """A card with no builder would be a dead end, and a page with no card would
    be unreachable. Both are caught here rather than in the browser."""
    assert set(panel._CONFIG_SUB_BUILDERS) == set(panel._CONFIG_CARD_META)
    for key, (title, icon, desc) in panel._CONFIG_CARD_META.items():
        assert title and icon.startswith("ic-") and desc.endswith(".")


def test_cloudflare_and_the_firewall_are_no_longer_hidden_inside_proxy():
    """The bug this file exists for: two grants whose only way in was a third
    grant's page."""
    proxy_page = panel._config_sub_proxy(admin())
    assert "cf-card" not in proxy_page
    assert "px-fw-add" not in proxy_page
