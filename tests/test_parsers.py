"""Unit tests on the parsers, using lines and tables recorded from the reference fabric on 2026-09-14."""
from fabricsre.timeline import parse_exporter_line
from fabricsre.nxapi import rows, NXAPIClient, NXAPIError
from fabricsre.investigate import Investigator
import pytest

LINE = ('2026-09-14T16:27:30.309210+00:00 172.29.129.232 local0.notice Exporter[52][Facility: local0, Severity: Critical] '
        'FabricName : DC1 Title : BGP_PEER_CONNECTION_DOWN NDSeverity : critical Nodes : ["dc1-bgw1"] [default:10.10.1.0]: BGP session to peer '
        '10.10.1.0 is not in established state: current BGP session status is closing Cleared : true SuspendedAlert :  Acknowledged : false Suppressed : false')


def test_exporter_line():
    p = parse_exporter_line(LINE)
    assert p["fabric"] == "DC1" and p["title"] == "BGP_PEER_CONNECTION_DOWN" and p["nd_severity"] == "critical"
    assert p["nodes"] == ["dc1-bgw1"] and p["cleared"] is True and "10.10.1.0" in p["text"] and p["ts"].year == 2026


def test_exporter_line_rejects_other():
    assert parse_exporter_line("2026-09-14T16:16:15+00:00 172.29.129.53 user.notice fabricsre-test udp receiver test") is None


def test_rows_single_and_list():
    t = {"TABLE_mac_address": {"ROW_mac_address": {"disp_mac_addr": "aac1.ab85.ab21", "disp_port": "Eth1/3"}}}
    assert rows(t, "TABLE_mac_address", "ROW_mac_address")[0]["disp_port"] == "Eth1/3"
    t2 = {"TABLE_mac_address": {"ROW_mac_address": [{"a": 1}, {"a": 2}]}}
    assert len(rows(t2, "TABLE_mac_address", "ROW_mac_address")) == 2
    assert rows({}, "TABLE_x", "ROW_x") == []


def test_walk_nested():
    body = {"TABLE_vrf": {"ROW_vrf": {"vrf-name-out": "tenant", "TABLE_adj": {"ROW_adj": {"ip-addr-out": "192.168.100.11", "mac": "aac1.ab85.ab21", "intf-out": "Vlan2300"}}}}}
    adj = Investigator._walk(body, "adj")
    assert adj and adj[0]["ip-addr-out"] == "192.168.100.11"
    body2 = {"TABLE_l2route_mac_ip_all": {"ROW_l2route_mac_ip_all": [{"host-ip": "192.168.100.11", "TABLE_nexthop": {"ROW_nexthop": {"nh": "Local"}}}]}}
    assert Investigator._walk(body2, "l2route_mac_ip_all")[0]["host-ip"] == "192.168.100.11"
    assert Investigator._walk(body2, "nexthop")[0]["nh"] == "Local"


def test_allowlist():
    NXAPIClient._check("show nve peers")
    NXAPIClient._check("show mac address-table address aac1.ab85.ab21")
    with pytest.raises(NXAPIError):
        NXAPIClient._check("configure terminal")
    with pytest.raises(NXAPIError):
        NXAPIClient._check("show running-config | include bgp")
    with pytest.raises(NXAPIError):
        NXAPIClient._check("show clock ; reload")
