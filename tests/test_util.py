from fabricsre.util import norm_mac, norm_if, norm_role, host_ip
from fabricsre.cli import _dur
import datetime as dt


def test_norm_mac():
    assert norm_mac("AA:C1:AB:85:AB:21") == "aac1.ab85.ab21"
    assert norm_mac("aac1.ab85.ab21") == "aac1.ab85.ab21"
    assert norm_mac("aa-c1-ab-85-ab-21") == "aac1.ab85.ab21"
    assert norm_mac(None) == "" and norm_mac("") == ""


def test_norm_if():
    assert norm_if("eth1/3") == "Ethernet1/3"
    assert norm_if("Eth1/3") == "Ethernet1/3"
    assert norm_if("ethernet1/3") == "Ethernet1/3"
    assert norm_if("Po10") == "port-channel10"
    assert norm_if("vlan2300") == "Vlan2300"
    assert norm_if("Loopback0") == "Loopback0"


def test_norm_role():
    assert norm_role("borderGateway") == "border gateway"
    assert norm_role("coreRouter") == "core router"
    assert norm_role("leaf") == "leaf"
    assert norm_role("border gateway") == "border gateway"


def test_host_ip_and_dur():
    assert host_ip("172.29.129.33/32") == "172.29.129.33" and host_ip(None) is None
    assert _dur("30m") == dt.timedelta(minutes=30) and _dur("2h") == dt.timedelta(hours=2) and _dur("1d") == dt.timedelta(days=1)
