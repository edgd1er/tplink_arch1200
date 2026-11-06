"""Unit tests for archer1200.Archer1200 module using pytest."""
import json
from unittest.mock import patch, call, MagicMock

from urllib3.exceptions import MaxRetryError
from _socket import gaierror
import pytest
import requests
from requests import Response

from archer1200.archer1200 import Archer1200


def _create_response(status_code: int, content: bytes) -> Response:
    """Helper function to create mock Response objects."""
    r = Response()
    r.status_code = status_code
    r._content = content
    return r


@pytest.fixture
def router_instance():
    """Fixture providing a Archer1200 instance with mocked HTTP calls."""
    # Create mock session
    mock_session = MagicMock()

    # Mock response for timestamp
    timestamp_response = MagicMock()
    timestamp_response.text = '<html><head><title>Index of /webpages/js/libs/</title></head><body><h1>Index of /webpages/js/libs/</h1><strong><a href="/webpages/js/libs/encrypt.987654321.js">encrypt.987654321.js</body></html>'
    timestamp_response.raise_for_status = MagicMock()

    # Mock response for cloud login check
    check_factory_response = MagicMock()
    check_factory_response.json.return_value = {
        "success": "true",
        "data": {"is_default": "false", "cloud_ever_login": "true"}
    }
    check_factory_response.text = '{"success": "true", "data": {"is_default": "false", "cloud_ever_login": "true"}}'
    check_factory_response.raise_for_status = MagicMock()

    # Mock response for cloud login
    cloud_login_response = MagicMock()
    cloud_login_response.json.return_value = {
        "success": "true",
        "data": {"password": "V_SECRET", "stok": "mocked_token"}
    }
    cloud_login_response.text = '{"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}'
    cloud_login_response.raise_for_status = MagicMock()

    # Set up side_effect for initialization calls
    # First POST: check_factory_default
    # Second POST: cloud_login
    mock_session.post.side_effect = [check_factory_response, cloud_login_response]
    mock_session.get.return_value = timestamp_response

    # Patch requests.session to return our mock
    with patch('requests.session', return_value=mock_session):
        # Create instance - this will use our mocked session
        router = Archer1200(username="ARCHER_LOGIN", encrypted="ARCHER_ENCRYPTED")

        # Verify the calls were made
        mock_session.get.assert_called_once_with('http://tplinkwifi.net/webpages/js/libs/')
        assert mock_session.post.call_count == 2

        # Reset mocks for individual tests
        mock_session.get.reset_mock()
        mock_session.post.reset_mock()
        mock_session.post.side_effect = None
        # Set default return value to a MagicMock that tests can configure
        default_response = MagicMock()
        default_response.text = ''
        default_response.json.return_value = {}
        default_response.raise_for_status = MagicMock()
        mock_session.get.return_value = default_response
        mock_session.post.return_value = default_response

        yield router, mock_session.get, mock_session.post


# ===== Tests for timestamp =====

def test_get_timestamp_ok(router_instance):
    """Test that timestamp is correctly extracted from mock response."""
    router, _, _ = router_instance
    assert router.time_stamp == "987654321"


def test_get_timestamp_ko_maxretryerror(router_instance, caplog):
    """Test timestamp retrieval fails with MaxRetryError."""
    router, mock_get, _ = router_instance
    mock_get.side_effect = MaxRetryError(None, "modemUrl", "mockException")
    with caplog.at_level('ERROR'):
        result = router.get_timestamp()
        assert result == ''
        assert "mockException" in caplog.text


def test_get_timestamp_ko_gaierror(router_instance, caplog):
    """Test timestamp retrieval fails with gaierror."""
    router, mock_get, _ = router_instance
    mock_get.side_effect = gaierror()
    with caplog.at_level('ERROR'):
        result = router.get_timestamp()
        assert result == ''
        assert "dns resolution error" in caplog.text.lower()


def test_get_timestamp_ko_connectionerror(router_instance):
    """Test timestamp retrieval fails with ConnectionError."""
    router, mock_get, _ = router_instance
    mock_get.side_effect = ConnectionError()
    assert router.get_timestamp() == ''


# ===== Tests for JSON POST =====

def test_get_jsonfrompost_when_error_404(router_instance):
    """Test JSON POST returns False on 404 error."""
    router, _, mock_post = router_instance
    mock_post.return_value = _create_response(404, b'{}')

    my_data = {'operation': 'read'}
    my_url = "https://tplinkwifi.net/cgi-bin/luci/;stok=/login?form=cloud_login"

    ret = router.get_jsonfrompost(url=my_url, data=my_data)
    assert ret['success'] is False
    mock_post.assert_called_once_with(my_url, my_data)


# ===== Tests for cloud login =====

def test_login_with_cloud_login_failed_empty_login(router_instance):
    """Test cloud login fails with empty login."""
    router, _, _ = router_instance
    with pytest.raises(SystemExit):
        router.cloud_login('', None)


def test_login_with_cloud_login_ok(router_instance):
    """Test cloud login succeeds and sets token."""
    router, _, mock_post = router_instance
    mock_post.return_value = _create_response(200,
        b'{"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}')
    router.cloud_login("user1", "pass1")
    assert router.vectors is None
    assert router.token == "mocked_token"


def test_login_with_cloud_login_failed(router_instance):
    """Test cloud login fails."""
    router, _, mock_post = router_instance
    mock_post.return_value = _create_response(200,
        b'{"errorcode":"login failed","success":false,"data":{"errorcode":"-20601"}}')
    router.cloud_login("user1", "pass1")
    assert router.vectors is None
    assert router.token is None


# ===== Tests for local login =====

def test_login_with_local_login_failed(router_instance):
    """Test local login fails."""
    router, _, mock_post = router_instance
    mock_post.return_value = _create_response(200,
        b'{"errorcode":"login failed","success":false,"data":{"errorcode":"-20601"}}')
    router.local_login(password="Password")
    assert router.vectors is None
    assert router.token is None


def test_login_with_local_login_ok(router_instance):
    """Test local login succeeds."""
    router, _, mock_post = router_instance
    router.vectors = ''
    router.token = ''
    dstatus = {"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))

    router.local_login(password="Password")
    assert router.vectors == "V_SECRET"
    assert router.token == "mocked_token"


# ===== Tests for status fields =====

def test_get_cpu_usage(router_instance):
    """Test CPU usage extraction."""
    router, _, mock_post = router_instance
    dstatus = {'success': True, 'data': {'cpu_usage': 0.33}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert router.get_cpu_usage() == 0.33


def test_get_mem_usage(router_instance):
    """Test memory usage extraction."""
    router, _, mock_post = router_instance
    dstatus = {'success': True, 'data': {'mem_usage': 0.28}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert router.get_mem_usage() == 0.28


def test_get_wan_ip(router_instance):
    """Test WAN IP extraction."""
    router, _, mock_post = router_instance
    dstatus = {'success': True, 'data': {'wan_ipv4_ipaddr': '2.2.2.2'}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert router.get_wan_ip() == "2.2.2.2"


def test_get_lan_ip(router_instance):
    """Test LAN IP extraction."""
    router, _, mock_post = router_instance
    dstatus = {'success': True, 'data': {'lan_ipv4_ipaddr': '192.168.0.1'}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert router.get_lan_ip() == "192.168.0.1"


# ===== Tests for status endpoints =====

def test_get_internet_status(router_instance):
    """Test internet status extraction."""
    router, _, mock_post = router_instance
    dstatus = {
        'success': True,
        'data': {
            'lan_ipv4_dhcp_enable': 'On',
            'lan_macaddr': '50-98',
            'wan_ipv4_snddns': '1.1.1.1',
            'wan_macaddr': '50-99',
            'wan_ipv4_pridns': '2.2.2.2',
            'wan_ipv4_gateway': '4.4.4.4',
            'wan_ipv4_netmask': '255.255.254.0',
            'lan_ipv4_netmask': '255.255.255.0',
            'wan_ipv4_ipaddr': '5.5.5.5',
            'wan_ipv4_conntype': 'dhcp',
            'lan_ipv4_ipaddr': '192.168.0.1'
        }
    }
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert str(dstatus['data']) == str(router.get_internet_status())
    mock_post.assert_called_once_with(
        'http://tplinkwifi.net/cgi-bin/luci/;stok=mocked_token/admin/status?form=internet',
        {'operation': 'read'}
    )


def test_get_dyn_dns(router_instance):
    """Test dynamic DNS extraction."""
    router, _, mock_post = router_instance
    dstatus = {
        'success': 'true',
        'data': {
            "pri_dns": "1.1.1.1",
            "mtu": "1500",
            "manual_snddns": "2.2.2.2",
            "dns_mode": "static",
            "hostname": "modem",
            "manual_pridns": "3.3.3.3",
            "snd_dns": "4.4.4.4",
            "link_status": "plugged",
            "nonaddress_support": 0,
            "mac_clone_type": "default",
            "conntype": "dhcp",
            "netmask": "255.255.254.0",
            "conn_status": "connected",
            "ipaddr": "6.6.6.6",
            "dyn_pridns": "0.0.0.0",
            "gateway": "5.5.5.5",
            "dyn_snddns": "0.0.0.0",
            "unicast": "off",
            "pppshare": 3
        }
    }
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert dstatus['data'] == router.get_dyn_dns()


def test_get_locale(router_instance):
    """Test locale extraction."""
    router, _, mock_post = router_instance
    dstatus = {
        'success': 'true',
        'data': {
            "locale": "fr_FR",
            "force": "false",
            "region_select_permission": "yes",
            "model": "Wireless Router Archer C1200"
        }
    }
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert dstatus['data'] == router.get_locale()


def test_get_router_mode(router_instance):
    """Test router mode extraction."""
    router, _, mock_post = router_instance
    dstatus = {'success': 'true', 'data': {'support': 'yes', 'mode': 'router'}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert dstatus['data'] == router.get_router_mode()


def test_get_firmware(router_instance):
    """Test firmware info extraction."""
    router, _, mock_post = router_instance
    dstatus = {
        'success': 'true',
        'data': {
            "hardware_version": "Archer C1200 v2.0",
            "model": "Archer C1200",
            "totaltime": 90,
            "is_default": 'false',
            "firmware_version": "2.0.2 Build 20180118 rel.38979 (EU)"
        }
    }
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert dstatus['data'] == router.get_firmware()


def test_get_cloud_support(router_instance):
    """Test cloud support extraction."""
    router, _, mock_post = router_instance
    dstatus = {'success': 'true', 'data': {"cloud_support": "yes"}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert dstatus['data']["cloud_support"] == router.get_cloud_support()


def test_get_cloud_status(router_instance):
    """Test cloud status extraction."""
    router, _, mock_post = router_instance
    dstatus = {'success': 'true', 'data': {"islogined": "yes"}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert dstatus['data']["islogined"] == router.get_cloud_status()


def test_get_led_status(router_instance):
    """Test LED status extraction."""
    router, _, mock_post = router_instance
    dstatus = {'success': 'true', 'data': {'enable': 'on', 'ledpm_support': 'yes', 'time_set': 'yes'}}
    mock_post.return_value = _create_response(200, json.dumps(dstatus).encode('utf-8'))
    assert str(dstatus['data']) == str(router.get_led_status())
