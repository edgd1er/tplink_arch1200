"""Unit tests for duckdns.DuckDns module using pytest."""
import pytest
from unittest.mock import patch, call, mock_open, MagicMock
import socket

from requests import Response

from duckdns import DuckDns


@pytest.fixture
def duckdns_instance():
    """Fixture providing a DuckDns instance with default parameters."""
    return DuckDns(
        token='myToken',
        domains='domain1,domain2,domain3',
        ip='1.2.3.4',
        force=False,
        clear=True,
        txt='myText',
        ip6='my_ip6',
        dry_run=True
    )


# ===== Tests for external IP =====

def test_get_external_ip(duckdns_instance):
    """Test external IP retrieval from httpbin.org."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {'origin': '4.5.6.7'}

        currentip = duckdns_instance.get_external_ip()

        assert currentip == '4.5.6.7'
        mock_get.assert_called_once_with("http://httpbin.org/ip")


def test_get_external_ip2(duckdns_instance):
    """Test external IP retrieval from myexternalip.com."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.text = '4.5.6.7'

        currentip = duckdns_instance.get_external_ip2()

        assert currentip == '4.5.6.7'
        mock_get.assert_called_once_with("http://myexternalip.com/raw")


# ===== Tests for DNS check =====

def test_check_false(duckdns_instance):
    """Test DNS check returns False when IPs do not match."""
    with patch('builtins.open', mock_open(read_data='')), \
         patch('socket.gethostbyname', autospec=True) as socket_mock:
        socket_mock.side_effect = ['1.2.3.4', '1.2.3.4', '1.2.3.4']

        ret = duckdns_instance.check()

        assert ret is False
        socket_mock.assert_has_calls([
            call('domain1.duckdns.org'),
            call('domain2.duckdns.org'),
            call('domain3.duckdns.org')
        ], any_order=False)


def test_check_true(duckdns_instance):
    """Test DNS check returns True when IPs match."""
    with patch('builtins.open', mock_open(read_data='')), \
         patch('socket.gethostbyname', autospec=True) as socket_mock:
        socket_mock.side_effect = ['4.3.2.1', '4.3.2.1', '4.3.2.1']

        ret = duckdns_instance.check()

        assert ret is True
        socket_mock.assert_has_calls([
            call('domain1.duckdns.org'),
            call('domain2.duckdns.org'),
            call('domain3.duckdns.org')
        ], any_order=False)


# ===== Tests for update =====

def test_update_no_params_dryrun_true(duckdns_instance):
    """Test update returns early when dry_run is True."""
    with patch('requests.get') as mock_get:
        duckdns_instance.dry_run = True

        res = duckdns_instance.update()

        assert res == 'DRYRUN, no update performed'
        assert mock_get.call_count == 0


def test_update_no_params_dryrun_false(duckdns_instance):
    """Test update performs request when dry_run is False."""
    with patch('requests.get') as mock_get:
        duckdns_instance.dry_run = False
        ret = 'OK'
        mock_get.return_value.text = ret

        res = duckdns_instance.update()

        expected_params = {
            "domains": duckdns_instance.domains,
            "token": duckdns_instance.token,
            "ip": duckdns_instance.ip,
            "verbose": False,
            "clear": duckdns_instance.clear,
            "txt": duckdns_instance.txt
        }

        assert res == ret
        assert mock_get.call_count == 1
        mock_get.assert_called_once_with(duckdns_instance.duckdns_url, expected_params, timeout=10)
