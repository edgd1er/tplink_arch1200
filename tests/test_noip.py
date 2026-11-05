"""Unit tests for noip.NoIp module using pytest."""
import pytest
from unittest.mock import patch, call, mock_open
import socket
import requests
from requests import Response

from src.noip.noip import NoIp


@pytest.fixture
def noip_instance():
    """Fixture providing a NoIp instance with default parameters."""
    return NoIp(
        login='myLogin',
        passwd='myPassword',
        hosts='noip.domain.com,second.domain.com',
        dry_run=True,
        ip="1.2.3.4",
        force=False
    )


# ===== Tests for external IP =====

def test_get_external_ip_ok(noip_instance):
    """Test external IP retrieval succeeds."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {'origin': '4.5.6.7'}

        currentip = noip_instance.get_external_ip()

        assert currentip == '4.5.6.7'
        mock_get.assert_called_once_with("http://httpbin.org/ip")


def test_get_external_ip_ko(noip_instance):
    """Test external IP retrieval returns different IP."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {'origin': '4.5.6.8'}

        currentip = noip_instance.get_external_ip()

        assert currentip != '4.5.6.7'
        mock_get.assert_called_once_with("http://httpbin.org/ip")


def test_get_external_ip2_ok(noip_instance):
    """Test external IP retrieval from myexternalip.com succeeds."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.text = '4.5.6.7'

        currentip = noip_instance.get_external_ip2()

        assert currentip == '4.5.6.7'
        mock_get.assert_called_once_with("http://myexternalip.com/raw")


def test_get_external_ip2_ko(noip_instance):
    """Test external IP retrieval from myexternalip.com returns different IP."""
    with patch('requests.get') as mock_get:
        mock_get.return_value.text = '4.5.6.8'

        currentip = noip_instance.get_external_ip2()

        assert currentip != '4.5.6.7'
        mock_get.assert_called_once_with("http://myexternalip.com/raw")


# ===== Tests for DNS check =====

def test_check_false(noip_instance):
    """Test DNS check returns False when IPs do not match."""
    with patch('builtins.open', mock_open(read_data='')), \
         patch('socket.gethostbyname', autospec=True) as socket_mock:
        socket_mock.side_effect = ['1.2.3.4', '1.2.3.4']

        ret = noip_instance.check()

        assert ret is False
        socket_mock.assert_has_calls([
            call('noip.domain.com'),
            call('second.domain.com')
        ], any_order=False)


def test_check_true(noip_instance):
    """Test DNS check returns True when IPs match."""
    with patch('builtins.open', mock_open(read_data='')), \
         patch('socket.gethostbyname', autospec=True) as socket_mock:
        socket_mock.side_effect = ['1.2.3.4', '5.6.7.8']

        ret = noip_instance.check()

        assert ret is True
        socket_mock.assert_has_calls([
            call('noip.domain.com'),
            call('second.domain.com')
        ], any_order=False)


# ===== Tests for update =====

def test_update_no_params_dryrun_true(noip_instance):
    """Test update returns early when dry_run is True."""
    with patch('requests.get') as mock_get:
        noip_instance.dry_run = True

        res = noip_instance.update()

        assert res == 'DRYRUN, nothing performed'
        assert mock_get.call_count == 0


def test_update_no_params_dryrun_false(noip_instance):
    """Test update performs request when dry_run is False."""
    with patch('requests.get') as mock_get:
        noip_instance.dry_run = False
        ret = 'OK'
        mock_get.return_value.status_code = requests.codes.ok
        mock_get.return_value.content = b'OK'

        res = noip_instance.update()

        params = {
            "b64creds": 'b64',
            "hostname": noip_instance.hosts,
            "myip": noip_instance.ip
        }

        assert res == ret
        assert mock_get.call_count == 1
        mock_get.assert_called_once_with(
            'http://{}@dynupdate.no-ip.com/nic/update?hostname={}&myip={}'.format(*params)
        )
