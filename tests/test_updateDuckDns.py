"""Unit tests for updateDuckDns module using pytest."""
import pytest
from unittest.mock import patch, Mock, call

import updateDuckDns
from src.archer1200.archer1200 import Archer1200


patcher_archer = Mock(spec=Archer1200)
duckdns_fqdn = 'omvholblack.duckdns.org'


@pytest.fixture(autouse=True)
def setup_log_dir():
    """Fixture to set up log_dir for all tests in this module."""
    updateDuckDns.log_dir = "/tmp"
    yield


# ===== Tests for duckdns update =====

def test_check_duckdns_update():
    """Test duckdns update when update is needed."""
    with patch('updateDuckDns.datetime') as date_mock, \
         patch('updateDuckDns.logger') as log_mock, \
         patch('updateDuckDns.duckdns.DuckDns', autospec=True) as duck_mock, \
         patch('builtins.open') as open_mock:

        date_mock.now.return_value.strftime.return_value = 'NOW.log'
        duck_mock.return_value.check_and_update.return_value = 'updating with 1.2.3.4'
        
        log_dir = '/tmp'
        res = updateDuckDns.check_duckdns(
            token='DUCK_TOKEN',
            domains='DOMAINS',
            force=False,
            ip='1.2.3.4',
            txt='txt',
            dry_run=False,
            log_dir=log_dir,
            run_by_cron=False
        )

        assert res == 'updating with 1.2.3.4'
        open_mock.assert_called()
        log_mock.error.assert_not_called()
        log_mock.debug.assert_called()
        log_mock.info.assert_called_with('updating with 1.2.3.4 written to /tmp/NOW.log, force: False')


def test_check_duckdns_no_update():
    """Test duckdns update when no update is needed."""
    with patch('updateDuckDns.datetime') as date_mock, \
         patch('updateDuckDns.logger') as log_mock, \
         patch('updateDuckDns.duckdns.DuckDns', autospec=True) as duck_mock, \
         patch('builtins.open') as open_mock:

        duck_mock.return_value.check_and_update.return_value = ''
        
        log_dir = '/tmp'
        res = updateDuckDns.check_duckdns(
            token='DUCK_TOKEN',
            domains='DOMAINS',
            force=False,
            ip='1.2.3.4',
            txt='txt',
            dry_run=False,
            log_dir=log_dir
        )

        assert res is False
        open_mock.assert_not_called()
        date_mock.assert_not_called()


# ===== Tests for noip update =====

def test_check_noip_update_performed():
    """Test noip update when update is performed."""
    with patch('socket.gethostbyname') as socket_mock, \
         patch('updateDuckDns.NoIp') as noip_mock:

        noip_mock.return_value.check_and_update.return_value = 'update needed'
        socket_mock.return_value = "1.2.3.4"
        
        res = updateDuckDns.check_noip(
            login='NOIP_LOGIN',
            passwd='NOIP_PASSWD',
            hosts='NOIP_HOSTS',
            ip='1234'
        )

        assert res is True
        noip_mock.assert_called()


def test_check_noip_no_update():
    """Test noip update when no update is needed."""
    with patch('socket.gethostbyname') as socket_mock, \
         patch('updateDuckDns.NoIp') as noip_mock:

        noip_mock.return_value.check_and_update.return_value = 'No update needed'
        socket_mock.return_value = "1.2.3.4"
        
        res = updateDuckDns.check_noip(
            login='NOIP_LOGIN',
            passwd='NOIP_PASSWD',
            hosts='NOIP_HOSTS',
            ip='1.2.3.4'
        )

        assert res is False
        noip_mock.assert_called()
