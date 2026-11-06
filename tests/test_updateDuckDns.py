"""Unit tests for updateDuckDns module using pytest."""
import os
import sys
import pytest
import tempfile
import shutil
from datetime import datetime
from unittest.mock import MagicMock, patch, mock_open as unittest_mock_open

# Import module under test - add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import updateDuckDns
from archer1200.archer1200 import Archer1200


patcher_archer = MagicMock(spec=Archer1200)
duckdns_fqdn = 'omvholblack.duckdns.org'


# ============================================================================
# Helper for mocking file operations
# ============================================================================

class CustomMockOpen:
    """Custom mock for open() function."""
    def __init__(self, read_data=''):
        self.read_data = read_data
        self.written_data = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return self.read_data

    def readlines(self):
        return self.read_data.split('\n') if self.read_data else []

    def write(self, data):
        self.written_data.append(data)
        return len(data)

    def writelines(self, lines):
        self.written_data.extend(lines)
        return len(lines)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def timeout_file(temp_dir):
    """Create a temporary timeout file."""
    timeout_path = os.path.join(temp_dir, 'timeout')
    return timeout_path


@pytest.fixture(autouse=True)
def setup_log_dir():
    """Fixture to set up log_dir for all tests in this module."""
    updateDuckDns.log_dir = "/tmp"
    yield


# ============================================================================
# Tests for duckdns update
# ============================================================================

def test_check_duckdns_update():
    """Test duckdns update when update is needed."""
    with patch('updateDuckDns.datetime') as date_mock, \
         patch('updateDuckDns.logger') as log_mock, \
         patch('duckdns.DuckDns', autospec=True) as duck_mock, \
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
         patch('duckdns.DuckDns', autospec=True) as duck_mock, \
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


# ============================================================================
# Tests for noip update
# ============================================================================

def test_check_noip_update_performed():
    """Test noip update when update is performed."""
    with patch('socket.gethostbyname') as socket_mock, \
         patch('noip.noip.NoIp') as noip_mock:

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
         patch('noip.noip.NoIp') as noip_mock:

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


# ============================================================================
# Tests for send_mail function
# ============================================================================

class TestSendMail:
    """Tests for send_mail function."""

    def test_send_mail_empty_message(self):
        """Test that send_mail returns early when message is empty."""
        # Should not raise any exception
        updateDuckDns.send_mail(title='Test', message='', hostname='testhost', run_by_cron=True)

    def test_send_mail_not_run_by_cron(self, capsys):
        """Test send_mail when not run by cron (prints message)."""
        with patch('builtins.print') as mock_print:
            updateDuckDns.send_mail(
                title='Test',
                message='Test message',
                hostname='testhost',
                run_by_cron=False
            )
            # Should print the message
            mock_print.assert_called()

    @patch('smtplib.SMTP_SSL')
    @patch('ssl.create_default_context')
    @patch('ssl._create_unverified_context')
    @patch('email.utils.formatdate')
    def test_send_mail_run_by_cron_success(self, mock_formatdate, mock_unverified_ctx, mock_default_ctx, mock_smtp_ssl):
        """Test send_mail when run by cron with successful SMTP connection."""
        mock_formatdate.return_value = 'Test Date'
        mock_default_ctx.return_value = MagicMock()
        mock_unverified_ctx.return_value = MagicMock()

        mock_smtp = MagicMock()
        mock_smtp_ssl.return_value = mock_smtp

        # Set required globals
        updateDuckDns.eml_from = 'test@example.com'
        updateDuckDns.eml_to = 'recipient@example.com'
        updateDuckDns.smtp_server = 'smtp.example.com'
        updateDuckDns.smtp_port = 587
        updateDuckDns.smtp_user = 'user'
        updateDuckDns.smtp_pass = 'pass'

        with patch('socket.gethostname', return_value='testhost'):
            with patch('builtins.print'):
                updateDuckDns.send_mail(
                    title='Test',
                    message='Test message',
                    hostname='testhost',
                    run_by_cron=True
                )

        # Verify SMTP calls
        mock_smtp_ssl.assert_called_once()
        mock_smtp.login.assert_called_once_with('user', 'pass')
        mock_smtp.send_message.assert_called_once()
        mock_smtp.quit.assert_called_once()

    @patch('smtplib.SMTP_SSL')
    @patch('ssl._create_unverified_context')
    @patch('ssl.create_default_context')
    @patch('builtins.print')
    def test_send_mail_gaierror_fallback(self, mock_print, mock_default_ctx, mock_unverified_ctx, mock_smtp_ssl):
        """Test send_mail falls back to smtp_server_ip when socket.gaierror occurs."""
        import socket
        mock_default_ctx.return_value = MagicMock()
        mock_unverified_ctx.return_value = MagicMock()

        # First call raises gaierror, second call (fallback) succeeds
        mock_smtp = MagicMock()
        mock_smtp_ssl.side_effect = [socket.gaierror("Name resolution failed"), mock_smtp]

        # Set required globals
        updateDuckDns.eml_from = 'test@example.com'
        updateDuckDns.eml_to = 'recipient@example.com'
        updateDuckDns.smtp_server = 'smtp.example.com'
        updateDuckDns.smtp_server_ip = '192.168.1.1'
        updateDuckDns.smtp_port = 587
        updateDuckDns.smtp_user = 'user'
        updateDuckDns.smtp_pass = 'pass'

        with patch('socket.gethostname', return_value='testhost'):
            updateDuckDns.send_mail(
                title='Test',
                message='Test message',
                hostname='testhost',
                run_by_cron=True
            )

        # Should have tried both servers
        assert mock_smtp_ssl.call_count == 2
        # Second call should be to IP
        second_call = mock_smtp_ssl.call_args_list[1]
        assert '192.168.1.1' in str(second_call)

    @patch('smtplib.SMTP_SSL')
    @patch('ssl.create_default_context')
    @patch('builtins.print')
    def test_send_mail_smtp_exception(self, mock_print, mock_default_ctx, mock_smtp_ssl):
        """Test send_mail handles SMTPException gracefully."""
        import smtplib
        mock_default_ctx.return_value = MagicMock()
        mock_smtp = MagicMock()
        mock_smtp.send_message.side_effect = smtplib.SMTPException("SMTP error")
        mock_smtp_ssl.return_value = mock_smtp

        # Set required globals
        updateDuckDns.eml_from = 'test@example.com'
        updateDuckDns.eml_to = 'recipient@example.com'
        updateDuckDns.smtp_server = 'smtp.example.com'
        updateDuckDns.smtp_port = 587
        updateDuckDns.smtp_user = 'user'
        updateDuckDns.smtp_pass = 'pass'

        with patch('socket.gethostname', return_value='testhost'):
            updateDuckDns.send_mail(
                title='Test',
                message='Test message',
                hostname='testhost',
                run_by_cron=True
            )

        mock_print.assert_called_once()
        # Verify exception object was printed
        call_args = mock_print.call_args[0][0]
        assert isinstance(call_args, smtplib.SMTPException)


# ============================================================================
# Tests for remove_host_from_timeout function
# ============================================================================

class TestRemoveHostFromTimeout:
    """Tests for remove_host_from_timeout function."""

    def test_remove_host_from_timeout_file_not_exists(self, timeout_file):
        """Test when timeout file does not exist."""
        result = updateDuckDns.remove_host_from_timeout(timeout_file, 'testhost')
        # Should not raise any exception
        assert result is None

    def test_remove_host_from_timeout_file_too_old(self, timeout_file, temp_dir):
        """Test when timeout file is older than one day."""
        # Create an old timeout file
        old_time = datetime.now().timestamp() - 86400 - 1  # 1 day + 1 second old
        with open(timeout_file, 'w') as f:
            f.write('testhost\t20230101_120000\tsome error\n')

        # Mock the file creation time to be old
        with patch('os.path.getctime', return_value=old_time):
            updateDuckDns.remove_host_from_timeout(timeout_file, 'testhost')

        # File should be deleted
        assert not os.path.exists(timeout_file)

    def test_remove_host_from_timeout_host_removed(self, timeout_file, temp_dir):
        """Test removing a host from timeout file."""
        # Create timeout file with multiple hosts
        with open(timeout_file, 'w') as f:
            f.write('host1\t20230101_120000\terror1\n')
            f.write('host2\t20230101_120000\terror2\n')
            f.write('host3\t20230101_120000\terror3\n')

        updateDuckDns.remove_host_from_timeout(timeout_file, 'host2')

        # Verify host2 is removed
        with open(timeout_file, 'r') as f:
            content = f.read()
        assert 'host2' not in content
        assert 'host1' in content
        assert 'host3' in content

    def test_remove_host_from_timeout_last_host_removed(self, timeout_file, temp_dir):
        """Test removing the last host deletes the file."""
        # Create timeout file with one host
        with open(timeout_file, 'w') as f:
            f.write('host1\t20230101_120000\terror1\n')

        updateDuckDns.remove_host_from_timeout(timeout_file, 'host1')

        # File should be deleted
        assert not os.path.exists(timeout_file)

    def test_remove_host_from_timeout_host_not_present(self, timeout_file, temp_dir):
        """Test removing a host that is not in the file."""
        # Create timeout file with one host
        with open(timeout_file, 'w') as f:
            f.write('host1\t20230101_120000\terror1\n')

        updateDuckDns.remove_host_from_timeout(timeout_file, 'host2')

        # File should still exist with original content
        with open(timeout_file, 'r') as f:
            content = f.read()
        assert 'host1' in content


# ============================================================================
# Tests for add_host_to_timeout function
# ============================================================================

class TestAddHostToTimeout:
    """Tests for add_host_to_timeout function."""

    def test_add_host_to_timeout_new_file(self, timeout_file):
        """Test adding a host to a new timeout file."""
        result = updateDuckDns.add_host_to_timeout(timeout_file, 'testhost', Exception('Test error'))

        assert result is True
        assert os.path.exists(timeout_file)
        with open(timeout_file, 'r') as f:
            content = f.read()
        assert 'testhost' in content

    def test_add_host_to_timeout_file_too_old(self, timeout_file, temp_dir):
        """Test adding to a timeout file that is too old."""
        # Create an old timeout file
        old_time = datetime.now().timestamp() - 86400 - 1
        with open(timeout_file, 'w') as f:
            f.write('oldhost\t20230101_120000\told error\n')

        # Mock the file creation time to be old
        with patch('os.path.getctime', return_value=old_time):
            result = updateDuckDns.add_host_to_timeout(timeout_file, 'newhost', Exception('New error'))

        assert result is True
        # Old file should be deleted and new one created
        with open(timeout_file, 'r') as f:
            content = f.read()
        assert 'oldhost' not in content
        assert 'newhost' in content

    def test_add_host_to_timeout_already_present(self, timeout_file, temp_dir):
        """Test that host is not added if already present."""
        # Create timeout file with host
        with open(timeout_file, 'w') as f:
            f.write('testhost\t20230101_120000\tsome error\n')

        result = updateDuckDns.add_host_to_timeout(timeout_file, 'testhost', Exception('Another error'))

        assert result is False
        # Content should remain unchanged
        with open(timeout_file, 'r') as f:
            lines = f.readlines()
        assert len(lines) == 1  # No new line added

    def test_add_host_to_timeout_multiple_hosts(self, timeout_file, temp_dir):
        """Test adding multiple hosts to timeout file."""
        result1 = updateDuckDns.add_host_to_timeout(timeout_file, 'host1', Exception('Error 1'))
        result2 = updateDuckDns.add_host_to_timeout(timeout_file, 'host2', Exception('Error 2'))

        assert result1 is True
        assert result2 is True

        with open(timeout_file, 'r') as f:
            content = f.read()
        assert 'host1' in content
        assert 'host2' in content


# ============================================================================
# Tests for setup_arg_parser function
# ============================================================================

class TestSetupArgParser:
    """Tests for setup_arg_parser function."""

    def test_setup_arg_parser_defaults(self):
        """Test argument parser with default values."""
        # Set global servers variable
        updateDuckDns.servers = '8.8.8.8,8.8.4.4'

        with patch('argparse.ArgumentParser') as mock_parser_class:
            mock_parser = MagicMock()
            mock_args = MagicMock()
            mock_args.clear = False
            mock_args.dryrun = False
            mock_args.force = False
            mock_args.txt = None
            mock_args.silent = False
            mock_args.domains = None
            mock_args.resolve = False
            mock_args.auth = None
            mock_args.verbose = False
            mock_parser.parse_args.return_value = mock_args
            mock_parser_class.return_value = mock_parser

            with patch('sys.argv', ['updateDuckDns.py']):
                args = updateDuckDns.setup_arg_parser()

        assert args.clear is False
        assert args.dryrun is False
        assert args.force is False
        assert args.txt is None
        assert args.silent is False
        assert args.domains is None
        assert args.resolve is False
        assert args.auth is None
        assert args.verbose is False

    def test_setup_arg_parser_with_flags(self):
        """Test argument parser with various flags."""
        # Set global servers variable
        updateDuckDns.servers = '8.8.8.8,8.8.4.4'

        with patch('argparse.ArgumentParser') as mock_parser_class:
            mock_parser = MagicMock()
            mock_args = MagicMock()
            mock_args.clear = True
            mock_args.dryrun = True
            mock_args.force = True
            mock_args.silent = True
            mock_args.verbose = True
            mock_args.txt = None
            mock_args.domains = None
            mock_args.resolve = False
            mock_args.auth = None
            mock_parser.parse_args.return_value = mock_args
            mock_parser_class.return_value = mock_parser

            with patch('sys.argv', ['updateDuckDns.py', '-c', '-n', '-f', '-s', '-v']):
                args = updateDuckDns.setup_arg_parser()

        assert args.clear is True
        assert args.dryrun is True
        assert args.force is True
        assert args.silent is True
        assert args.verbose is True

    def test_setup_arg_parser_with_options(self):
        """Test argument parser with option values."""
        # Set global servers variable
        updateDuckDns.servers = '8.8.8.8,8.8.4.4'

        with patch('argparse.ArgumentParser') as mock_parser_class:
            mock_parser = MagicMock()
            mock_args = MagicMock()
            mock_args.clear = False
            mock_args.dryrun = False
            mock_args.force = False
            mock_args.silent = False
            mock_args.verbose = False
            mock_args.txt = 'test_txt'
            mock_args.domains = 'dom1,dom2'
            mock_args.resolve = False
            mock_args.auth = 'token123'
            mock_parser.parse_args.return_value = mock_args
            mock_parser_class.return_value = mock_parser

            with patch('sys.argv', ['updateDuckDns.py', '-t', 'test_txt', '-d', 'dom1,dom2', '-a', 'token123']):
                args = updateDuckDns.setup_arg_parser()

        assert args.txt == 'test_txt'
        assert args.domains == 'dom1,dom2'
        assert args.auth == 'token123'

    def test_setup_arg_parser_resolve_mode(self):
        """Test argument parser in resolve mode."""
        # Set global servers variable
        updateDuckDns.servers = '8.8.8.8,8.8.4.4'

        with patch('argparse.ArgumentParser') as mock_parser_class:
            mock_parser = MagicMock()
            mock_args = MagicMock()
            mock_args.clear = False
            mock_args.dryrun = False
            mock_args.force = False
            mock_args.silent = False
            mock_args.verbose = False
            mock_args.txt = None
            mock_args.domains = None
            mock_args.resolve = True
            mock_args.auth = None
            mock_parser.parse_args.return_value = mock_args
            mock_parser_class.return_value = mock_parser

            with patch('sys.argv', ['updateDuckDns.py', '-r']):
                args = updateDuckDns.setup_arg_parser()

        assert args.resolve is True


# ============================================================================
# Tests for check_servers function
# ============================================================================

class TestCheckServers:
    """Tests for check_servers function."""

    @patch('dns.resolver.Resolver')
    @patch('updateDuckDns.add_host_to_timeout')
    @patch('updateDuckDns.remove_host_from_timeout')
    def test_check_servers_success(self, mock_remove, mock_add, mock_resolver_class):
        """Test check_servers with successful DNS resolution."""
        # Setup mock resolver
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        mock_answer = MagicMock()
        mock_answer.rrset = '1.2.3.4'
        mock_resolver.resolve.return_value = mock_answer

        # Mock rr iteration
        mock_rr = MagicMock()
        mock_rr.to_text.return_value = '1.2.3.4'
        mock_answer.__iter__ = lambda self: iter([mock_rr])

        # Set global
        updateDuckDns.timeout_fname = '/tmp/timeout'

        result = updateDuckDns.check_servers(
            servers='8.8.8.8,8.8.4.4',
            name='www.free.fr',
            force=False,
            log_dir='/tmp',
            hostname='testhost',
            run_by_cron=True
        )

        mock_resolver.resolve.assert_called()
        mock_remove.assert_called()

    @patch('dns.resolver.Resolver')
    @patch('updateDuckDns.add_host_to_timeout')
    @patch('updateDuckDns.send_mail')
    @patch('builtins.open', new_callable=unittest_mock_open)
    def test_check_servers_timeout(self, mock_open_file, mock_send_mail, mock_add, mock_resolver_class):
        """Test check_servers with DNS timeout."""
        import dns.exception

        # Setup mock resolver
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()

        # Set globals
        updateDuckDns.timeout_fname = '/tmp/timeout'
        updateDuckDns.RUN_BY_CRON = False

        result = updateDuckDns.check_servers(
            servers='8.8.8.8',
            name='www.free.fr',
            force=False,
            log_dir='/tmp',
            hostname='testhost',
            run_by_cron=False
        )

        mock_add.assert_called_once()

    @patch('dns.resolver.Resolver')
    def test_check_servers_empty_server(self, mock_resolver_class, capsys):
        """Test check_servers with empty server in list."""
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        with patch('logging.Logger.warning') as mock_warning:
            result = updateDuckDns.check_servers(
                servers='8.8.8.8,,8.8.4.4',
                name='www.free.fr',
                force=False,
                log_dir='/tmp',
                hostname='testhost',
                run_by_cron=False
            )

        mock_warning.assert_called()


# ============================================================================
# Tests for getArcher function
# ============================================================================

class TestGetArcher:
    """Tests for getArcher function."""

    @patch('updateDuckDns.Archer1200')
    @patch('updateDuckDns.send_mail')
    def test_get_archer_cannot_connect(self, mock_send_mail, mock_archer_class):
        """Test getArcher when cannot connect to router."""
        mock_archer = MagicMock()
        mock_archer.get_timestamp.return_value = ''
        mock_archer_class.return_value = mock_archer

        # Set globals
        updateDuckDns.ARCHER_LOGIN = 'test_login'
        updateDuckDns.ARCHER_ENCRYPTED = 'test_encrypted'
        updateDuckDns.ARCHER_URL = 'http://test.url'
        updateDuckDns.RUN_BY_CRON = False
        updateDuckDns.hostname = 'testhost'

        with pytest.raises(SystemExit) as exc_info:
            updateDuckDns.getArcher()

        assert exc_info.value.code == 1
        mock_send_mail.assert_called_once()

    @patch('updateDuckDns.Archer1200')
    @patch('sys.exit')
    def test_get_archer_no_internet(self, mock_exit, mock_archer_class):
        """Test getArcher when no internet connection."""
        mock_archer = MagicMock()
        mock_archer.get_timestamp.return_value = 'timestamp'
        mock_archer.get_internet_status.return_value = 'disconnected'
        mock_archer_class.return_value = mock_archer

        # Set globals
        updateDuckDns.ARCHER_LOGIN = 'test_login'
        updateDuckDns.ARCHER_ENCRYPTED = 'test_encrypted'
        updateDuckDns.ARCHER_URL = 'http://test.url'

        result = updateDuckDns.getArcher()

        assert result is False
        mock_exit.assert_not_called()

    @patch('updateDuckDns.Archer1200')
    def test_get_archer_success(self, mock_archer_class):
        """Test getArcher with successful IP retrieval."""
        mock_archer = MagicMock()
        mock_archer.get_timestamp.return_value = 'timestamp'
        mock_archer.get_internet_status.return_value = 'connected'
        mock_archer.get_wan_ip.return_value = '1.2.3.4'
        mock_archer.logout.return_value = None
        mock_archer_class.return_value = mock_archer

        # Set globals
        updateDuckDns.ARCHER_LOGIN = 'test_login'
        updateDuckDns.ARCHER_ENCRYPTED = 'test_encrypted'
        updateDuckDns.ARCHER_URL = 'http://test.url'

        result = updateDuckDns.getArcher()

        assert result == '1.2.3.4'
        mock_archer.logout.assert_called_once()
