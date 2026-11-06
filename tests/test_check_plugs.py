"""Unit tests for check_plugs module using pytest."""
import http.client
import sys
from unittest.mock import MagicMock, patch, AsyncMock
from urllib.parse import urlparse

# Import pytest first
import pytest

# Ensure we can import asyncio on older Python versions
if sys.version_info >= (3, 8):
    import asyncio

# Now import the module under test (dependencies should be installed)
from check_plugs.check_plugs import (
    HostsConfig,
    config_to_list,
    getConfigFromTarget,
    getConfigFromMeriossName,
    get_host_status,
    send_mail,
)


# ===== Fixtures =====

@pytest.fixture
def sample_hosts_config():
    """Fixture providing sample hosts_config list."""
    import check_plugs.check_plugs as check_plugs_module
    original = check_plugs_module.hosts_config.copy() if hasattr(check_plugs_module, 'hosts_config') else []
    check_plugs_module.hosts_config = [
        HostsConfig('plug1', '192.168.1.1', 'Meross Plug 1', 'https://plug1.local'),
        HostsConfig('plug2', '192.168.1.2', 'Meross Plug 2', 'https://plug2.local'),
        HostsConfig('plug3', '192.168.1.3', 'Meross Plug 3', 'https://plug3.local'),
    ]
    yield check_plugs_module.hosts_config
    check_plugs_module.hosts_config = original


@pytest.fixture(autouse=True)
def reset_global_vars():
    """Reset global variables before and after each test."""
    import check_plugs.check_plugs as check_plugs_module

    # Save original values (handle case where they don't exist yet)
    orig_hosts_config = check_plugs_module.hosts_config
    orig_to_process = check_plugs_module.to_process
    orig_logger = check_plugs_module.logger
    orig_ldir = check_plugs_module.LDIR

    # Reset for test
    check_plugs_module.hosts_config = []
    check_plugs_module.to_process = []
    check_plugs_module.logger = MagicMock()
    check_plugs_module.LDIR = '/mock/dir'

    yield

    # Restore original values
    check_plugs_module.hosts_config = orig_hosts_config
    check_plugs_module.to_process = orig_to_process
    check_plugs_module.logger = orig_logger
    check_plugs_module.LDIR = orig_ldir


# ===== Tests for HostsConfig class =====

class TestHostsConfig:
    """Tests for HostsConfig class."""

    def test_hosts_config_init(self):
        """Test HostsConfig initialization."""
        hc = HostsConfig('test', '192.168.1.1', 'Test Plug', 'https://test.local')

        assert hc.shortname == 'test'
        assert hc.name == 'Test Plug'
        assert hc.host == '192.168.1.1'
        assert hc.url == 'https://test.local'

    def test_hosts_config_url_property(self):
        """Test HostsConfig URL property getter and setter."""
        hc = HostsConfig('test', '192.168.1.1', 'Test Plug', 'https://test.local')

        assert hc.get_url() == 'https://test.local'

        hc.set_url('https://new.local')
        assert hc.get_url() == 'https://new.local'
        assert hc.url == 'https://new.local'


# ===== Tests for config_to_list =====

class TestConfigToList:
    """Tests for config_to_list function."""

    def test_config_to_list_populates_hosts_config(self):
        """Test that config_to_list populates hosts_config list."""
        import check_plugs.check_plugs as check_plugs_module
        # Create a mock config object
        mock_config = {
            'hosts': {
                'plug1': '"Plug 1","Meross Plug 1","https://plug1.local"',
                'plug2': '"Plug 2","Meross Plug 2","https://plug2.local"',
                'plug3': '"Plug 3","Meross Plug 3","https://plug3.local"',
            }
        }

        # Set the config global variable
        check_plugs_module.config = mock_config

        config_to_list()

        assert len(check_plugs_module.hosts_config) == 3
        assert isinstance(check_plugs_module.hosts_config[0], HostsConfig)


# ===== Tests for getConfigFromTarget =====

class TestGetConfigFromTarget:
    """Tests for getConfigFromTarget function."""

    def test_get_config_from_target_found(self, sample_hosts_config):
        """Test finding a host by shortname."""
        result = getConfigFromTarget('plug1')

        assert result is not None
        assert result.shortname == 'plug1'
        assert result.name == 'Meross Plug 1'

    def test_get_config_from_target_not_found(self, sample_hosts_config):
        """Test that None is returned when target not found."""
        result = getConfigFromTarget('nonexistent')

        assert result is None


# ===== Tests for getConfigFromMeriossName =====

class TestGetConfigFromMeriossName:
    """Tests for getConfigFromMeriossName function."""

    def test_get_config_from_meross_name_found(self, sample_hosts_config):
        """Test finding a host by Meross name."""
        result = getConfigFromMeriossName('Meross Plug 1')

        assert result is not None
        assert result.name == 'Meross Plug 1'
        assert result.shortname == 'plug1'

    def test_get_config_from_meross_name_not_found(self, sample_hosts_config):
        """Test that None is returned when Meross name not found."""
        result = getConfigFromMeriossName('Nonexistent Plug')

        assert result is None


# ===== Tests for get_host_status =====

class TestGetHostStatus:
    """Tests for get_host_status function."""

    def test_get_host_status_success_200(self):
        """Test successful HTTP 200 response."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.reason = 'OK'
            mock_conn.getresponse.return_value = mock_response
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com')

            assert result['status'] == 200
            assert result['reason'] == 'OK'
            mock_conn.request.assert_called_once()
            mock_conn.close.assert_called_once()

    def test_get_host_status_success_404(self):
        """Test successful HTTP 404 response."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_response = MagicMock()
            mock_response.status = 404
            mock_response.reason = 'Not Found'
            mock_conn.getresponse.return_value = mock_response
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com')

            assert result['status'] == 404
            assert result['reason'] == 'Not Found'

    def test_get_host_status_timeout_error(self):
        """Test handling of TimeoutError."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.getresponse.side_effect = TimeoutError("Connection timed out")
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com')

            assert result['status'] == 500
            assert 'timed out' in str(result['reason']).lower()

    def test_get_host_status_http_exception(self):
        """Test handling of HTTPException."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.getresponse.side_effect = http.client.HTTPException("HTTP error")
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com')

            assert result['status'] == 500
            assert result['reason'] is not None

    def test_get_host_status_connection_error(self):
        """Test handling of ConnectionError."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.getresponse.side_effect = ConnectionError("Connection refused")
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com')

            assert result['status'] == 500
            assert result['reason'] is not None

    def test_get_host_status_os_error(self):
        """Test handling of OSError."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.getresponse.side_effect = OSError("Network error")
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com')

            assert result['status'] == 500
            assert result['reason'] is not None

    def test_get_host_status_generic_exception(self):
        """Test handling of generic Exception."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.getresponse.side_effect = Exception("Generic error")
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com')

            assert result['status'] == 500
            assert result['reason'] is not None

    def test_get_host_status_with_port(self):
        """Test with custom port."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.reason = 'OK'
            mock_conn.getresponse.return_value = mock_response
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com:8443')

            # Check that the connection was made to port 8443
            call_args = mock_conn_class.call_args
            assert call_args[1]['port'] == 8443

    def test_get_host_status_default_port(self):
        """Test with default HTTPS port."""
        with patch('http.client.HTTPSConnection') as mock_conn_class:
            mock_conn = MagicMock()
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.reason = 'OK'
            mock_conn.getresponse.return_value = mock_response
            mock_conn_class.return_value = mock_conn

            result = get_host_status('https://example.com')

            # Check that the connection was made to default port 443
            call_args = mock_conn_class.call_args
            assert call_args[1]['port'] == 443


# ===== Tests for send_mail =====

class TestSendMail:
    """Tests for send_mail function."""

    def test_send_mail_empty_hosts(self):
        """Test that send_mail returns early when hosts list is empty."""
        # Should not raise any exception and return None
        send_mail([], run_by_cron=1)
        # No assertions needed, just verify no exception

    def test_send_mail_not_run_by_cron(self):
        """Test send_mail when not run by cron (prints message)."""
        import check_plugs.check_plugs as check_plugs_module
        with patch('builtins.print') as mock_print:
            check_plugs_module.to_process = ['plug1', 'plug2']
            check_plugs_module.hosts_config = [
                HostsConfig('plug1', '192.168.1.1', 'plug1', 'https://plug1.local'),
                HostsConfig('plug2', '192.168.1.2', 'plug2', 'https://plug2.local'),
            ]

            send_mail(['plug1', 'plug2'], run_by_cron=0)

            # Should print the message instead of sending email
            assert mock_print.called
            call_args = mock_print.call_args[0][0]
            assert 'The hosts were irresponsive and switch off/on:' in call_args

    def test_send_mail_run_by_cron(self):
        """Test send_mail when run by cron (sends email)."""
        import check_plugs.check_plugs as check_plugs_module
        with patch('smtplib.SMTP') as mock_smtp_class, \
             patch('ssl.create_default_context') as mock_ssl:

            mock_smtp = MagicMock()
            mock_smtp_class.return_value = mock_smtp
            mock_ssl.return_value = MagicMock()

            # Set up global variables
            check_plugs_module.to_process = ['plug1']
            check_plugs_module.hosts_config = [
                HostsConfig('plug1', '192.168.1.1', 'plug1', 'https://plug1.local'),
            ]
            check_plugs_module.eml_from = 'test@example.com'
            check_plugs_module.eml_to = 'recipient@example.com'
            check_plugs_module.smtp_server = 'smtp.example.com'
            check_plugs_module.smtp_port = 587
            check_plugs_module.smtp_user = 'user'
            check_plugs_module.smtp_pass = 'pass'

            with patch('socket.gethostname', return_value='testhost'):
                send_mail(['plug1'], run_by_cron=1)

            # Verify SMTP calls
            mock_smtp.ehlo.assert_called()
            mock_smtp.starttls.assert_called()
            mock_smtp.login.assert_called_once_with('user', 'pass')
            mock_smtp.send_message.assert_called_once()
            mock_smtp.quit.assert_called_once()

    def test_send_mail_smtp_exception(self):
        """Test send_mail handles SMTPException gracefully."""
        import smtplib
        import check_plugs.check_plugs as check_plugs_module
        with patch('smtplib.SMTP') as mock_smtp_class, \
             patch('ssl.create_default_context') as mock_ssl, \
             patch('builtins.print') as mock_print:

            mock_smtp = MagicMock()
            mock_smtp.send_message.side_effect = smtplib.SMTPException("SMTP error")
            mock_smtp_class.return_value = mock_smtp
            mock_ssl.return_value = MagicMock()

            # Set up global variables
            check_plugs_module.to_process = ['plug1']
            check_plugs_module.hosts_config = [
                HostsConfig('plug1', '192.168.1.1', 'plug1', 'https://plug1.local'),
            ]
            check_plugs_module.eml_from = 'test@example.com'
            check_plugs_module.eml_to = 'recipient@example.com'
            check_plugs_module.smtp_server = 'smtp.example.com'
            check_plugs_module.smtp_port = 587
            check_plugs_module.smtp_user = 'user'
            check_plugs_module.smtp_pass = 'pass'

            with patch('socket.gethostname', return_value='testhost'):
                send_mail(['plug1'], run_by_cron=1)

            # Verify exception was caught and printed
            mock_print.assert_called_once()
            # The exception object is printed, not just the string
            call_args = mock_print.call_args[0][0]
            assert isinstance(call_args, smtplib.SMTPException)
            assert str(call_args) == "SMTP error"

            # Should print the error
            assert mock_print.called
            mock_smtp.quit.assert_called_once()


# ===== Tests for prepare_off_on and prepare_get_status functions =====

class TestPrepareFunctions:
    """Tests for prepare_off_on and prepare_get_status functions."""

    @patch('asyncio.new_event_loop')
    @patch('asyncio.set_event_loop')
    @patch('check_plugs.check_plugs.switch_off_on', new_callable=AsyncMock)
    def test_prepare_off_on_empty_list(self, mock_switch, mock_set_loop, mock_new_loop):
        """Test prepare_off_on with empty list returns early."""
        from check_plugs.check_plugs import prepare_off_on
        prepare_off_on([], dryrun=False)

        # Should return immediately without calling switch_off_on
        mock_switch.assert_not_called()
        mock_new_loop.assert_not_called()
        mock_set_loop.assert_not_called()

    @patch('asyncio.new_event_loop')
    @patch('asyncio.set_event_loop')
    @patch('check_plugs.check_plugs.switch_off_on', new_callable=AsyncMock)
    def test_prepare_off_on_with_devices(self, mock_switch, mock_set_loop, mock_new_loop):
        """Test prepare_off_on with devices to process."""
        from check_plugs.check_plugs import prepare_off_on
        mock_loop = MagicMock()
        mock_new_loop.return_value = mock_loop

        prepare_off_on(['device1', 'device2'], dryrun=True)

        # Should create and set event loop
        mock_new_loop.assert_called_once()
        mock_set_loop.assert_called_once_with(mock_loop)

        # Should call switch_off_on with the loop
        mock_loop.run_until_complete.assert_called_once()

        # Should close the loop
        mock_loop.close.assert_called_once()

    @patch('asyncio.new_event_loop')
    @patch('asyncio.set_event_loop')
    @patch('check_plugs.check_plugs.get_meross_devices_status', new_callable=AsyncMock)
    def test_prepare_get_status(self, mock_get_status, mock_set_loop, mock_new_loop):
        """Test prepare_get_status function."""
        from check_plugs.check_plugs import prepare_get_status
        mock_loop = MagicMock()
        mock_new_loop.return_value = mock_loop

        prepare_get_status()

        # Should create and set event loop
        mock_new_loop.assert_called_once()
        mock_set_loop.assert_called_once_with(mock_loop)

        # Should call get_meross_devices_status
        mock_loop.run_until_complete.assert_called_once()

        # Should close the loop
        mock_loop.close.assert_called_once()


# ===== Tests for main configuration logic =====

class TestMainLogic:
    """Tests for main configuration and argument parsing logic."""

    def test_url_parsing(self):
        """Test URL parsing with urlparse."""
        url = 'https://example.com:8443/path?query=value'
        parsed = urlparse(url)

        assert parsed.scheme == 'https'
        assert parsed.hostname == 'example.com'
        assert parsed.port == 8443
        assert parsed.path == '/path'
        assert parsed.query == 'query=value'

    def test_default_port_handling(self):
        """Test that default port is handled correctly."""
        url = 'https://example.com'
        parsed = urlparse(url)

        assert parsed.port is None
        # In get_host_status, default port is set to 443
        port = parsed.port or 443
        assert port == 443
