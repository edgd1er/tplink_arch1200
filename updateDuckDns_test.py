#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch, Mock

import archer1200
from updateDuckDns import check_ip_with_fqdn

patcherArcher = Mock(spec=archer1200.Archer1200)
duckdns_fqdn = 'omvholblack.duckdns.org'


@patch('archer1200.Archer1200')
class UpdateDuckDnstCase(unittest.TestCase):

    @patch('updateDuckDns.logger')
    def test1_check_ip_with_fqdn_return_false_when_internet_none(self, logger, mock_archer1200):
        wan_ip = "1.2.3.4"
        internet = None
        expected = False
        mock_archer1200.get_wan_ip = Mock(return_value=wan_ip)
        mock_archer1200.get_internet_status = Mock(return_value=internet)
        res = check_ip_with_fqdn(mock_archer1200, duckdns_fqdn)
        mock_archer1200.logout.assert_called()
        mock_archer1200.get_wan_ip.assert_called()
        mock_archer1200.get_internet_status.assert_called()
        logger.error.assert_called()
        self.assertEqual(expected, res)

    @patch('updateDuckDns.logger')
    def test2_check_ip_with_fqdn_return_false_when_internet_dicsonnected(self, logger, mock_archer1200):
        wan_ip = "1.2.3.4"
        internet = {'internet_status': 'disconnected'}
        expected = False
        mock_archer1200.get_wan_ip = Mock(return_value=wan_ip)
        mock_archer1200.get_internet_status = Mock(return_value=internet)
        res = check_ip_with_fqdn(mock_archer1200, duckdns_fqdn)
        mock_archer1200.logout.assert_called()
        mock_archer1200.get_wan_ip.assert_called()
        mock_archer1200.get_internet_status.assert_called()
        logger.error.assert_called()
        self.assertEqual(expected, res)

    @patch('socket.gethostbyname')
    @patch('updateDuckDns.logger')
    def test3_check_ip_with_fqdn_return_false_when_wan_ip_not_equals_duck_ip(self, mock_logger, mock_gethostbyname,
                                                                             mock_archer1200):
        wan_ip = "1.2.3.4"
        duck_ip = "4.3.2.1"
        internet = {'internet_status': 'connected'}
        expected = True
        mock_archer1200.get_wan_ip = Mock(return_value=wan_ip)
        mock_archer1200.get_internet_status = Mock(return_value=internet)
        mock_gethostbyname.return_value = duck_ip
        res = check_ip_with_fqdn(mock_archer1200, duckdns_fqdn)
        mock_archer1200.get_wan_ip.assert_called()
        mock_archer1200.get_internet_status.assert_called()
        mock_archer1200.logout.assert_called()
        mock_logger.error.assert_not_called()
        mock_logger.debug.assert_called_once_with(f' router ip: {wan_ip} ==  {duckdns_fqdn}: {duck_ip}')
        mock_logger.info.assert_called_with('update duckdns ip needed')
        self.assertEqual(expected, res)

    @patch('socket.gethostbyname')
    @patch('updateDuckDns.logger')
    def test4_check_ip_with_fqdn_return_false_when_wan_ip_equals_duck_ip(self, mock_logger, mock_gethostbyname,
                                                                         mock_archer1200):
        wan_ip = "1.2.3.4"
        duck_ip = "1.2.3.4"
        internet = {'internet_status': 'connected'}
        expected = False
        mock_archer1200.get_wan_ip = Mock(return_value=wan_ip)
        mock_archer1200.get_internet_status = Mock(return_value=internet)
        mock_gethostbyname.return_value = duck_ip
        res = check_ip_with_fqdn(mock_archer1200, duckdns_fqdn)
        mock_archer1200.get_wan_ip.assert_called_once()
        mock_archer1200.get_internet_status.assert_called_once()
        mock_archer1200.logout.assert_called_once()
        mock_logger.error.assert_not_called()
        mock_logger.debug.assert_called_once_with(f' router ip: {wan_ip} ==  {duckdns_fqdn}: {duck_ip}')
        mock_logger.info.assert_called_once_with('update duckdns ip not needed')
        self.assertEqual(expected, res)


if __name__ == '__main__':
    unittest.main()
