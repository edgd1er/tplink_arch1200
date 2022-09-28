#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import unittest
from unittest.mock import patch, Mock

import updateDuckDns

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import archer1200

patcher_archer = Mock(spec=archer1200.Archer1200)
duckdns_fqdn = 'omvholblack.duckdns.org'



class UpdateDuckDnstCase(unittest.TestCase):

    #####################
    # check for duckdns #
    #####################
    @patch('updateDuckDns.logger')
    @patch('duckdns.Duckdns')
    def test_check_duckdns_ok(self, duck_mock, log_mock):
        duck_mock.return_value.check_check_and_update.return_value ='OK'
        res = updateDuckDns.check_duckdns(token='DUCK_TOKEN', domains='DOMAINS', force=False, ip='1.2.3.4', txt='txt', dry_run=False)
        self.assertEqual('OK',res)


    ###############
    # check no ip #
    ###############
    @patch('noip.NoIp')
    def test_check_noip(self,noip_mock):
        res = updateDuckDns.check_noip(login='NOIP_LOGIN', passwd='NOIP_PASSWD', hosts='NOIP_HOSTS', ip='1234', )

    @patch('updateDuckDns.logger')
    def test1_check_ip_with_fqdn_return_false_when_internet_none(self, logger, mock_archer1200):
        wan_ip = "1.2.3.4"
        internet = None
        expected = False
        mock_archer1200.get_wan_ip = Mock(return_value=wan_ip)
        mock_archer1200.get_internet_status = Mock(return_value=internet)

        res = ''  # check_ip_with_fqdn(mock_archer1200, duckdns_fqdn)

        mock_archer1200.get_wan_ip.assert_called()
        mock_archer1200.get_internet_status.assert_called()
        mock_archer1200.logout.assert_called()
        logger.error.assert_called()
        self.assertEqual(expected, res)

    @patch('updateDuckDns.logger')
    def test2_check_ip_with_fqdn_return_false_when_internet_dicsonnected(self, logger, mock_archer1200):
        wan_ip = "1.2.3.4"
        internet = {'internet_status': 'disconnected'}
        expected = False
        mock_archer1200.get_wan_ip = Mock(return_value=wan_ip)
        mock_archer1200.get_internet_status = Mock(return_value=internet)
        res = ''  # check_ip_with_fqdn(mock_archer1200, duckdns_fqdn)
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
        res = ''  # check_ip_with_fqdn(mock_archer1200, duckdns_fqdn)
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
        res = ''  # check_ip_with_fqdn(mock_archer1200, duckdns_fqdn)
        mock_archer1200.get_wan_ip.assert_called_once()
        mock_archer1200.get_internet_status.assert_called_once()
        mock_archer1200.logout.assert_called_once()
        mock_logger.error.assert_not_called()
        mock_logger.debug.assert_called_once_with(f' router ip: {wan_ip} ==  {duckdns_fqdn}: {duck_ip}')
        mock_logger.info.assert_called_once_with('update duckdns ip not needed')
        self.assertEqual(expected, res)


if __name__ == '__main__':
    tests = unittest.TestLoader().loadTestsFromTestCase(UpdateDuckDnstCase)
    suite = unittest.TestSuite([tests])
    print(suite)
    runner = unittest.TextTestRunner()
    runner.run(suite)
    # unittest.main()
