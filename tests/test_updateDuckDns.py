#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import os
import sys
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import updateDuckDns
from archer1200 import Archer1200


patcher_archer = Mock(spec=Archer1200)
duckdns_fqdn = 'omvholblack.duckdns.org'


class UpdateDuckDnstCase(unittest.TestCase):

    def setUp(self):
        updateDuckDns.log_dir = "/tmp"
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(threadName)s %(name)s %(message)s")
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)

    #####################
    # check for duckdns #
    #####################
    @patch('updateDuckDns.datetime') #now.strftime("%Y%m%d_%H%M_duck.log")')
    @patch('updateDuckDns.logger')
    @patch('updateDuckDns.duckdns.DuckDns',autospec=True)
    @patch('updateDuckDns.open')
    def test_check_duckdns_update(self, open_mock, duck_mock, log_mock, date_mock ):
        log_dir = '/tmp'
        date_mock.now.return_value.strftime.return_value = 'NOW.log'
        duck_mock.return_value.check_and_update.return_value = 'updating with 1.2.3.4'
        res = updateDuckDns.check_duckdns(token='DUCK_TOKEN', domains='DOMAINS', force=False, ip='1.2.3.4', txt='txt',
                                          dry_run=False, log_dir=log_dir, run_by_cron=0)
        self.assertEqual('updating with 1.2.3.4', res)
        open_mock.assert_called()
        log_mock.error.assert_not_called()
        log_mock.debug.assert_called()
        log_mock.info.assert_called_with('updating with 1.2.3.4 written to /tmp/NOW.log, force: False')

    @patch('updateDuckDns.datetime')
    @patch('updateDuckDns.logger')
    @patch('updateDuckDns.duckdns.DuckDns',autospec=True)
    @patch('updateDuckDns.open')
    def test_check_duckdns_no_update(self, open_mock, duck_mock, log_mock, date_mock):
        log_dir = '/tmp'
        duck_mock.return_value.check_and_update.return_value = ''
        res = updateDuckDns.check_duckdns(token='DUCK_TOKEN', domains='DOMAINS', force=False, ip='1.2.3.4', txt='txt',
                                          dry_run=False, log_dir=log_dir)
        self.assertEqual(False, res)
        open_mock.assert_not_called()
        date_mock.assert_not_called()

    ###############
    # check no ip #
    ###############
    @patch('noip.NoIp')
    def test_check_noip_update_performed(self, noip_mock):
        log_dir = '/tmp'
        noip_mock.return_value.check_and_update.return_value = 'update needed'
        res = updateDuckDns.check_noip(login='NOIP_LOGIN', passwd='NOIP_PASSWD', hosts='NOIP_HOSTS', ip='1234')
        self.assertEqual(True, res)
        noip_mock.assert_called()
        # my_noip = noip.NoIp(login=NOIP_LOGIN, passwd=NOIP_PASSWD, hosts=NOIP_HOSTS, ip=ip, force=force)
        # out = my_noip.check_and_update()
        # logger.debug(f'out: {out}')
        # logger.info(out.strip().replace('\n', ' '))

    @patch('noip.NoIp')
    def test_check_noip_no_update(self, noip_mock):
        log_dir = '/tmp'
        noip_mock.return_value.check_and_update.return_value = 'No update needed'
        res = updateDuckDns.check_noip(login='NOIP_LOGIN', passwd='NOIP_PASSWD', hosts='NOIP_HOSTS', ip='1234')
        self.assertEqual(False, res)
        noip_mock.assert_called()


if __name__ == '__main__':
    tests = unittest.TestLoader().loadTestsFromTestCase(UpdateDuckDnstCase)
    suite = unittest.TestSuite([tests])
    print(suite)
    runner = unittest.TextTestRunner()
    runner.run(suite)
    # unittest.main()
