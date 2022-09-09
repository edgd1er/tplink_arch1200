#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# official modules
import logging
import os
import sys
import unittest
from unittest.mock import patch, call

from requests import Response

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Homemade Modules
from duckdns import Duckdns

"""
Test some functions of duckdns.Duckdns module
"""


class DuckdnsCase(unittest.TestCase):

    @staticmethod
    def get_response(code: str, status_code: int, content: bytes) -> Response:
        r = Response()
        r.code = code
        r.status_code = status_code
        r._content = content
        return r

    @classmethod
    @patch('archer1200.requests.Session.get')
    @patch('archer1200.requests.Session.post')
    def setUpClass(cls, spost_mock, sget_mock) -> None:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        cls.duckdns = Duckdns(token='myToken', domains='domain1,domain2,domain3', ip='1.2.3.4', force=False, clear=True,
                              txt='myText', ip6='my_ip6', dry_run=True)

    @patch('duckdns.requests.get', autospec=True)
    def test_get_external_ip(self, req_mock):
        # requests.get("http://httpbin.org/ip").json().get('origin')
        req_mock.return_value.json.return_value = {'origin': '4.5.6.7'}

        # specify the return value of the get() method
        currentip = self.duckdns.get_external_ip()

        self.assertEqual('4.5.6.7', currentip)
        req_mock.assert_called_once_with("http://httpbin.org/ip")

    @patch('duckdns.requests.get', autospec=True)
    def test_get_external_ip2(self, get_mock):
        # requests.get("http://myexternalip.com/raw").text
        get_mock.return_value.text = '4.5.6.7'

        # specify the return value of the get() method
        currentip = self.duckdns.get_external_ip2()

        self.assertEqual('4.5.6.7', currentip)
        get_mock.assert_called_once_with("http://myexternalip.com/raw")

    @patch('duckdns.socket.gethostbyname', autospec=True)
    def test_check_false(self, socket_mock):
        socket_mock.side_effect = ['1.2.3.4', '1.2.3.4', '1.2.3.4']

        ret = self.duckdns.check()

        print(f'post was called {socket_mock.call_count} = 3')
        print(f'post was called with {socket_mock.call_args_list} ')
        self.assertEqual(False, ret)
        socket_mock.assert_has_calls([call('domain1.duckdns.org'), call('domain2.duckdns.org'),
                                      call('domain3.duckdns.org')], any_order=False)

    @patch('duckdns.socket.gethostbyname', autospec=True)
    def test_check_true(self, socket_mock):
        socket_mock.side_effect = ['4.3.2.1', '4.3.2.1', '4.3.2.1']
        self.logger = logging.getLogger('Duckdns').setLevel(logging.DEBUG)
        ret = self.duckdns.check()

        print(f'post was called {socket_mock.call_count} = 3')
        print(f'post was called with {socket_mock.call_args_list} ')
        print(f'ip: {self.duckdns.ip} ')
        self.assertEqual(True, ret)
        socket_mock.assert_has_calls([call('domain1.duckdns.org'), call('domain2.duckdns.org'),
                                      call('domain3.duckdns.org')], any_order=False)

    @patch('duckdns.requests.get', autospec=True)
    def test_update_no_params_dryrun_true(self, get_mock):
        params = {
            "domains": self.duckdns.domains,
            "token": self.duckdns.token,
            "ip": self.duckdns.ip,
            "verbose": False,
            "clear": self.duckdns.clear,
            "txt": self.duckdns.txt
        }
        # r = requests.get(self.duckdns_url, params).text.strip()
        ret = 'DRYRUN, nothing performed'
        get_mock.return_value.text = ret
        self.duckdns.dry_run = True

        res = self.duckdns.update()
        self.assertEqual(ret, res)
        self.assertEqual(get_mock.call_count, 0)

    @patch('duckdns.requests.get', autospec=True)
    def test_update_no_params_dryrun_false(self, get_mock):
        params = {
            "domains": self.duckdns.domains,
            "token": self.duckdns.token,
            "ip": self.duckdns.ip,
            "verbose": False,
            "clear": self.duckdns.clear,
            "txt": self.duckdns.txt
        }
        # r = requests.get(self.duckdns_url, params).text.strip()
        self.duckdns.dry_run = False
        ret = 'OK'
        get_mock.return_value.text = ret

        res = self.duckdns.update()
        self.assertEqual(ret, res)
        self.assertEqual(get_mock.call_count, 1)
        get_mock.assert_called_once_with(self.duckdns.duckdns_url, params)
