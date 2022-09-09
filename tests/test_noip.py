#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# official modules
import logging
import os
import sys
import unittest
from unittest.mock import patch, call

import requests
from requests import Response

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Homemade Modules
from noip import NoIp

"""
Test some functions of noip module
"""


class NoIpCase(unittest.TestCase):

    @staticmethod
    def get_response(code: str, status_code: int, content: bytes) -> Response:
        r = Response()
        r.code = code
        r.status_code = status_code
        r._content = content
        return r

    @classmethod
    def setUpClass(cls) -> None:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        cls.noip = NoIp(login='myLogin', passwd='myPassword', hosts='noip.domain.com,second.domain.com', dry_run=True,
                        ip="1.2.3.4", force=False)

    @patch('noip.requests.get', autospec=True)
    def test_get_external_ip_ok(self, req_mock):
        # requests.get("http://httpbin.org/ip").json().get('origin')
        req_mock.return_value.json.return_value = {'origin': '4.5.6.7'}

        # specify the return value of the get() method
        currentip = self.noip.get_external_ip()

        self.assertEqual('4.5.6.7', currentip)
        req_mock.assert_called_once_with("http://httpbin.org/ip")

    @patch('noip.requests.get', autospec=True)
    def test_get_external_ip_ko(self, req_mock):
        # requests.get("http://httpbin.org/ip").json().get('origin')
        req_mock.return_value.json.return_value = {'origin': '4.5.6.8'}

        # specify the return value of the get() method
        currentip = self.noip.get_external_ip()

        self.assertNotEqual('4.5.6.7', currentip)
        req_mock.assert_called_once_with("http://httpbin.org/ip")

    @patch('noip.requests.get', autospec=True)
    def test_get_external_ip2_ok(self, get_mock):
        # requests.get("http://myexternalip.com/raw").text
        get_mock.return_value.text = '4.5.6.7'

        # specify the return value of the get() method
        currentip = self.noip.get_external_ip2()

        self.assertEqual('4.5.6.7', currentip)
        get_mock.assert_called_once_with("http://myexternalip.com/raw")

    @patch('noip.requests.get', autospec=True)
    def test_get_external_ip2_ko(self, get_mock):
        # requests.get("http://myexternalip.com/raw").text
        get_mock.return_value.text = '4.5.6.8'

        # specify the return value of the get() method
        currentip = self.noip.get_external_ip2()

        self.assertNotEqual('4.5.6.7', currentip)
        get_mock.assert_called_once_with("http://myexternalip.com/raw")

    @patch('noip.socket.gethostbyname', autospec=True)
    def test_check_false(self, socket_mock):
        socket_mock.side_effect = ['1.2.3.4', '1.2.3.4']

        ret = self.noip.check()

        print(f'post was called {socket_mock.call_count} = 2')
        print(f'post was called with {socket_mock.call_args_list} ')
        socket_mock.assert_has_calls([call('noip.domain.com'), call('second.domain.com')], any_order=False)
        self.assertEqual(False, ret)

    @patch('noip.socket.gethostbyname', autospec=True)
    def test_check_true(self, socket_mock):
        socket_mock.side_effect = ['1.2.3.4', '5.6.7.8']
        self.logger = logging.getLogger('Duckdns').setLevel(logging.DEBUG)
        ret = self.noip.check()

        print(f'post was called {socket_mock.call_count} = 2')
        print(f'post was called with {socket_mock.call_args_list} ')
        print(f'ip: {self.noip.ip} ')
        self.assertEqual(True, ret)
        socket_mock.assert_has_calls([call('noip.domain.com'), call('second.domain.com')], any_order=False)

    @patch('noip.requests.get', autospec=True)
    def test_update_no_params_dryrun_true(self, get_mock):
        params = {
            "b64creds": 'b64',
            "hostname": self.noip.hosts,
            "myip": self.noip.ip
        }
        # re = requests.get('http://{}@dynupdate.no-ip.com/nic/update?hostname={}&myip={}'.format(*params))
        ret = 'DRYRUN, nothing performed'
        get_mock.return_value.text = ret
        self.noip.dry_run = True

        res = self.noip.update()
        print(f'get was called {get_mock.call_count} = 0')
        print(f'get was called with {get_mock.call_args_list} ')
        self.assertEqual(ret, res)
        self.assertEqual(get_mock.call_count, 0)

    @patch('duckdns.requests.get', autospec=True)
    def test_update_no_params_dryrun_false(self, get_mock):
        params = {
            "b64creds": 'b64',
            "hostname": self.noip.hosts,
            "myip": self.noip.ip
        }
        # re = requests.get('http://{}@dynupdate.no-ip.com/nic/update?hostname={}&myip={}'.format(*params))
        self.noip.dry_run = False
        ret = 'OK'
        get_mock.return_value.status_code = requests.codes.ok
        get_mock.return_value.content = b'OK'

        res = self.noip.update()
        print(f'get was called {get_mock.call_count} = 1')
        print(f'get was called with {get_mock.call_args_list} ')
        self.assertEqual(ret, res)
        self.assertEqual(get_mock.call_count, 1)
        get_mock.assert_called_once_with('http://{}@dynupdate.no-ip.com/nic/update?hostname={}&myip={}'.format(*params))
