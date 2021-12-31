#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import configparser
# official modules
import json
import logging.config
import unittest
from unittest.mock import patch

from requests import Response

# Homemade Modules
import archer1200
from archer1200 import Archer1200

"""
Test some functions of archer1200.Archer1200 module
"""


class Archer1200Case(unittest.TestCase):

    def get_response(self, code: str, status_code: int, content: str) -> Response:
        r = Response()
        r.code = code
        r.status_code = status_code
        r._content = b"f{content}"
        return r

    @classmethod
    @patch('time.sleep')
    @patch('archer1200.requests.Response.close')
    @patch('archer1200.requests.Session.get')
    @patch('archer1200.requests.Session.post')
    def setUpClass(cls, post, get, close, sleep) -> None:
        getResp = Response()
        getResp.code = ""
        getResp.status_code = 200
        getResp._content = b"{'text': '<html><head><title>Index of /webpages/js/libs/</title></head><body><h1>Index of /webpages/js/libs/</h1><strong><a href=\'/webpages/js/libs/encrypt.987654321.js\'>encrypt.987654321.js</body></html>'}"
        get.return_value = getResp

        postRespLoginType = Response()
        postRespLoginType.code = ""
        postRespLoginType.status_code = 200
        postRespLoginType._content = b'{"success": "true", "data": {"is_default": "false", "cloud_ever_login": "true" }}'

        postRespLogin = Response()
        postRespLogin.code = ""
        postRespLogin.status_code = 200
        postRespLogin._content = b'{"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}'

        post.side_effect = [postRespLoginType, postRespLogin]
        cls.router = Archer1200(encrypted=ARCHER_ENCRYPTED)
        # cls.router.init_login()

    def test_get_timestamp_ok(self):
        timestamp = self.router.time_stamp
        expected = "987654321"
        self.assertEqual(expected, timestamp)

    @patch('archer1200.requests.Session.post')
    def test_login_with_cloud_login_ok(self,post):
        expected_vectors = None
        expected_token = "mocked_token"

        postRespLogin = Response()
        postRespLogin.code = ""
        postRespLogin.status_code = 200
        postRespLogin._content = b'{"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}'
        post.return_value = postRespLogin

        self.router.cloud_login("user1","pass1")
        self.assertEqual(expected_vectors, self.router.vectors)
        self.assertEqual(expected_token, self.router.token)

    @patch('archer1200.requests.Session.post')
    def test_login_with_cloud_login_failed(self, post):
        expected_vectors = None
        expected_token = None

        postRespLogin = Response()
        postRespLogin.code = ""
        postRespLogin.status_code = 200
        postRespLogin._content = b'{"errorcode":"login failed","success":false,"data":{"errorcode":"-20601"}}'
        post.return_value = postRespLogin

        self.router.cloud_login("user1","pass1")
        self.assertEqual(expected_vectors, self.router.vectors)
        self.assertEqual(expected_token, self.router.token)

    @ patch('archer1200.requests.Session.post')
    def test_login_with_local_login_failed(self, post):
        expected_vectors = None
        expected_token = None

        postRespLogin = Response()
        postRespLogin.code = ""
        postRespLogin.status_code = 200
        postRespLogin._content = b'{"errorcode":"login failed","success":false,"data":{"errorcode":"-20601"}}'
        post.return_value = postRespLogin

        self.router.local_login(password="Password")
        self.assertEqual(expected_vectors, self.router.vectors)
        self.assertEqual(expected_token, self.router.token)

    @patch('archer1200.requests.Session.post')
    def test_login_with_local_login_ok(self, post):
        self.router.vectors = ''
        self.router.token = ''
        expected_vectors = "V_SECRET"
        expected_token = "mocked_token"

        postRespLogin = Response()
        postRespLogin.code = ""
        postRespLogin.status_code = 200
        postRespLogin._content = b'{"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}'
        post.return_value = postRespLogin

        self.router.local_login(password="Password")
        self.assertEqual(expected_vectors, self.router.vectors)
        self.assertEqual(expected_token, self.router.token)

    # @patch.object(Session, 'get', spec=True)
    # @patch.object(Archer1200, 'get_timestamp', return_value="1234")
    # @patch.object(Archer1200, 'session')
    @patch('archer1200.requests.Session.post')
    def test_get_field_from_status_all(self, post):
        postRespLogin = Response()
        postRespLogin.code = ""
        postRespLogin.status_code = 200
        postRespLogin._content = b'{"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}'
        post.return_value = postRespLogin

        expected = 'SECRET'

        # session_instance = session_mock.return_value
        # mock_response = session_instance.request.return_value
        # assert session_mock.post.called_count(1)
        # router = Archer1200(encrypted=ARCHER_ENCRYPTED)
        # router.token = 'NOT_REAL_ONE'

        # session_instance = mock_session.return_value
        # session_instance.request.return_value = response
        # mock_response = session_instance.request.return_value

        # router = Archer1200(encrypted=ARCHER_ENCRYPTED)
        # assert get_timestamp_mock.called
        # assert response is mock_response
        # session_instance.request.assert_called_with('get', 'http://tplinkwifi.net/cgi-bin/luci/;stok=/login?form=login')

        # session_instance = session_mock.return_value
        # mock_response = session_instance.request.return_value
        # assert session_mock.post.called_count(1)
        # assert get_timestamp_mock.called
        # router.token = 'NOT_REAL_ONE'

    # @patch.object(Archer1200, 'session', spec=requests.session)
    # @patch.object(Archer1200, 'init_login')
    # def test1_internet_status(self, init_login_mock, session_mock):
    #     pass
    #     logger = logging.getLogger(__name__)
    #     logger.addHandler(logging.NullHandler())
    #     logger.setLevel('DEBUG')
    #     expected = 'connected'
    #     # session_instance = session_mock.return_value
    #     # mock_response = session_instance.request.return_value
    #     router = Archer1200(encrypted=ARCHER_ENCRYPTED)
    #     router.token = 'NOT_REAL_ONE'
    #
    #     session_mock.return_value = MagicMock(spec=requests.session().post, return_value='')
    #     # {'status_code': 200, '_content': "{'success': 'true', 'data':{'internet':'connected'}"}
    #     # session_mock.return_value = mock.MagicMock(get=mock.MagicMock(return_value='bar'))
    #     # mock.MagicMock(post=mock.MagicMock(return_value="{'success': 'true', 'data':{'internet':'connected'}"))
    #     res = router.get_internet_status()
    #     # assertEqual(expected, res)
    #     # assert something_mock.call_count == 1
    #     assert session_mock.post.called_count(1)
    #     assert session_mock.post.called_with("")


def main(my_router):
    print('internet_status: ' + str(my_router.get_internet_status()))
    print('lang: ' + json.dumps(my_router.get_locale()))
    # quit(1)
    print('firmware: ' + json.dumps(my_router.get_firmware()))
    print('ledstatus: ' + json.dumps(my_router.get_led_status()))
    print('lan_ipv4_ipaddr: ' + my_router.get_lan_ip())
    print('wan_ipv4_ipaddr: ' + my_router.get_wan_ip())
    print('wan_ipv4_dynamic: ' + json.dumps(my_router.get_wan_ipv4_dynamic()))
    print('cpu-usage: ' + str(my_router.get_cpu_usage()))
    print('mem-usage: ' + str(my_router.get_mem_usage()))
    print('cloud_support: ' + str(my_router.get_cloud_support()))
    print('cloud_status: ' + str(my_router.get_cloud_status()))
    print('router_mode: ' + str(my_router.get_router_mode()))
    print('ipv4_status: ' + str(my_router.get_ipv4_status()))
    print('syslog types: ' + json.dumps(my_router.get_syslog_types()))
    print('syslog filter: ' + json.dumps(my_router.get_syslog_filter()))
    print('syslog log: ' + json.dumps(my_router.get_syslog_log()))


def secondary(my_router):
    print('lang from locale: ' + str(my_router.get_lang()))
    print('model from locale: ' + str(my_router.get_model()))
    print('model from firmware: ' + str(my_router.get_firm_model()))
    print('version from firmware: ' + str(my_router.get_firm_version()))
    print('hardware from firmware: ' + str(my_router.get_firm_hardware()))
    print('totaltime from firmware: ' + str(my_router.get_firm_totaltime()))
    print('default from firmware: ' + str(my_router.get_firm_default()))
    print('status from ledstatus: ' + str(my_router.get_led_enable()))
    print('timeset from ledstatus: ' + str(my_router.get_led_timeset()))
    print('ledpm from ledstatus: ' + str(my_router.get_led_ledpm()))


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    config = configparser.ConfigParser()
    files = config.read(filenames='updateDuckDns.ini')
    if files == '':
        logger.error(f'Cannot read file updateDuckDns.ini')
    ARCHER_ENCRYPTED = config['my_duckdns'].get('archer_encrypted', '<hashes>')
    ARCHER_LOGIN = config['my_duckdns'].get('archer_login', '<archer_login>')
    # argParser
    parser = argparse.ArgumentParser(
        description='Functionnal tests or unit tests')
    parser.add_argument('-f', '--functionnal', action='store_true',
                        help='run functionnal tests (real access to device)', default=False)
    parser.add_argument('-u', '--unittest', action='store_true', help='run unittests (mock device)', default=False)
    parser.add_argument('-d', '--debug', action='store_true', help='activate debug logging.', default=False)
    parser.add_argument('-s', '--silent', action='store_true', help='silent mode', default=False)

    args = parser.parse_args()
    log_level = logging.INFO
    if args.silent:
        log_level = logging.ERROR
        logger.info(f'silent: Setting log level to {log_level}')
    if args.debug:
        log_level = logging.DEBUG
        logger.info(f'debug: Setting log level to {log_level}')
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(name)s [%(funcName)s][%(lineno)d] - %(message)s',
                        level=log_level)

    if (not args.unittest and not args.functionnal) or (args.unittest):
        logger.info("************************* Unittests *************************************")
        tests = unittest.TestLoader().loadTestsFromTestCase(Archer1200Case)
        suite = unittest.TestSuite([tests])
        print(suite)
        print()
        runner = unittest.TextTestRunner()
        runner.run(suite)
        # unittest.main()
        logger.info("*************************************************************************")

    if args.functionnal:
        logger.info("*************************** Functionnal *********************************")
        my_router = archer1200.Archer1200(encrypted=ARCHER_ENCRYPTED, username=ARCHER_LOGIN)
        # main(my_router)
        # secondary(my_router)
        my_router.logout()
        logger.info("*************************************************************************")
