#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import configparser
# official modules
import json
import logging.config
import os
import sys
import unittest
from unittest.mock import patch

from requests import Response

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


# Homemade Modules
from archer1200 import Archer1200

"""
Test some functions of archer1200.Archer1200 module
"""


class Archer1200Case(unittest.TestCase):

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
    def setUpClass(cls, post, get) -> None:
        get.return_value = cls.get_response("", 200,
                                            b"{'text': '<html><head><title>Index of /webpages/js/libs/</title></head><body><h1>Index of /webpages/js/libs/</h1><strong><a href=\'/webpages/js/libs/encrypt.987654321.js\'>encrypt.987654321.js</body></html>'}")

        postRespLoginType = cls.get_response("", 200,
                                             b'{"success": "true", "data": {"is_default": "false", "cloud_ever_login": "true" }}')

        postRespLogin = cls.get_response("", 200,
                                         b'{"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}')

        post.side_effect = [postRespLoginType, postRespLogin]
        cls.router = Archer1200(username="ARCHER_LOGIN", encrypted="ARCHER_ENCRYPTED")
        get.called_once_with('http://tplinkwifi.net/webpages/js/libs')
        logger = logging.getLogger(__name__)
        logger.debug(f'post was called {post.call_count} >= 3')
        p_call = post.call_args
        pargs, pkwargs = p_call
        # useless not control on calling args when using side_effect
        post.called_once_with('http://tplinkwifi.net/cgi-bin/luci/;stok=/login?form=check_factory_default',
                              {'operation': 'read'})
        post.called_once_with('http://tplinkwifi.net/cgi-bin/luci/;stok=/login?form=cloud_login',
                              {'operation': 'login', 'username': None,
                               'password': '01cabd2121d369db9b04ef5e08d12799d8eddfb02a9b07fc1748d33f0a5ee8b485047d7ca4f5b9229c5021302f17380fb22086b092319d7c684a883c6219de4e6065c7f800932b9c93243573fc874a08b5f4be41fd6670f3cd64054740dcfffc848a73b2ef5d206eec37179a203d461d5053e4b80b67a23ce55634fa74e787c4'})
        post.called_once_with('http://tplinkwifi.net/cgi-bin/luci/;stok=/login?form=login',
                              {'operation': 'login', 'password': 'Password'})
        # won't trigger AssertionError as mock used with side_effect.
        post.called_once_with('http://toto', {'operation': 'login', 'billy': 'bob'})
        logger.debug(f'pargs: {pargs}, pkwargs: {pkwargs}')
        logger.debug(post.call_args_list)
        # erroneous count as mock used with side_effect.
        # cls.assertEqual(post.call_count,3)
        # TODO use has calls
        # post.assert_has_calls(
        #    [('http://tplinkwifi.net/cgi-bin/luci/;stok=/login?form=check_factory_default', {'operation': 'read'}),
        #     ('http://tplinkwifi.net/cgi-bin/luci/;stok=/login?form=cloud_login',
        #         {'operation': 'login', 'username': None,
        #          'password': '01cabd2121d369db9b04ef5e08d12799d8eddfb02a9b07fc1748d33f0a5ee8b485047d7ca4f5b9229c5021302f17380fb22086b092319d7c684a883c6219de4e6065c7f800932b9c93243573fc874a08b5f4be41fd6670f3cd64054740dcfffc848a73b2ef5d206eec37179a203d461d5053e4b80b67a23ce55634fa74e787c4'})
        #      ], any_order=True)

    def test_get_timestamp_ok(self):
        timestamp = self.router.time_stamp
        expected = "987654321"
        self.assertEqual(expected, timestamp)

    @patch('archer1200.requests.Session.post')
    def test_get_jsonfrompost_when_error_404(self, post):
        post.return_value = self.get_response("", 404, b'{}')
        my_data = {'operation': 'read'}
        my_url = "https://tplinkwifi.net/cgi-bin/luci/;stok=/login?form=cloud_login"

        ret = self.router.get_jsonfrompost(url=my_url, data=my_data)
        self.assertEqual(False, ret['success'])
        post.assert_called_once_with(my_url, my_data)

    @patch('archer1200.requests.Session.post')
    def test_login_with_cloud_login_ok(self, post):
        expected_vectors = None
        expected_token = "mocked_token"

        postRespLogin = Response()
        postRespLogin.code = ""
        postRespLogin.status_code = 200
        post.return_value = self.get_response("", 200,
                                              b'{"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}')
        self.router.cloud_login("user1", "pass1")
        self.assertEqual(expected_vectors, self.router.vectors)
        self.assertEqual(expected_token, self.router.token)

    @patch('archer1200.requests.Session.post')
    def test_login_with_cloud_login_failed(self, post):
        expected_vectors = None
        expected_token = None

        post.return_value = self.get_response("", 200,
                                              b'{"errorcode":"login failed","success":false,"data":{"errorcode":"-20601"}}')

        self.router.cloud_login("user1", "pass1")
        self.assertEqual(expected_vectors, self.router.vectors)
        self.assertEqual(expected_token, self.router.token)

    @patch('archer1200.requests.Session.post')
    def test_login_with_local_login_failed(self, post):
        expected_vectors = None
        expected_token = None

        post.return_value = self.get_response("", 200,
                                              b'{"errorcode":"login failed","success":false,"data":{"errorcode":"-20601"}}')

        self.router.local_login(password="Password")
        self.assertEqual(expected_vectors, self.router.vectors)
        self.assertEqual(expected_token, self.router.token)

    @patch('archer1200.requests.Session.post')
    def test_login_with_local_login_ok(self, post):
        self.router.vectors = ''
        self.router.token = ''
        expected_vectors = "V_SECRET"
        expected_token = "mocked_token"
        dstatus = {"success": "true", "data": {"password": "V_SECRET", "stok": "mocked_token"}}
        bstatus = json.dumps(dstatus).encode('utf-8')

        post.return_value = self.get_response(code='', status_code=200, content=bstatus)

        self.router.local_login(password="Password")
        self.assertEqual(expected_vectors, self.router.vectors)
        self.assertEqual(expected_token, self.router.token)

    @patch('archer1200.requests.Session.post')
    def test_get_field_from_status_all(self, post):
        dstatus = {'success': True, 'data': {'wireless_2g_wep_format3': 'hex', 'wireless_5g_disabled': 'off',
                                             'wireless_5g_wep_type2': '64', 'storage_available_unit': 'B',
                                             'storage_vendor': '', 'usb_storages': {}, 'wan_ipv6_conntype': '6to4',
                                             'printer_count': 0, 'printer_name': 'None', 'storage_available': 0,
                                             'wan_ipv4_netmask': '255.255.254.0', 'storage_capacity': 0,
                                             'access_devices_wired': [
                                                 {'wire_type': 'wired', 'macaddr': '01-02-03-04-05-06',
                                                  'ipaddr': '192.168.0.2', 'hostname': 'hermes'}],
                                             'wireless_2g_wds_status': 'disable', 'wireless_2g_wep_type3': '64',
                                             'wireless_2g_wep_format2': 'hex', 'cpu_usage': 0.33,
                                             'access_devices_wireless_host': [
                                                 {'wire_type': '2.4G', 'macaddr': 'A0-A0-A0-A0-A0-A0',
                                                  'ipaddr': '192.168.0.3', 'hostname': 'mercure'}], 'mem_usage': 0.28,
                                             'guest_5g_psk_key': 'pre_shared_key_5g_guest',
                                             'access_devices_wireless_guest': [
                                                 {'wire_type': '5G', 'macaddr': 'C2-C4-C2-C2-C4-C2-C4',
                                                  'ipaddr': '192.168.0.4',
                                                  'hostname': 'apollo'}], 'guest_2g_encryption': 'psk',
                                             'wireless_5g_encryption': 'psk',
                                             'guest_5g_ssid': 'TP-Link_Guest_5G', 'guest_5g_hidden': 'off',
                                             'guest_access': 'on', 'wireless_2g_txpower': 'high',
                                             'guest_5g_enable': 'on', 'wireless_2g_macaddr': 'C2-C4-C2-C4-C2-C4',
                                             'wireless_5g_disabled_all': 'off',
                                             'guest_5g_extinfo': {'support_wds_show': 'no', 'support_band': 'both'},
                                             'wireless_5g_current_channel': '36', 'wireless_2g_port': '1812',
                                             'wireless_2g_wpa_cipher': 'auto', 'wireless_5g_wep_key4': '',
                                             'wireless_2g_htmode': 'auto', 'guest_5g_encryption': 'psk',
                                             'wireless_2g_wep_key3': '', 'wireless_5g_psk_cipher': 'aes',
                                             'guest_2g_psk_cipher': 'aes', 'wireless_5g_wep_format1': 'hex',
                                             'wireless_2g_wep_select': '1', 'wireless_2g_wep_type2': '64',
                                             'wireless_5g_wep_select': '1',
                                             'wireless_2g_psk_key': 'pre_shared_key_2g',
                                             'wireless_2g_wep_type1': '64', 'wireless_5g_ssid': 'TP-Link_5G',
                                             'wireless_2g_wep_key1': '', 'wireless_2g_current_channel': '3',
                                             'wan_ipv4_snddns': '1.1.1.1', 'wan_ipv6_ip6addr': '::',
                                             'wireless_5g_extinfo': {'support_wds_show': 'no', 'support_band': 'both'},
                                             'guest_2g_hidden': 'off', 'wireless_2g_channel': '3',
                                             'wireless_2g_enable': 'on',
                                             'wireless_2g_extinfo': {'support_wds_show': 'no', 'support_band': 'both'},
                                             'wireless_2g_wpa_version': 'auto',
                                             'wireless_5g_psk_key': 'pre_shared_key_5g',
                                             'wireless_2g_wep_format4': 'hex', 'lan_ipv4_netmask': '255.255.255.0',
                                             'wireless_5g_wep_key2': '', 'wireless_5g_enable': 'on',
                                             'wireless_5g_wep_type1': '64', 'wireless_5g_wep_key1': '',
                                             'lan_macaddr': '50-C7-50-C7-50-C7', 'wireless_2g_encryption': 'psk',
                                             'wireless_2g_psk_cipher': 'aes', 'wireless_5g_port': '1812',
                                             'guest_2g_psk_version': 'rsn', 'wireless_5g_wpa_cipher': 'auto',
                                             'guest_5g_disabled': 'off', 'wireless_5g_hwmode': 'nac_5',
                                             'wan_ipv6_gateway': '::',
                                             'lan_ipv6_link_local_addr': 'FE80::52C7:BFFF:FEBA:ED98/64',
                                             'wireless_5g_wep_type4': '64', 'wireless_5g_wep_format4': 'hex',
                                             'wan_ipv6_snddns': '::', 'wireless_2g_disabled': 'off',
                                             'wireless_5g_wep_format3': 'hex', 'wan_ipv6_pridns': '::',
                                             'wireless_2g_hidden': 'off', 'wireless_2g_psk_version': 'rsn',
                                             'guest_isolate': 'on', 'wan_macaddr': '50-C7-50-C7-50-C7-50-99',
                                             'wireless_5g_wps_state': 'configured',
                                             'wireless_2g_wps_state': 'configured', 'wireless_5g_hidden': 'off',
                                             'wireless_5g_psk_version': 'rsn', 'wireless_5g_wep_format2': 'hex',
                                             'wireless_2g_ssid': 'TP_Link-2g', 'wireless_2g_wep_key4': '',
                                             'wireless_5g_wep_mode': 'auto', 'wan_ipv4_ipaddr': '2.2.2.2',
                                             'guest_2g_extinfo': {'support_wds_show': 'no', 'support_band': 'both'},
                                             'lan_ipv6_assign_type': 'dhcpv6', 'wireless_2g_wep_format1': 'hex',
                                             'wireless_2g_wep_key2': '',
                                             'lan_ipv6_ipaddr': '2002::ED98/64',
                                             'wireless_2g_server': '0.0.0.0', 'wireless_5g_htmode': 'auto',
                                             'guest_5g_psk_cipher': 'aes', 'guest_2g_disabled': 'off',
                                             'wan_ipv4_gateway': '10.10.10.10', 'wireless_2g_disabled_all': 'off',
                                             'guest_2g_psk_key': 'pre_shared_key_2g_guest', 'wireless_5g_wpa_key': '',
                                             'guest_5g_psk_version': 'rsn', 'guest_2g_ssid': 'TP-Link_Guest_ED98',
                                             'wireless_2g_wpa_key': '', 'wireless_5g_server': '0.0.0.0',
                                             'wireless_5g_macaddr': '50-C7-96', 'lan_ipv4_dhcp_enable': 'On',
                                             'wireless_5g_txpower': 'high', 'wireless_2g_wep_type4': '64',
                                             'wireless_2g_hwmode': 'bgn', 'wireless_5g_channel': 'auto',
                                             'wan_ipv6_enable': 'off', 'wan_ipv4_pridns': '2.2.2.2',
                                             'guest_2g_enable': 'off', 'wireless_5g_wep_key3': '',
                                             'wireless_2g_wep_mode': 'auto', 'wireless_5g_wpa_version': 'auto',
                                             'wireless_5g_wep_type3': '64', 'storage_capacity_unit': 'B',
                                             'wan_ipv4_conntype': 'dhcp', 'lan_ipv4_ipaddr': '192.168.0.1',
                                             'wireless_5g_wds_status': 'disable'}}
        bstatus = json.dumps(dstatus).encode('utf-8')
        post.return_value = self.get_response('', 200, bstatus)
        logger = logging.getLogger(__name__)
        logger.debug(f'cpu: {self.router.get_cpu_usage()}')
        logger.debug(f'mem: {self.router.get_mem_usage()}')
        self.assertEqual(self.router.get_cpu_usage(), 0.33)
        self.assertEqual(self.router.get_mem_usage(), 0.28)
        self.assertEqual(self.router.get_wan_ip(), "2.2.2.2")
        self.assertEqual(self.router.get_lan_ip(), "192.168.0.1")

    @patch('archer1200.requests.Session.post')
    def test_get_internet_status(self, post):
        dstatus = {'success': True, 'data': {'lan_ipv4_dhcp_enable': 'On', 'lan_macaddr': '50-98',
                                             'wan_ipv4_snddns': '1.1.1.1',
                                             'wan_macaddr': '50-99', 'wan_ipv4_pridns': '2.2.2.2',
                                             'wan_ipv4_gateway': '4.4.4.4', 'wan_ipv4_netmask': '255.255.254.0',
                                             'lan_ipv4_netmask': '255.255.255.0', 'wan_ipv4_ipaddr': '5.5.5.5',
                                             'wan_ipv4_conntype': 'dhcp',
                                             'lan_ipv4_ipaddr': '192.168.0.1'}}
        post.return_value = self.get_response('', 200, json.dumps(dstatus).encode('utf-8'))
        self.assertEqual(dstatus['data'], self.router.get_internet_status())
        post.called_once_with('http://tplinkwifi.net/cgi-bin/luci/;stok=mocked_token/admin/status?form=internet',
                              {'operation': 'post'})

    @patch('archer1200.requests.Session.post')
    def test_get_dyn_dns(self, post):
        dstatus = {'success': 'true',
                   'data': {"pri_dns": "1.1.1.1", "mtu": "1500", "manual_snddns": "2.2.2.2",
                            "dns_mode": "static", "hostname": "modem", "manual_pridns": "3.3.3.3",
                            "snd_dns": "4.4.4.4", "link_status": "plugged", "nonaddress_support": 0,
                            "mac_clone_type": "default", "conntype": "dhcp", "netmask": "255.255.254.0",
                            "conn_status": "connected", "ipaddr": "6.6.6.6", "dyn_pridns": "0.0.0.0",
                            "gateway": "5.5.5.5", "dyn_snddns": "0.0.0.0", "unicast": "off", "pppshare": 3}}
        bstatus = json.dumps(dstatus).encode('utf-8')
        post.return_value = self.get_response("", 200, bstatus)
        self.assertEqual(dstatus['data'], self.router.get_dyn_dns())

    @patch('archer1200.requests.Session.post')
    def test_get_locale(self, post):
        dstatus = {'success': 'true',
                   'data': {"locale": "fr_FR", "force": "false", "region_select_permission": "yes",
                            "model": "Wireless Router Archer C1200"}}
        bstatus = json.dumps(dstatus).encode('utf-8')
        post.return_value = self.get_response("", 200, bstatus)
        self.assertEqual(dstatus['data'], self.router.get_locale())

    @patch('archer1200.requests.Session.post')
    def test_get_router_mode(self, post):
        dstatus = {'success': 'true',
                   'data': {'support': 'yes', 'mode': 'router'}}
        bstatus = json.dumps(dstatus).encode('utf-8')
        post.return_value = self.get_response("", 200, bstatus)
        self.assertEqual(dstatus['data'], self.router.get_router_mode())

    @patch('archer1200.requests.Session.post')
    def test_get_firmware(self, post):
        dstatus = {'success': 'true',
                   'data': {"hardware_version": "Archer C1200 v2.0", "model": "Archer C1200", "totaltime": 90,
                            "is_default": 'false', "firmware_version": "2.0.2 Build 20180118 rel.38979 (EU)"}}
        bstatus = json.dumps(dstatus).encode('utf-8')
        post.return_value = self.get_response("", 200, bstatus)
        self.assertEqual(dstatus['data'], self.router.get_firmware())

    @patch('archer1200.requests.Session.post')
    def test_get_cloud_support(self, post):
        dstatus = {'success': 'true',
                   'data': {"cloud_support": "yes"}}
        bstatus = json.dumps(dstatus).encode('utf-8')
        post.return_value = self.get_response("", 200, bstatus)
        self.assertEqual(dstatus['data']["cloud_support"], self.router.get_cloud_support())

    @patch('archer1200.requests.Session.post')
    def test_get_cloud_status(self, post):
        dstatus = {'success': 'true',
                   'data': {"islogined": "yes"}}
        bstatus = json.dumps(dstatus).encode('utf-8')
        post.return_value = self.get_response("", 200, bstatus)
        self.assertEqual(dstatus['data']["islogined"], self.router.get_cloud_status())

    @patch('archer1200.requests.Session.post')
    def test_get_led_status(self, post):
        dstatus = {'success': 'true',
                   'data': {'enable': 'on', 'time_set': 'yes', 'ledpm_support': 'yes'}
                   }
        bstatus = json.dumps(dstatus).encode('utf-8')
        post.return_value = self.get_response("", 200, bstatus)
        self.assertEqual(dstatus['data'], self.router.get_led_status())


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
    if os.path.exists('updateDuckDns.ini'):
        files = config.read(filenames='updateDuckDns.ini')
    if files == '':
        logger.error(f'Cannot read file updateDuckDns.ini ')
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
        # suite = unittest.TestSuite([Archer1200Case("test_login_with_cloud_login_ok")])
        # suite = unittest.TestSuite([Archer1200Case("test_get_internet_status")])
        print(suite)
        runner = unittest.TextTestRunner()
        runner.run(suite)
        logger.info("*************************************************************************")

    if args.functionnal:
        logger.info("*************************** Functionnal *********************************")
        my_router = Archer1200(encrypted=ARCHER_ENCRYPTED, username=ARCHER_LOGIN)
        main(my_router)
        secondary(my_router)
        my_router.logout()
        logger.info("*************************************************************************")
