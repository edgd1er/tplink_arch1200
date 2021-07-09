#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
# official modules
import json
import logging.config

# Homemade Modules
import archer1200

"""
Test some functions of archer1200.Archer1200 module
"""

def main():
    my_router = archer1200.Archer1200(encrypted=archer_encrypted, username=archer_login)
    print('lang: ' + json.dumps(my_router.get_locale()))
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
    print('internet_status: ' + str(my_router.get_internet_status()))
    print('syslog types: ' + json.dumps(my_router.get_syslog_types()))
    print('syslog filter: ' + json.dumps(my_router.get_syslog_filter()))
    print('syslog log: ' + json.dumps(my_router.get_syslog_log()))


if __name__ == "__main__":
    log_level = logging.DEBUG
    # log_level = logging.INFO
    logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=log_level)
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    config = configparser.ConfigParser()
    files = config.read(filenames='updateDuckDns.ini')
    archer_encrypted = config['my_duckdns'].get('archer_encrypted', '<hashes>')
    archer_login = config['my_duckdns'].get('archer_login', '<archer_login>')
    main()
