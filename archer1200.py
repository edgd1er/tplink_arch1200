#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import functools
import json
import logging
import re
import shutil
import socket
import time

import requests
import urllib3
from requests.exceptions import HTTPError

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
max_age_ttl = 30


def time_cache(max_age, maxsize=128, typed=False):
    """Least-recently-used cache decorator with time-based cache invalidation.

    Args:
        max_age: Time to live for cached results (in seconds).
        maxsize: Maximum cache size (see `functools.lru_cache`).
        typed: Cache on distinct input types (see `functools.lru_cache`).
    """

    def _decorator(fn):
        @functools.lru_cache(maxsize=maxsize, typed=typed)
        def _new(*args, __time_salt, **kwargs):
            return fn(*args, **kwargs)

        @functools.wraps(fn)
        def _wrapped(*args, **kwargs):
            return _new(*args, **kwargs, __time_salt=int(time.time() / max_age))

        return _wrapped

    return _decorator


class Archer1200:
    """
    get information from a TP link Archer C1200 using a Token
    no setter.
    """
    url_base = 'http://tplinkwifi.net/'
    url_cgi = url_base + 'cgi-bin/luci/;stok='
    url_js = url_base + 'webpages/js/libs/'
    url_web = url_base + 'webpages/'
    session = None
    username = None
    encrypted_password = None
    time_stamp = None
    token = None
    status_all = None
    get_count = 0
    vectors = None

    def __init__(self, encrypted: str, username=None, url: str = url_base):
        """
        Initialize router class with encryted password
          - get stok
          - set cookie in requests session.
        :param encrypted:
        """
        logger.debug(f'start')
        self.url_base = url
        self.session = requests.session()
        self.username = username
        self.encrypted_password = encrypted
        self.time_stamp = self.get_timestamp()
        self.token = ''
        self.status_all = None
        self.get_count = 0
        self.vectors = None
        self.is_cloud_login = self.get_cloud_login_status()
        logger.debug(f'time_stamp: {self.time_stamp}, username: {self.username}')
        if self.is_cloud_login:
            self.cloud_login(self.username, self.encrypted_password)
        else:
            self.local_login(self.encrypted_password)
        logger.debug(f'end')

    def str2bool(self, v: str) -> bool:
        ret = str(v).lower() in ("yes", "true", "t", "1")
        logger.debug(f'v: {v} = {ret}')
        return ret

    def download_file(self, url, file_name):
        if len(self.token) == 0:
            logger.error("Not logged in, exiting")
            return
        try:
            with self.session.request.urlopen(url) as response, open(file_name, 'wb') as out_file:
                shutil.copyfileobj(response, out_file)
        except HTTPError as http_err:
            logger.error(f'HTTP error occurred: {http_err}')  # Python 3.6
        except Exception as err:
            logger.error(f'Other error occurred: {err}')  # Python 3.6

    def get_cloud_login_status(self):
        logger.debug('START')
        ret = False
        json_response = self.get_jsonfrompost(url=Archer1200.url_cgi + '/login?form=check_factory_default',
                                              data={'operation': 'read'})
        try:
            logger.debug(
                f'check_factory_default: success: {json_response["success"]}, is_default: {(json_response["data"]["is_default"])}')
            if self.str2bool(json_response["success"]):
                if self.str2bool(json_response['data']['is_default']):
                    logger.error("router is not configured or was reset, still with first login form")
                    quit(1)
                ret = json_response['data']['cloud_ever_login']
            else:
                logger.error(f'check_factory_default: query failed, defaulting to false')
                logger.debug(f'check_factory_default: query failed {json_response}')
            logger.debug(f'END: {ret}')
        except KeyError as ke:
            logger.error(f'{ke}: {json_response}')
        return ret

    def get_timestamp(self):
        ret = ''
        logger.debug('START')
        try:
            response = self.session.get(Archer1200.url_js)
            m = re.search(r'(?<=encrypt\.)([\d]+)\.js', response.text)
            ret = m.group(1)
            logger.debug(f'timestamp: {ret}, response: {response.text}')
        except urllib3.exceptions.MaxRetryError as mre:
            logger.error(f'Max Retry Error error occurred: {mre}')
        except socket.gaierror as gae:
            logger.error(f'DNS resolution error: {gae}')
        except ConnectionError as con_err:
            logger.error(f'Connexion error occurred: {con_err}')
        finally:
            logger.info(f'END: timestamp: {ret}')

        return ret

    def get_jsonfrompost(self, url, data):
        m = re.search(r'([a-zA-Z0-9]+\?[a-z=]+)', url)
        try:
            action = m.group(1).replace('?', '(').__add__(')')
            logger.debug(f'getting {url} with {data}')
            logger.info(f' getting {data["operation"]} {action} ')
        except AttributeError as ae:
            logging.error(f' {ae} cannot parse url {url}')
            action = url

        ret = json.loads("{\"success\":false}")
        try:
            response = self.session.post(url, data)
            logger.debug(f'url: {action}/{url}, response: {response}')
            logger.debug(f'url: {action}/{url}, response.text: {response.text}')
            # If the response was successful, no Exception will be raised
            response.raise_for_status()
            ret = response.json()
            logger.debug(f'{url}): json status: {ret["success"]} , ret {ret}')
        except HTTPError as http_err:
            logger.debug(f'HTTP error occurred: {http_err} on {action}/{url}, {response}')  # Python 3.6
            logger.error(f'HTTP error occurred: {http_err} on {action}/{url}')  # Python 3.6
        except ValueError as vae:
            logger.debug(f'json error occurred: {vae} on {action}/{url}, {response}')  # Python 3.6
            logger.error(f'json error occurred: {vae} on {action}/{url}')  # Python 3.6
        except Exception as err:
            logger.debug(f'Other error occurred: {err} on {action}/{url}, {response}')  # Python 3.6
            logger.error(f'Other error occurred: {err} on {action}/{url}')  # Python 3.6
        finally:
            pass
            # logger.info(f'{action}: json status: {response.json()["success"]}')
        return ret

    # TP link specific
    def cloud_login(self, username, password):
        logger.debug(f'START: username: {username}/ password: {password}')
        if username == None or password == None or username =='' or password =='':
            logger.error("END: Expecting a username and a password to perform cloud login.")
            exit()
        json_response = self.get_jsonfrompost(url=Archer1200.url_cgi + '/login?form=cloud_login',
                                              data={'operation': 'login',
                                                    'username': username,
                                                    'password': password})
        logger.debug(f'json: {json_response}')
        if self.str2bool(json_response['success']):
            self.token = json_response['data']['stok']
            logger.debug(f'END: login success: stok: {self.token}, vectors: {self.vectors}')
            logger.info(f'response:: {json_response["success"]}')
        else:
            self.token = None
            self.vectors = None
            logger.error(f'END: {json_response["errorcode"]}: {json_response["data"]["errorcode"]}')

    def local_login(self, password):
        """
        perform local login to interface
        never tested, always logged with cloud_login
        :param password:
        :return: 0 if ok else 1
        """
        logger.debug('START')
        # Not used as encryption was not transcoded to python, get encryption init values
        json_response = self.get_jsonfrompost(url=Archer1200.url_cgi + '/login?form=login',
                                              data={'operation': 'read'})
        # already connected ?
        if self.str2bool(json_response['success']):
            self.vectors = json_response['data']['password']
            logger.debug(f'vectors: {self.vectors}')

        # login using encrypted password
        json_response = self.get_jsonfrompost(url=Archer1200.url_cgi + '/login?form=login',
                                              data={'operation': 'login', 'password': password})

        if self.str2bool(json_response['success']):
            self.token = json_response['data']['stok']
            logger.debug(f'END: stok: {self.token}')
            logger.info(f'response: {json_response["success"]}')
            return 0
        else:
            if json_response is dict and "errorcode" in json_response.keys:
                logger.error(f'END: {json_response["errorcode"]}: {json_response["data"]["errorcode"]}')
                logger.debug(f'END: failed: json: {json_response}')
            else:
                logger.error(f'END: Nothing in response: {json_response}')
            self.token = None
            self.vectors = None
            return 1

    def get_generic_function(self, url, action) -> dict:
        """
        template get function with action as data for post request
        :return:
          json object converted to dictionary
        """
        logger.debug('START')
        to_return = {"error": "empty content"}
        if self.token == None:
            logger.error("Not logged in, exiting")
            return {"error": "not logged in"}
        json_response = self.get_jsonfrompost(url=Archer1200.url_cgi + self.token + url, data=action)
        logger.debug(f'{action} on {url}: {json_response}')
        if not self.str2bool(json_response['success']):
            logger.error(f'Error on url: {url}, response: {json_response}')
            json_response['data'] = ''
            logger.debug(f'{action} on {url}: {json_response}')
            return json_response
        try:
            if 'data' in json_response.keys():
                to_return = json_response['data']
                logger.debug(f'{action} on {url}: {to_return}')
            else:
                to_return = json_response
                logger.debug(f'{action} on {url}: {json_response}')
        except KeyError as ke:
            logger.error(f'{ke}: {action} on {url}: {json_response}')
            to_return = json_response
        finally:
            logger.debug(f'END: {to_return}')
        return to_return

    def get_generic_read_function(self, url, action={'operation': 'read'}) ->dict:
        """
        template get from read operation
        :return:
          json object converted to dictionary
        """
        return self.get_generic_function(url=url, action=action)

    @time_cache(max_age=max_age_ttl)
    def get_cached_read_function(self, url, action={'operation': 'read'}, field=None) -> dict:
        """
        template get from read operation
        search field in cached data_all if present.
        :return:
          json object converted to dictionary
        """
        to_return = 'None found'
        to_return = self.get_generic_read_function(url=url, action=action)
        logger.debug(f'action: {action}, field: {field}, url: {url}, return: {to_return}')
        if field == None:
            return to_return

        return self.get_value_from_keys(to_return, field, to_return)

    def get_generic_write_function(self, url):
        """
        tempalte get from write operation
        :return:
          json object
        """
        logger.debug(f'START: url: {url}')
        if self.token == None:
            logger.error("Not logged in, exiting")
            return {"error": "not logged in"}

        return self.get_generic_function(url=url, action={'operation': 'write'})

    def get_field_from_status_all(self, field=None) -> str:
        """
        search field in status?form=all request
        :return:
          string with the value of the requested field
        """
        to_return = 'None found'
        status_all = self.get_cached_read_function(url='/admin/status?form=all')
        if field is None:
            logger.debug(f'No field searched: {json.dumps(status_all)}')
            return status_all
        logger.debug(f'searching for {field}: {json.dumps(status_all).count(field)}')
        try:
            to_return = status_all[field]
            logger.debug(f'found field: {field}: {to_return}')
        except Exception as e:
            logger.info(f'field not found: {e}')

        return to_return

    def get_wan_ip(self) -> str:
        """
        extract modem's external ip v4 from get_all response
        :return: ip
        """
        field = 'wan_ipv4_ipaddr'
        to_return = self.get_field_from_status_all(field)
        if to_return is not None:
            return to_return
        tmp = self.get_cached_read_function(url='/admin/network?form=status_ipv4', field=field)
        return self.get_value_from_keys(tmp, field, "0.0.0.0")

    def get_lan_ip(self) -> str:
        """
        extract modem's external ip v4 from get_all response
        :return: ip
        """
        field = 'lan_ipv4_ipaddr'
        return self.get_field_from_status_all(field)

    def get_internet_status(self) -> str:
        """
        get internet status: (connected or not)
        :return:
        """
        field = 'internet_status'
        # to_return = self.get_field_from_status_all(field)
        # if to_return == 'None found':
        tmp = self.get_cached_read_function(url='/admin/status?form=internet')
        logger.debug(f'{tmp}')
        # tmp = self.get_cached_read_function(url='/admin/network?form=status_ipv4', field=field)
        return self.get_value_from_keys(tmp, field, tmp)

    def get_cpu_usage(self) -> float:
        to_return = self.get_field_from_status_all('cpu_usage')
        if isinstance(to_return, float):
            return to_return
        return float(-1)

    def get_mem_usage(self) -> float:
        to_return = self.get_field_from_status_all('mem_usage')
        if isinstance(to_return, float):
            return to_return
        return float(-1)

    def get_dyn_dns(self):
        """
        get dynamic dns parameters
        :return:
        """
        return self.get_cached_read_function(url='/admin/network?form=wan_ipv4_dynamic')

    def get_locale(self) -> dict:
        """
        get locale from device
        :return:
        """
        return self.get_cached_read_function(url='/locale?form=lang')

    def get_router_mode(self) -> dict:
        """
        Get route mode: router or bridge
        :return: dict with two keys

        :Example

        router_mode: {'support': 'yes', 'mode': 'router'}
        """
        return self.get_cached_read_function(url='/admin/system?form=sysmode')

    def get_firmware(self):
        """
        get hardware and software version
        return dict with keys

        :Example
        firmware: {"hardware_version": "Archer C1200 v2.0", "model": "Archer C1200", "totaltime": 90, "is_default": false, "firmware_version": "2.0.2 Build"}
        :return:
        """
        return self.get_cached_read_function(url='/admin/firmware?form=upgrade')

    def get_cloud_support(self) -> str:
        status = self.get_cached_read_function(url='/admin/cloud_account?form=check_support')
        field = 'cloud_support'
        return self.get_value_from_keys(fdict=status, field=field)

    def get_cloud_status(self) -> str:
        status = self.get_cached_read_function(url='/admin/cloud_account?form=check_login')
        field = 'islogined'
        return self.get_value_from_keys(fdict=status, field=field)

    def get_led_status(self) -> dict:
        status = self.get_cached_read_function(url='/admin/ledgeneral?form=setting')
        return self.get_value_from_keys(fdict=status, field="")

    def get_ipv4_status(self) -> dict:
        status = self.get_cached_read_function(url='/admin/network?form=status_ipv4')
        return self.get_value_from_keys(fdict=status, field="")

    def get_wan_ipv4_protos(self):
        status = self.get_cached_read_function(url='/admin/network?form=wan_ipv4_protos')
        return self.get_value_from_keys(fdict=status, field="")

    def get_wan_ipv4_dynamic(self) -> str:
        status = self.get_cached_read_function(url='/admin/network?form=wan_ipv4_dynamic')
        return self.get_value_from_keys(fdict=status, field="")

    def get_traffic_lists(self):
        json_response = self.get_cached_read_function(url='/admin/traffic?form=lists')
        return json_response

    # system
    def get_syslog_types(self) -> dict:
        json_response = self.get_cached_read_function(url='/admin/syslog?form=types')
        return json_response

    def get_syslog_filter(self) -> dict:
        json_response = self.get_cached_read_function(url='/admin/syslog?form=filter')
        return json_response

    def get_syslog_log(self) -> dict:
        json_response = self.get_generic_read_function(url='/admin/syslog?form=log', action={'operation': 'load'})
        return json_response

    def logout(self):
        """
        logout when finished
        :return:
        """
        json_response = self.get_generic_write_function(url='/admin/system?form=logout')
        try:
            logger.info(f"{json_response['success']}")
        except KeyError as ke:
            logger.debug(f'json_response: {json_response}')
            logger.error(f'{json_response["error"]}')

    # Higher level api
    def get_value_from_keys(self, fdict: dict = None, field: str = "", default=None) -> str:
        """

        :param fdict:
        :param field:
        :param default:
        :return:
        """
        to_return = default
        logger.debug(f'START: {field} in {fdict} defaulting to {default}')
        if isinstance(fdict, dict):
            if "error" in fdict.keys():
                to_return = fdict['error']
            else:
                if field in fdict.keys():
                    to_return = fdict[field]
                else:
                    to_return = fdict
        return to_return

    def get_lang(self) -> str:
        """
        get device language
        :return: iso language
        """
        return self.get_value_from_keys(fdict=self.get_locale(), field='locale')

    def get_model(self) -> str:
        """
        get device model
        :return: iso language
        """
        return self.get_value_from_keys(fdict=self.get_locale(), field='model')

    def get_firm_model(self) -> str:
        """
        get device model
        :return: "Archer C1200"
        """
        return self.get_value_from_keys(fdict=self.get_firmware(), field='model')

    def get_firm_hardware(self) -> str:
        """
        get hardware version
        :return: "Archer C1200 v2.0"
        """
        return self.get_value_from_keys(fdict=self.get_firmware(), field='hardware_version')

    def get_firm_version(self) -> str:
        """
        get firmware version
        :return: "2.0.2 Build 20180118 rel.38979 (EU)"
        """
        return self.get_value_from_keys(fdict=self.get_firmware(), field='firmware_version')

    def get_firm_totaltime(self) -> str:
        """
        get firmware version
        :return: 90
        """
        return self.get_value_from_keys(fdict=self.get_firmware(), field='totaltime')

    def get_firm_default(self) -> bool:
        """
        return is_default value
        :return: true/false
        """
        return str(self.get_value_from_keys(fdict=self.get_firmware(), field='is_default')).lower() in ("yes", "true", "t", "1")

    def get_led_enable(self) -> str:
        """
        return led status
        :return: on/off
        """
        return self.get_value_from_keys(fdict=self.get_led_status(), field='enable', default="off")

    def get_led_timeset(self) -> str:
        """
        return weither the night times are set or not
        :return: true/false
        """
        return self.get_value_from_keys(fdict=self.get_led_status(), field='time_set')

    def get_led_ledpm(self) -> str:
        """
        return led night enabled status
        :return: true/false
        """
        return self.get_value_from_keys(fdict=self.get_led_status(), field='ledpm_support')
