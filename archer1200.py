import functools
import json
import logging
import re
import shutil
import time
import urllib.request

import requests
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

  def __init__(self, encrypted):
    """
    Initialize router class with encryted password
      - get stok
      - set cookie in requests session.
    :param encrypted:
    """
    self.session = requests.session()
    self.encrypted_password = encrypted
    self.time_stamp = self.get_time_stamp()
    self.token = ''
    self.status_all = None
    self.get_count = 0
    self.vectors = None
    self.init_login()

  def download_file(self, url, file_name):
    try:
      with urllib.request.urlopen(url) as response, open(file_name, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)
    except HTTPError as http_err:
      logger.error(f'HTTP error occurred: {http_err}')  # Python 3.6
    except Exception as err:
      logger.error(f'Other error occurred: {err}')  # Python 3.6

  def get_time_stamp(self):
    response = requests.get(Archer1200.url_js)
    m = re.search('(?<=encrypt\.)([0-9]+)\.js', response.text)
    return m.group(1)

  def get_jsonfrompost(self, url, data):
    m = re.search('([a-zA-Z0-9]+\?[a-z=]+)', url)
    action = m.group(1).replace('?', '(').__add__(')')
    logger.debug(f'get_jsonfrompost: getting {url} with {data}')
    logger.info(f'get_jsonfrompost: getting {action}')
    try:
      response = self.session.post(url, data)

      logger.debug(f'get_jsonfrompost: url: {action}, response: {response.text}')
      # If the response was successful, no Exception will be raised
      response.raise_for_status()
    except HTTPError as http_err:
      logger.error(f'HTTP error occurred: {http_err} on {url}')  # Python 3.6
      logger.info(f'HTTP error occurred: {http_err} on {action}')  # Python 3.6

    except Exception as err:
      logger.info(f'Other error occurred: {err} on {action}')  # Python 3.6
      logger.error(f'Other error occurred: {err} on {url}')  # Python 3.6
    else:
      # logger.info(f'{action}: json status: {response.json()["success"]}')
      logger.debug(f'{url}): json status: {response.json()["success"]}')
      return response.json()

  # TP link specific
  def init_login(self):
    # Not used as encryption was not transcoded to python, get encryption init values
    json_response = self.get_jsonfrompost(url=Archer1200.url_cgi + '/login?form=login', data={'operation': 'read'})
    if json_response['success'] == True:
      self.vectors = json_response['data']['password']
      logger.debug(f'vectors: {self.vectors}')

    # login using encrypted password
    json_response = self.get_jsonfrompost(url=Archer1200.url_cgi + '/login?form=login', data={'operation': 'login',
                                                                                              'password': self.encrypted_password})
    logger.debug(f'init_login: json: {json_response}')
    if json_response['success'] == True:
      self.token = json_response['data']['stok']
      logger.debug(f'init_login: stok: {self.token}')
      logger.info(f'login: {json_response["success"]}')

  def get_generic_function(self, url, action):
    """
    template get function with action as data for post request
    :return:
      json object converted to dictionary
    """
    json_response = self.get_jsonfrompost(url=Archer1200.url_cgi + self.token + url, data=action)
    if json_response['success'] == False:
      logger.error(f'Error on url: {url}, response: {json_response}')
      return json_response
    try:
      to_return = json_response['data']
    except KeyError:
      to_return = json_response

    if logger.isEnabledFor(logging.DEBUG):
      for key in to_return:
        logger.debug(f'get_generic_function: {key}: {to_return[key]}')
    return to_return

  def get_generic_read_function(self, url):
    """
    template get from read operation
    :return:
      json object converted to dictionary
    """
    return self.get_generic_function(url=url, action={'operation': 'read'})

  @time_cache(max_age=max_age_ttl)
  def get_cached_read_function(self, url, field=None):
    """
    template get from read operation
    search field in cached data_all if present.
    :return:
      json object converted to dictionary
    """
    to_return = self.get_generic_read_function(url=url)
    logger.debug(f'get_cached_read_function: {url}')
    if field is not None:
      return to_return[field]
    return to_return

  def get_generic_write_function(self, url):
    """
    tempalte get from write operation
    :return:
      json object
    """
    return self.get_generic_function(url=url, action={'operation': 'write'})

  def get_field_from_status_all(self, field=None):
    """
    search field in status?form=all request
    :return:
      json object
    """
    status_all = self.get_cached_read_function(url='/admin/status?form=all')
    logger.debug(f'get_field_from_status_all: searching for {field}: {json.dumps(status_all).count(field)}')
    if field is None:
      return status_all

    to_return = None
    try:
      to_return = status_all[field]
      logger.debug(f'get_field_from_status_all: found field: {field}: {to_return}')
    except Exception:
      return to_return

  def get_wan_ip(self):
    """
    extract modem's external ip v4 from get_all response
    :return: ip
    """
    field = 'wan_ipv4_ipaddr'
    to_return = self.get_field_from_status_all(field)
    if to_return is not None:
      return to_return
    return self.get_cached_read_function(url='/admin/network?form=status_ipv4', field=field)

  def get_lan_ip(self):
    """
    extract modem's external ip v4 from get_all response
    :return: ip
    """
    field = 'lan_ipv4_ipaddr'
    to_return = self.get_field_from_status_all(field)
    if to_return is not None:
      return to_return
    return self.get_cached_read_function(url='/admin/status?form=all')[field]

  def get_internet_status(self):
    """
    get internet status: (connected or not)
    :return:
    """
    field = 'internet_status'
    to_return = self.get_field_from_status_all(field)
    if to_return is not None:
      return to_return
    return self.get_cached_read_function('/admin/status?form=internet')

  def get_dyn_dns(self):
    """
    get dynamic dns parameters
    :return:
    """
    return self.get_cached_read_function('admin/network?form=wan_ipv4_dynamic')

  def get_locale(self):
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
    return self.get_cached_read_function(url='/admin/firmware?form=upgrade')

  def get_cloud_status(self):
    return self.get_cached_read_function(url='/admin/cloud_account?form=check_support')

  def get_led_status(self):
    return self.get_cached_read_function(url='/admin/ledgeneral?form=setting')

  def get_ipv4_status(self):
    return self.get_cached_read_function(url='/admin/network?form=status_ipv4')

  def get_led_wan_ipv4_protos(self):
    return self.get_cached_read_function(url='/admin/network?form=wan_ipv4_protos')

  def get_wan_ipv4_dynamic(self):
    return self.get_cached_read_function(url='/admin/network?form=wan_ipv4_dynamic')

  def get_system_log(self):
    json_response = self.get_cached_read_function(url='/admin/syslog?form=log')
    return json_response['data']

  def get_traffic_lists(self):
    json_response = self.get_cached_read_function(url='/admin/traffic?form=lists')
    return json_response['data']

  def logout(self):
    """
    logout when finished
    :return:
    """
    json_response = self.get_generic_write_function(url='/admin/system?form=logout')
    logger.info(f"logout: {json_response['success']}")
