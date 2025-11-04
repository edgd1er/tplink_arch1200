#!/usr/bin/env python3
import argparse
import asyncio
import configparser
import http
import json
import logging.config
import os
import smtplib
import socket
import ssl
import sys
from email.message import EmailMessage
from http.client import HTTPResponse
from urllib.parse import urlparse
import aiohttp
import requests

try:
    import meross_iot.model.enums
    from meross_iot.http_api import MerossHttpClient
    from meross_iot.manager import MerossManager
except ImportError:
    logging.error("Failed to import meross_iot.manager. pip install --break-system-packages meross_iot")
    sys.exit(1)

# Variables
LDIR = os.path.dirname(os.path.realpath(__file__))
logger = None
hosts_config = []
to_process = []


# functions
# coding: utf-8
class HostsConfig:
    def __init__(self, shortname, host, name, url):
        self.shortname = shortname
        self.name = name
        self.host = host
        self.url = url

    def set_url(self, value):
        self._url = value

    def get_url(self):
        return self._url

    url = property(fget=get_url, fset=set_url)


def config_to_list():
    for h in config['hosts']:
        (host_name, merioss_name, host_url) = config['hosts'].get(h, ',,').split(',')
        hc = HostsConfig(h, host_name.strip('"'), merioss_name, host_url.strip('"'))
        logger.debug(f'adding {hc.shortname}, {hc.name}, {hc.host}, {hc.url} to config')
        hosts_config.append(hc)


def getConfigFromTarget(target: str):
    """
    extract host config from configlist
    :param target:
    :return:
    """
    hc = next(filter(lambda x: (target == x.shortname), hosts_config), None)
    if hc is None:
        logger.debug(f'searching {target}=> not found ')
    else:
        logger.debug(f'searching {target}=> found {hc.host}')
    return hc


def getConfigFromMeriossName(merioss: str):
    hc = next(filter(lambda x: (merioss == x.name), hosts_config), None)
    if hc is None:
        logger.debug(f'searching {merioss}=> not found ')
    else:
        logger.debug(f'searching {merioss}=> found {hc.host}')
    return hc


def send_mail(hosts: list = [], run_by_cron: int = 0):
    """
    send mail if run by cron
    :param list of hosts to flip:
    :param run_by_cron:
    :return:
    """
    if len(hosts) == 0:
        return
    message = "The hosts were irresponsive and switch off/on: "
    for h in to_process:
        hc = getConfigFromMeriossName(h)
        message += f"{hc.shortname}({hc.name}, {hc.url}), "
    message = message[0:-2]
    if not run_by_cron:
        print("send_mail: " + message)
    else:
        subject = f'[{socket.gethostname()}][Merioss: Check plugs]'
        msg = f'From: {eml_from}\r\nTo: {eml_to}\r\nSubject: {subject}\r\n\r\n{message}'
        mailserver = smtplib.SMTP(smtp_server, smtp_port)
        mailserver.ehlo()
        mailserver.starttls(context=ssl.create_default_context())
        mailserver.ehlo()
        mailserver.login(smtp_user, smtp_pass)
        try:
            #mailserver.sendmail(eml_from, eml_to, msg)
            emlmsg = EmailMessage()
            emlmsg.set_content(msg)
            emlmsg['Subject'] = subject
            emlmsg['From'] = eml_from
            emlmsg['To'] = eml_to
            mailserver.send_message(from_addr=eml_from, to_addrs=eml_to, msg=emlmsg)
        except smtplib.SMTPException as e:
            print(e)
        finally:
            mailserver.quit()

async def switch_off_on(to_process: list, dryrun: bool = False):
    ch = ''
    if len(to_process) == 0:
        return
    # Setup the HTTP client API from user-password
    try:
        http_api_client = await MerossHttpClient.async_from_user_password(api_base_url='https://iotx-eu.meross.com',
                                                                      email=email,
                                                                      password=password)
        logger.debug(f'email: {email}, pwd: {password}, dryrun: {dryrun}, to_process: f{to_process}')
    except aiohttp.client_exceptions.ClientConnectorError as ce:
        logger.error(f'ClientConnectorError: {ce}',exc_info=ce)
        sys.exit(1)
    except Exception as ex:
        logger.error(f'Exception: {ex}', exc_info=ex)
        sys.exit(1)
    finally:
        logger.info(f'end of switch_on_off')
    # Setup and start the device manager
    manager = MerossManager(http_client=http_api_client)
    await manager.async_init()

    # Retrieve all the MSS310 devices that are registered on this account
    await manager.async_device_discovery()
    plugs = manager.find_devices(device_type="mss310")

    pname=list(map(lambda x:x.name, plugs))
    logger.debug(f'target: {to_process}, dryrun: {dryrun}, plugs: {pname}')
    found=[ p for p in to_process if p in pname ]
    if len(found)==0:
        logger.error(f'to_process: {to_process} not found in plugs: {pname}')
    for dev in plugs:
        # The first time we play with a device, we must update its status
        await dev.async_update()
        if to_process.count(dev.name) > 0:
            logger.info(f'Name: {dev.name}, type: {dev.type}, status: {dev.is_on(channel=0)}')
            for c in dev.channels:
                ch += f'Channel idx: {c._index}, name: {c._name}, name, type: {c._type}, master: {c._master},'
            logger.debug(
                f'Name: {dev.name}, type: {dev.type}, uuid: {dev.uuid}, firmware: {dev.firmware_version}, hardware: {dev.hardware_version}, timestamp: {dev.last_full_update_timestamp}, status: {dev.is_on(channel=0)}, mqtt: {dev.mqtt_host}:{dev.mqtt_port}, Channels: {ch}')
            # print(f"Abilities: {dev.abilities}...")

            if dev.is_on(channel=0) is True:
                if dryrun:
                    logger.info(f'dryrun true, not turning off {dev.name}')
                else:
                    logger.info(f"Turning off {dev.name}...")
                    await dev.async_turn_off(channel=0)
                    await asyncio.sleep(5)
            logger.info(f"Turning on {dev.name}...")
            await dev.async_turn_on(channel=0)
            if __name__ == '__switch_off_on__':
                meross_iot.manager.OnlineStatus
            # We can now start playing with that
            # print("Waiting a bit before turing it off")
            # print(f"Turing off {dev.name}")
            # await dev.async_turn_off(channel=0)
    # Close the manager and logout from http_api
    manager.close()
    await http_api_client.async_logout()

async def get_meross_devices_status():
    # Setup the HTTP client API from user-password
    http_api_client = await MerossHttpClient.async_from_user_password(api_base_url='https://iotx-eu.meross.com',
                                                                      email=email,
                                                                      password=password)
    logger.debug(f'email: {email}, pwd: {password}')
    # Setup and start the device manager
    manager = MerossManager(http_client=http_api_client)
    await manager.async_init()

    # Retrieve all the MSS310 devices that are registered on this account
    await manager.async_device_discovery()
    plugs = manager.find_devices(device_type="mss310")
    for dev in plugs:
        await dev.async_update()
        logger.info(f'plug: {dev.name}, type: {dev.type}, status: {dev.is_on(channel=0)}')

def prepare_get_status():
    logger.debug(f'prepare get status')
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    #loop = asyncio.get_event_loop()
    # 1) Create an event loop object ✅
    loop = asyncio.new_event_loop()
    # 2) Set the current event loop for the current OS thread ✅
    asyncio.set_event_loop(loop)
    loop.run_until_complete(get_meross_devices_status())
    loop.close()


def get_host_status(host_url: str) -> HTTPResponse:
    r1 = {'status': 500, 'reason': None}
    o = urlparse(host_url)
    host_name = o.hostname
    host_port = o.port or 443
    host_path = o.query
    logger.debug(f'Checking {host_name} with {host_url}')
    try:
        conn = http.client.HTTPSConnection(host=host_name, port=host_port, timeout=5,
                                           context=ssl._create_unverified_context())
        conn.request("GET", host_path)
        r2 = conn.getresponse()
        r1['status'] = r2.status
        r1['reason'] = r2.reason
    except TimeoutError as e:
        # do some stuff, log error, etc.
        logger.error(f"Cannot connect to {host_name}:{host_port}. timeout received: {e}")
        r1['reason'] = e
    except http.client.HTTPException as e:
        # other kind of error occured during request
        logger.error(f"request error to {host_name}:{host_port}/${host_path}. exception: {e}")
        r1['reason'] = e
    except requests.exceptions.ConnectionError as e:
        logger.error(f"request error to {host_name}:{host_port}/{host_path}. connection refused: {e}")
        r1['reason'] = e
    except OSError as e:
        logger.error(f"request error to {host_name}:{host_port}/{host_path}. oserror: {e}")
        r1['reason'] = e
    except Exception as e:
        logger.error(f"request error to {host_name}:{host_port}/{host_path}. exception: {e}")
        r1['reason'] = e
    else:  # no error occurred
        logger.debug(f"no exception: status: {r1['status']}, reason: {r1['reason']}")
    finally:  # always close the connection
        conn.close()
    return r1


def prepare_off_on(to_process: list, dryrun: bool):
    # Windows and python 3.8 requires to set up a specific event_loop_policy.
    #  On Linux and MacOSX this is not necessary.
    if len(to_process) == 0:
        return
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    #loop = asyncio.get_event_loop()
    # 1) Create an event loop object ✅
    loop = asyncio.new_event_loop()
    # 2) Set the current event loop for the current OS thread ✅
    asyncio.set_event_loop(loop)
    loop.run_until_complete(switch_off_on(to_process, dryrun))
    loop.close()


if __name__ == '__main__':
    RUN_BY_CRON = int(os.environ.get('RUN_BY_CRON', '0'))
    if not os.path.isfile(LDIR + os.path.sep + 'check_plugs_logging.ini'):
        print(
            f'check_plugs_logging.ini not found, please define one from sample: {LDIR + os.path.sep + "check_plugs_logging.ini"}')
        sys.exit()
    logging.config.fileConfig(fname=LDIR + os.path.sep + 'check_plugs_logging.ini', disable_existing_loggers=False)
    logger = logging.getLogger(__name__)
    # configParser
    config = configparser.ConfigParser()
    plugs = config.read(filenames=LDIR + os.path.sep + 'check_plugs.ini')
    logger.debug(f'read plugs: {plugs}')
    # argParser
    parser = argparse.ArgumentParser(
        description='Switch off/on when host offline')
    parser.add_argument('-t', '--target', type=str, default=None, help='host to check.')
    parser.add_argument('-a', '--all', action='store_true',
                        help='check all defined hosts')
    parser.add_argument('-n', '--dryrun', action='store_true', help='do not switch off')
    parser.add_argument('-f', '--force', action='store_true', help='force swithc off')
    parser.add_argument('-q', '--silent', action='store_true', help='silent mode for cron execution')
    parser.add_argument('-s', '--status', action='store_true', help='get devices status')
    parser.add_argument('-v', '--verbose', action='store_true', help='More output.')
    parser.add_argument('-k', '--kill', type=str, default=None, help='switch off/on an item.')

    args = parser.parse_args()

    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    if args.silent:
        log_level = logging.ERROR

    logger.setLevel(log_level)
    logging.getLogger('check_plug').setLevel(log_level)
    logger.debug(f'script dir: {LDIR}')

    logger.debug(f'{config.sections()}')
    email = config['merioss'].get('meross_email', 'none')
    password = config['merioss'].get('meross_password', 'none')
    #check smtp and set vars
    current_smtp="smtp_h3"
    eml_from = config[current_smtp].get('eml_from', 'none')
    eml_to = config[current_smtp].get('eml_to', 'none')
    smtp_server = config[current_smtp].get('smtp_server', '')
    smtp_port = int(config[current_smtp].get('smtp_port'))
    smtp_user = config[current_smtp].get('smtp_user')
    smtp_pass = config[current_smtp].get('smtp_pass')

    config_to_list()

    if (not args) or (not args.all and not args.target and not args.kill and not args.status):
        logger.debug(f'args: {args}')
        logger.error(f"no target (-t) or all (-a) nor kill (-k) option defined. exiting")
        quit()
    if args.all:
        logger.debug(f'all {args} will be checked')
        for h in hosts_config:
            if h.host.find(socket.gethostname()) < 0:
                logger.debug(f"host: {h.shortname}, merioss: {h.name}, url: {h.url}")
                r1 = get_host_status(h.url)
                logger.debug(f'target: {h.shortname}, merioss name: {h.name}, url: {h.url}, response: {r1["status"]}')
                logger.info(f'target: {h.shortname}, response: {r1["status"]}')
                if (r1 is None or (200, 404).count(r1["status"]) == 0 or args.force):
                    to_process.append(h.name)

    if args.target:
        target = args.target
        logger.debug(f' {target} will be checked, dry-run: {args.dryrun}')
        hc = getConfigFromTarget(target)
        if hc == None:
            logger.error(f'{target} not found in config.')
            sys.exit(1)
        logger.debug(f'{hc.host} ?= {socket.gethostname()} ?= {hc.host.find(socket.gethostname())}')
        if hc.host.find(socket.gethostname()) > -1:
            logger.info(f' {target} ({hc.host}) is this host, exiting.')
            sys.exit(0)
        r1 = get_host_status(hc.url)
        logger.debug(f'target: {hc.shortname}, merioss name: {hc.name}, url: {hc.url}, response: {r1["status"]}')
        logger.info(f'target: {hc.shortname}, response: {r1["status"]}')
        if (r1 is None or (200, 404).count(r1["status"]) == 0 or args.force):
            to_process.append(hc.name)

    if args.kill:
        hc = getConfigFromTarget(args.kill)
        if hc is not None:
            logger.info(f'Kill: add {hc.host} to the list to process.')
            to_process.append(hc.name)
        else:
            logger.error(f'{args.kill} not found in config.')

    #TODO
    prepare_off_on(to_process, args.dryrun)
    send_mail(to_process, RUN_BY_CRON)

    if args.status:
        prepare_get_status()