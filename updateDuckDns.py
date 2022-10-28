#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
updateDuckDNs: check current ip with the one returned by dns resolution
if ips are differents then duckdns ns ip is updated.
"""

# official modules
import argparse
import configparser
import logging
import logging.config
import os
import smtplib
import socket
import ssl
import sys
from datetime import datetime

import dns.resolver

# Homemade Modules
import archer1200
import duckdns
import noip

# Variables
LDIR = os.path.dirname(os.path.realpath(__file__))
hostname = socket.gethostname().split(".")[0]
logger = logging.getLogger(__name__)


# functions
# coding: utf-8

def send_mail(title: str = '', message='', hostname: str = 'Not given', run_by_cron: int = 0):
    """
    send mail if run by cron
    :param title:
    :param hostname:
    :return:
    :param message:
    :param run_by_cron:
    :return:
    """
    if message == '':
        return
    if not run_by_cron:
        logger.debug(f'send_mail: {message}')
        print("send_mail: " + message)
    else:
        subject = f'[{hostname}][{title}]'
        msg = f'From: {eml_from}\r\nTo: {eml_to}\r\nSubject: {subject}\r\n\r\n{message}'
        mailserver = smtplib.SMTP(smtp_server, smtp_port)
        mailserver.ehlo()
        mailserver.starttls(context=ssl.create_default_context())
        mailserver.ehlo()
        mailserver.login(smtp_user, smtp_pass)
        try:
            mailserver.sendmail(eml_from, eml_to, msg)
        except smtplib.SMTPException as e:
            print(e)
        finally:
            mailserver.quit()


def setup_arg_parser():
    parser = argparse.ArgumentParser(
        description='Update duckdns.org Dynamic DNS record')
    parser.add_argument('-c', '--clear', action='store_true',
                        help='if set to true, the update will ignore the txt parameter and clear the txt record')
    parser.add_argument('-n', '--dryrun', action='store_true', help='do not update duckdns')
    parser.add_argument('-f', '--force', action='store_true', help='force duckdns ip update')
    parser.add_argument('-t', '--txt', type=str, default=None, help='the txt you require.')
    parser.add_argument('-s', '--silent', action='store_true', help='silent mode for cron execution')
    parser.add_argument('-d', '--domains', type=str, default=None,
                        help='The DuckDNS domains to update as comma separated list. '
                             'Defaults to DUCKDNS_DOMAINS environment variable.')
    parser.add_argument('-r', '--resolve', action='store_true',
                        help=f'check resolution for listed servers: {servers}')
    parser.add_argument(
        '-a', '--auth', type=str, default=None,
        help='An UUID4 provided by DuckDNS for your user. '
             'Defaults to DUCKDNS_TOKEN environment variable.')
    parser.add_argument('-v', '--verbose', action='store_true', help='More output.')

    return parser.parse_args()


def check_duckdns(token: str = '', domains: str = '', force: bool = False, ip: str = '', dry_run: bool = False,
                  txt: str = '', log_dir='/tmp', hostname='Not Given', run_by_cron: int = 0):
    my_duck_dns = duckdns.DuckDns(token=token, domains=domains, force=force, ip=ip, txt=txt, dry_run=dry_run)
    out = my_duck_dns.check_and_update()
    if '' != out:
        fname = datetime.now().strftime("%Y%m%d_%H%M_duck.log")
        logger.debug(f'name: {fname}, out: {out}')
        logger.info(out.strip().replace('\n', ' ') + f' written to {log_dir}/{fname}, force: {force}')
        with open(os.path.join(log_dir, fname), 'x+') as duckstats:
            duckstats.write(out)
        send_mail(title='DuckDNS: update ip', message=out, run_by_cron=run_by_cron, hostname=hostname)
        return out
    return False


def check_noip(login: str = '', passwd: str = '', hosts: str = '', ip: str = '', force: bool = False):
    my_noip = noip.NoIp(login=login, passwd=passwd, hosts=hosts, ip=ip, force=force)
    out = my_noip.check_and_update()
    logger.debug(f'out: {out}')
    logger.info(out.strip().replace('\n', ' '))
    if out == 'No update needed':
        return False
    return True


def check_servers(servers, name: str = 'www.free.fr', force: bool = False, log_dir: str = '/tmp', hostname='Not Given'):
    message = ''
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 2
    resolver.lifetime = 5
    # Set the DNS Server
    for s in servers.split(','):
        resolver.nameservers = [s]
        try:
            answer = resolver.resolve(name, 'A')
            logger.debug(f'server: {s}, resolved: {answer.rrset}')
            for rr in answer:
                logger.info(f'server: {s}, {name} = {rr.to_text()}')
        except Exception as e:
            message += f'No resolution for {name} on {s}: {e}\n'
            logger.error(f'{s}: {e}')
    if len(message) > 1:
        send_mail(title='DNS: checkServers', message=message, run_by_cron=RUN_BY_CRON, hostname=hostname)
        fname = datetime.now().strftime("%Y%m%d_%H%M_resolve.log")
        with open(os.path.join(log_dir, fname), 'x+', encoding='utf-8') as results:
            results.write(message)
        return False
    return True


def main():
    """"
    Read arguments, config
    """
    clear = False
    txt = None
    global log_dir
    global sql_dir
    global DUCK_TOKEN
    global DOMAINS
    global ARCHER_ENCRYPTED
    global ARCHER_LOGIN
    global RUN_BY_CRON
    global NOIP_LOGIN
    global NOIP_PASSWD
    global NOIP_HOST
    global REMOTE_DIR
    global hostname
    global servers

    if hostname.find('phoebe') >= 0:
        REMOTE_DIR = '/tmp'
        log_dir = f'{REMOTE_DIR}/logs'
        sql_dir = f'{REMOTE_DIR}/sql'

    if hostname.find('holdom') >= 0:
        log_dir = f'{REMOTE_DIR}/logs'
        sql_dir = f'{REMOTE_DIR}/sql'

    if not os.path.isdir(REMOTE_DIR):
        logger.error(f'remote_dir is not set or does not exists: {REMOTE_DIR}')
        quit()

    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(sql_dir, exist_ok=True)

    # argParser
    args = setup_arg_parser()

    if args.auth is None:
        if DUCK_TOKEN == '':
            logger.error('Duckdns token not defined')
            quit()
    else:
        DUCK_TOKEN = args.auth

    if args.domains is not None:
        DOMAINS = args.domains

    force = args.force
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    if args.silent:
        log_level = logging.ERROR

    logger.setLevel(log_level)
    logging.getLogger('archer1200').setLevel(log_level)
    logging.getLogger('duckdns').setLevel(log_level)
    logging.getLogger('noip').setLevel(log_level)
    logger.info(f'script dir: {LDIR}')
    logger.info(f'log_dir: {log_dir}, sql_dir: {sql_dir}')

    # logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=log_level)
    logger.debug(
        f'auth: {args.auth}, clear: {args.clear}, dryrun: {args.dryrun}, force: {args.force}, txt: {args.txt}, silent: {args.silent}, domains: {args.domains}, resolve: {args.resolve}, verbose: {args.verbose}')
    if not args.resolve:
        # Router status check
        my_router = archer1200.Archer1200(username=ARCHER_LOGIN, encrypted=ARCHER_ENCRYPTED, url=ARCHER_URL)
        if my_router.get_timestamp() == '':
            logger.error('Error archer1200.Archer1200: cannot connect to router.')
            send_mail(title='DucksDNS: init', message='Error archer1200.Archer1200: cannot connect to router.',
                      run_by_cron=RUN_BY_CRON)
            sys.exit(1)

        internet = my_router.get_internet_status()
        if internet is None or str(internet) in ['disconnected', 'not logged in']:
            logger.error(f'Error, no connection to internet ({str(internet)})')
            return False

        ip = my_router.get_wan_ip()
        if ip == '':
            logger.error('Error archer1200.Archer1200: cannot get wan from router.')
            send_mail(title='DucksDNS: no WAN', message='Error archer1200.Archer1200: cannot get wan from router.',
                      run_by_cron=RUN_BY_CRON)
            sys.exit(1)

        #####################
        # check for duckdns #
        #####################
        # logger.debug(f'Token value: {DUCK_TOKEN}, domains: {DOMAINS}, fqdn: {duckdns_fqdn}, {args}')
        check_duckdns(token=DUCK_TOKEN, domains=DOMAINS, force=args.force, ip=ip, txt=txt, dry_run=args.dryrun,
                      log_dir=log_dir, hostname=hostname)

        ###############
        # check no ip #
        ###############
        # logger.debug(f'NOIP_PASSWD: {NOIP_PASSWD}, domains: {NOIP_HOSTS}, ip: {ip}, force: {args.force}')
        check_noip(login=NOIP_LOGIN, passwd=NOIP_PASSWD, hosts=NOIP_HOSTS, ip=ip, force=args.force, log_dir=log_dir)

        # End
        my_router.logout()

    else:
        #################
        # check servers #
        #################
        # logger.debug(f'NOIP_PASSWD: {NOIP_PASSWD}, domains: {NOIP_HOSTS}, ip: {ip}, force: {args.force}')
        check_servers(servers, name='www.free.fr', force=args.force, log_dir=log_dir)


if __name__ == "__main__":
    """
    read config from updateDuckDns.ini and updateDuckDns_logging.ini
    """
    RUN_BY_CRON = int(os.environ.get('RUN_BY_CRON', '0'))
    if not os.path.isfile(LDIR + os.path.sep + 'updateDuckDns_logging.ini'):
        print(
            f'updateDuckDns_logging.ini not found, please define one from sample: {LDIR + os.path.sep + "updateDuckDns_logging.ini"}')
        sys.exit()
    logging.config.fileConfig(fname=LDIR + os.path.sep + 'updateDuckDns_logging.ini', disable_existing_loggers=False)
    logger = logging.getLogger(__name__)
    # configParser
    config = configparser.ConfigParser()
    files = config.read(filenames=LDIR + os.path.sep + 'updateDuckDns.ini')
    # logger.debug(f'file read read: {files}, sections: {config.sections()}, config: {config}')
    DUCK_TOKEN = config['my_duckdns'].get('duck_token', 'none')
    REMOTE_DIR = config['my_duckdns'].get('remote_dir', os.path.curdir)
    DOMAINS = config['my_duckdns'].get('domains', 'domain1,domain3,domain3,domain4,domain5')
    ARCHER_ENCRYPTED = config['my_duckdns'].get('archer_encrypted', '<hashes>')
    ARCHER_URL = config['my_duckdns'].get('archer_url', "http://tplinkwifi.net/")
    ARCHER_LOGIN = config['my_duckdns'].get('archer_login', '<archer_login>')
    duckdns_fqdn = config['my_duckdns'].get('duckdns_fqdn', 'youduckdns.duckdns.org', )
    eml_from = config['my_duckdns'].get('eml_from', 'none')
    eml_to = config['my_duckdns'].get('eml_to', 'none')
    smtp_server = config['my_duckdns'].get('smtp_server', '')
    smtp_port = int(config['my_duckdns'].get('smtp_port'))
    smtp_user = config['my_duckdns'].get('smtp_user')
    smtp_pass = config['my_duckdns'].get('smtp_pass')
    NOIP_LOGIN = config['noip'].get('login')
    NOIP_PASSWD = config['noip'].get('passwd')
    NOIP_HOSTS = config['noip'].get('hosts')
    log_dir = f'{LDIR}/logs'
    sql_dir = f'{LDIR}/sql'
    servers = config['global'].get('servers', '')
    main()

# res2 = js2py.eval_js()
