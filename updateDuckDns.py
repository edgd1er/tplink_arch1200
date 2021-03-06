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
from datetime import datetime

# Homemade Modules
import archer1200
import duckdns

# Variables
LDIR = os.path.dirname(os.path.realpath(__file__))
logger = {}


# functions
# coding: utf-8

def send_mail(message='', run_by_cron=0):
    """
    send mail if run by cron
    :param message:
    :param run_by_cron:
    :return:
    """
    if message == '':
        return
    if not run_by_cron:
        print("send_mail: " + message)
    else:
        subject = f'[{socket.gethostname()}][Duck: update ip]'
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


def check_ip_with_fqdn(my_router, duckdns_fqdn):
    """ return true if dns resolution is not correct
    :rtype: object
    """
    ip = my_router.get_wan_ip()
    internet = my_router.get_internet_status()
    my_router.logout()

    if internet is None or str(internet).find('disconnected') > 0:
        logger.error(f'Error, no connection to internet ({str(internet)})')
        return False

    ip_from_dns_duck = socket.gethostbyname(duckdns_fqdn)
    logger.debug(f' router ip: {ip} ==  {duckdns_fqdn}: {ip_from_dns_duck}')

    # tp link has updated its dns but need to update duckdns
    if ip != ip_from_dns_duck:
        logger.info('update duckdns ip needed')
        return True

    logger.info('update duckdns ip not needed')
    return False


def main():
    clear = False
    txt = None
    log_dir = f'{LDIR}/logs'
    sql_dir = f'{LDIR}/sql'
    global DUCK_TOKEN
    global DOMAINS
    global ARCHER_ENCRYPTED
    global ARCHER_LOGIN
    global RUN_BY_CRON

    if socket.gethostname().find('holdom') >= 0:
        log_dir = f'{REMOTE_DIR}/logs'
        sql_dir = f'{REMOTE_DIR}/sql'

    if not os.path.isdir(REMOTE_DIR):
        logger.error(f'remote_dir is not set or does not exists: {REMOTE_DIR}')
        quit()

    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(sql_dir, exist_ok=True)
    logger.info(f'log_dir: {log_dir}, sql_dir: {sql_dir}')

    # argParser
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
    parser.add_argument(
        '-a', '--auth', type=str, default=None,
        help='An UUID4 provided by DuckDNS for your user. '
             'Defaults to DUCKDNS_TOKEN environment variable.')
    parser.add_argument('-v', '--verbose', action='store_true', help='More output.')

    args = parser.parse_args()

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
    logger.info(f'script dir: {LDIR}')

    # logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=log_level)
    logger.debug(f'Token value: {DUCK_TOKEN}, domains: {DOMAINS}, fqdn: {duckdns_fqdn}, {args}')

    my_router = archer1200.Archer1200(username=ARCHER_LOGIN, encrypted=ARCHER_ENCRYPTED, url=ARCHER_URL)
    if my_router.get_timestamp() == '':
        logger.error(f'Error archer1200.Archer1200: cannot connect to router.')
        send_mail(f'Error archer1200.Archer1200: cannot connect to router.', RUN_BY_CRON)
        exit(1)

    if check_ip_with_fqdn(my_router, duckdns_fqdn) or force:
        my_duck_dns = duckdns.duckdns(token=DUCK_TOKEN, domains=DOMAINS)
        # ip = my_duck_dns.get_external_ip2()
        ip = my_router.get_wan_ip()
        if ip == '':
            logger.error(f'Error archer1200.Archer1200: cannot get wan from router.')
            send_mail(f'Error archer1200.Archer1200: cannot get wan from router.', RUN_BY_CRON)
            exit(1)

        out = my_duck_dns.duckdns_update(ip=ip, verbose=args.verbose, clear=clear, txt=txt, ip6=None,
                                         dry_run=args.dryrun)
        fname = datetime.now().strftime("%Y%m%d_%H%M_duck.log")
        logger.info(out.strip().replace('\n', ' ') + f' written to {log_dir}/{fname}, forced: {force}')
        with open(os.path.join(log_dir, fname), 'x+') as duckstats:
            duckstats.write(out)
        send_mail(out, RUN_BY_CRON)

    # send_mail(f'RUN_BY_CRON: {RUN_BY_CRON}, this is a test message to test mail sending', RUN_BY_CRON)


if __name__ == "__main__":
    RUN_BY_CRON = int(os.environ.get('RUN_BY_CRON', '0'))
    if not os.path.isfile(LDIR + os.path.sep + 'updateDuckDns_logging.ini'):
        print(
            f'updateDuckDns_logging.ini not found, please define one from sample: {LDIR + os.path.sep + "updateDuckDns_logging.ini"}')
        quit()
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
    main()

# res2 = js2py.eval_js()
