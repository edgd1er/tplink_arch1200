#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
ldir = os.path.dirname(os.path.realpath(__file__))
logger = {}


# functions
# coding: utf-8

def send_mail(message=''):
    if message == '':
        return
    subject = f'[{socket.gethostname()}][Duck: update ip]'
    msg = """\
From: %s\r\n\
To: %s\r\n\
Subject: %s\r\n\
\r\n\
%s
""" % (eml_from, eml_to, subject, message)
    mailserver = smtplib.SMTP(smtp_server, smtp_port)
    mailserver.ehlo()
    mailserver.starttls(context=ssl.create_default_context())
    mailserver.ehlo()
    mailserver.login(smtp_user, smtp_pass)
    try:
        mailserver.sendmail(eml_from, eml_to, msg)
    except smtplib.SMTPException as e:
        print(e)
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
    else:
        logger.info('update duckdns ip not needed')
        return False


def main():
    clear = False
    txt = None
    rdir = '/media/usb1/docker/duckdns'
    log_dir = f'{ldir}/logs'
    sql_dir = f'{ldir}/sql'
    global duck_token
    global domains
    global encrypted

    if socket.gethostname().find('holdom') >= 0:
        log_dir = f'{rdir}/logs'
        sql_dir = f'{rdir}/sql'

    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(sql_dir, exist_ok=True)

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
        if duck_token == '':
            logger.error('Duckdns token not defined')
            quit()
    else:
        duck_token = args.auth

    if args.domains is not None:
        domains = args.domains

    force = args.force
    if args.verbose:
        log_level = logging.DEBUG
        logging.getLogger('archer1200').setLevel(log_level)
        logging.getLogger('duckdns').setLevel(log_level)
    else:
        log_level = logging.INFO

    if args.silent:
        log_level = logging.ERROR
        logging.getLogger('archer1200').setLevel(log_level)
        logging.getLogger('duckdns').setLevel(log_level)

    logger.setLevel(log_level)
    # logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=log_level)
    logger.debug(f'Token value: {duck_token}, domains: {domains}, fqdn: {duckdns_fqdn}, {args}')

    my_router = archer1200.Archer1200(encrypted=encrypted)

    if check_ip_with_fqdn(my_router, duckdns_fqdn) or force:
        my_duck_dns = duckdns.duckdns(token=duck_token, domains=domains)
        ip = my_duck_dns.get_external_ip2()
        out = my_duck_dns.duckdns_update(ip=ip, verbose=args.verbose, clear=clear, txt=txt, ip6=None,
                                         dry_run=args.dryrun)
        fname = datetime.now().strftime("%Y%m%d_%H%M_duck.log")
        logger.info(out.strip().replace('\n', ' ') + f' written to {log_dir}/{fname}, forced: {force}')
        send_mail(out)
        with open(os.path.join(log_dir, fname), 'x+') as duckstats:
            duckstats.write(out)


if __name__ == "__main__":
    logging.config.fileConfig(fname=ldir + os.path.sep + 'updateDuckDns_logging.ini', disable_existing_loggers=False)
    logger = logging.getLogger(__name__)
    # configParser
    config = configparser.ConfigParser()
    config['my_duckdns'] = {'duck_token': 'none',
                            'domains': 'domain1,domain3,domain3,domain4,domain5',
                            'encrypted': '<hashes>',
                            'duckdns_fqdn': 'youduckdns.duckdns.org'}
    config.sections()
    config.read('updateDuckDns.ini')
    duck_token = config['my_duckdns']['duck_token']
    domains = config['my_duckdns']['domains']
    encrypted = config['my_duckdns']['encrypted']
    duckdns_fqdn = config['my_duckdns']['duckdns_fqdn']
    eml_from = config['my_duckdns']['eml_from']
    eml_to = config['my_duckdns']['eml_to']
    smtp_server = config['my_duckdns']['smtp_server']
    smtp_port = config['my_duckdns']['smtp_port']
    smtp_user = config['my_duckdns']['smtp_user']
    smtp_pass = config['my_duckdns']['smtp_pass']
    main()

# res2 = js2py.eval_js()
