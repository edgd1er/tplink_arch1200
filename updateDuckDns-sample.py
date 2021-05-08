#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# official modules
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

# duck_token = '__duckdns_token__'
# domains = "yourdomain1,yourdomain2,yourdomain3,yourdomain4,yourdomain5"
# encrypted = '__your_router_encrypted_password_extracted_as_shown_in_readme'
# duckdns_fqdn= 'myhost.duckdns.org'

ldir = os.path.dirname(os.path.realpath(__file__))


# functions
# coding: utf-8

def send_mail(message=''):
  if message == '':
    return
  from_addr = "test591@free.fr"
  to_addr = "test591@free.fr"
  subject = f'[{socket.gethostname()}][Duck: update ip]'
  msg = """\
From: %s\r\n\
To: %s\r\n\
Subject: %s\r\n\
\r\n\
%s
""" % (from_addr, to_addr, subject, message)
  mailserver = smtplib.SMTP('smtp.myprovider.com', 587)
  mailserver.ehlo()
  mailserver.starttls(context=ssl.create_default_context())
  mailserver.ehlo()
  mailserver.login("user", "password")
  try:
    mailserver.sendmail(from_addr, to_addr, msg)
  except smtplib.SMTPException as e:
    print(e)
  mailserver.quit()


def check_ip_with_fqdn(my_router):
  """ return true if dns resolution is not correct
  :rtype: object
  """
  ip = my_router.get_wan_ip()
  internet = my_router.get_internet_status()
  my_router.logout()
  global duckdns_fqdn

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
  import argparse
  clear = False
  txt = None
  log_dir = f'{ldir}/logs'
  sql_dir = f'{ldir}/sql'
  global duck_token
  global domains
  global encrypted

  os.makedirs(log_dir, exist_ok=True)
  os.makedirs(sql_dir, exist_ok=True)

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
  logger.debug(f'Token value: {duck_token}, domains: {domains}, {args}')

  my_router = archer1200.Archer1200(encrypted=encrypted)

  if check_ip_with_fqdn(my_router) or force:
    my_duck_dns = duckdns.duckdns(token=duck_token, domains=domains)
    ip = my_duck_dns.get_external_ip2()
    out = my_duck_dns.duckdns_update(ip=ip, verbose=args.verbose, clear=clear, txt=txt, ip6=None, dry_run=args.dryrun)
    fname = datetime.now().strftime("%y%m%d_%H%M_duck.log")
    logger.info(out.strip().replace('\n', ' ') + f' written to {log_dir}/{fname}, forced: {force}')
    send_mail(out)
    with open(os.path.join(log_dir, fname), 'x+') as duckstats:
      duckstats.write(out)


if __name__ == "__main__":
  logging.config.fileConfig(fname=ldir + os.path.sep + 'updateDuckDns.conf', disable_existing_loggers=False)
  logger = logging.getLogger(__name__)
  main()

# res2 = js2py.eval_js()
