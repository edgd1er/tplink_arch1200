#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# official modules
import logging
import logging.config
import os
import re
import socket

# Homemade Modules
import archer1200
import duckdns

# Variables

duck_token = '__duckdns_token__'
domains = "yourdomain1,yourdomain2,yourdomain3,yourdomain4,yourdomain5"
encrypted = '__your_router_encrypted_password_extracted_as_shown_in_readme'
duckdns_fqdn = 'myhost.duckdns.org'


# functions
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
  force = 0
  clear = False
  txt = None
  ip = None
  mail = '/usr/bin/msmtp'
  ldir = os.getcwd()
  rdir = '/media/usb1/docker/duckdns'
  log_dir = f'{ldir}/logs'
  sql_dir = f'{ldir}/sql'
  global duck_token
  global domains
  global encrypted

  m = re.search(r"holdom", socket.gethostname())
  if m is not None:
    log_dir = 'f{rdir}/logs'
    sql_dir = 'f{rdir}/sql'

  os.makedirs(log_dir, exist_ok=True)
  os.makedirs(sql_dir, exist_ok=True)

  parser = argparse.ArgumentParser(
    description='Update duckdns.org Dynamic DNS record')
  parser.add_argument('-c', '--clear', action='store_true',
                      help='if set to true, the update will ignore the txt parameter and clear the txt record')
  parser.add_argument('-n', '--dryrun', action='store_true', help='do not update duckdns')
  parser.add_argument('-f', '--force', action='store_true', help='force duckdns ip update')
  parser.add_argument('-t', '--txt', type=str, default=None, help='the txt you require.')
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
  else:
    log_level = logging.INFO

  logger.setLevel(log_level);
  # http://myexternalip.com/raw | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"
  # logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=log_level)
  logger.debug(f'Token value: {duck_token}, domains: {domains}, {args}')

  my_router = archer1200.Archer1200(encrypted=encrypted)

  if check_ip_with_fqdn(my_router) or force:
    # if force:
    my_duck_dns = duckdns.duckdns(token=duck_token, domains=domains)
    ip = my_duck_dns.get_external_ip2()
    out = my_duck_dns.duckdns_update(ip=ip, verbose=args.verbose, clear=clear, txt=txt, ip6=None, dry_run=args.dryrun)
    #  domains=args.domains, token=args.token, verbose=args.verbose)
    # 20210401_1750_duck.log
    logger.info(out.strip().replace('\n', ' '))


if __name__ == "__main__":
  logging.config.fileConfig(fname='updateDuckDns.conf', disable_existing_loggers=False)
  logger = logging.getLogger(__name__)
  main()
