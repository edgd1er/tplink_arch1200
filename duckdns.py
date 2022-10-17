#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import os
import socket

import requests

# Largely inspired by
# https://raw.githubusercontent.com/hbldh/duckdns-upd8/master/duckdns.py

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
lastipfile='/tmp/lastip'

class Duckdns:
    """
    duckdns client to update domains according to specs
    https://www.duckdns.org/spec.jsp

    largely inspired from https://github.com/hbldh/duckdns-upd8/blob/master/duckdns.py
    """
    duckdns_url = "https://www.duckdns.org/update"

    def __init__(self, token: str = '', domains='', ip: str = None, force: bool = False, clear=False, txt=None,
                 ip6=None, dry_run: bool = False):
        """
        create duck dns client with token and domains to update.
        If no or empty params, env values are used.

        :type ip: object
        :type token: object
        :type force: object
        :param token: to allow dns record updates
        :param domains: selection of previously defined domains to update
        """
        self.token = token if token else os.environ.get("DUCKDNS_TOKEN")
        self.domains = domains if domains else os.environ.get("DUCKDNS_DOMAINS")
        self.txt = txt
        self.ip6 = ip6
        self.clear = clear
        self.force = force
        self.txt = txt
        self.dry_run = dry_run
        if ip is None or ip == '':
            ip = self.get_external_ip()
        if ip == '':
            ip = self.get_external_ip2()
        self.ip = ip
        logger.debug(f'Instance: token: {token}, domains: {domains}, ip: {self.ip}, force: {self.force}')

    def get_external_ip(self):
        """Get your external IP address as string.

        Uses httpbin(1): HTTP Request & Response Service

        """
        return requests.get("http://httpbin.org/ip").json().get('origin')

    def get_external_ip2(self):
        """Get your external IP address as string.

        Uses http://myexternalip.com/raw: HTTP Request & Response Service

        """
        return requests.get("http://myexternalip.com/raw").text

    def check(self):
        to_update = False
        try:
            with open(lastipfile, mode='r') as i:
                ipfile = i.read()
        except FileNotFoundError as fnf:
            logger.debug(f'{fnf}')
            logger.warning(f'f{lastipfile} not found.')
            ipfile = self.ip
            with open(lastipfile,mode='w') as i:
                i.write(self.ip)
        for h in self.domains.split(','):
            ip = socket.gethostbyname(h + ".duckdns.org")
            if ipfile == self.ip and ip != self.ip:
                logger.debug(f'Recently updated, no change needed for {h}: {ip} != {ipfile} == {self.ip}')
            elif ip != self.ip:
                logger.debug(f'{h} need to be updated: {self.ip} != ${ip}')
                to_update = True
            else:
                logger.debug(f'no change needed for {h}: {ip}')
        if to_update:
            logger.info(f'Update requested for {self.domains}')
        else:
            logger.info(f'No need to update {self.domains}')
        return True if self.force else to_update

    def update(self, ip=None, verbose=False, clear=False, txt=None, ip6=None, dry_run=False):
        """Update duckdns.org Dynamic DNS record.

        Args:
            domains (str): The DuckDNS domains to update as comma separated list.
            token (str): An UUID4 provided by DuckDNS for your user.
            verbose (bool): Returns info about whether or not IP has been changed as
                well as if the request was accepted.

        Returns:
            "OK" or "KO" depending on success or failure. Verbose adds IP and change
            status as well.

        """
        #r = 'NOCHANGE'
        params = {
            "domains": self.domains,
            "token": self.token,
            "ip": ip if ip else self.ip,
            "verbose": verbose,
            "clear": clear if clear else self.clear,
            "txt": txt if txt else self.txt
        }
        if txt is not None:
            params['txt'] = txt

        if ip6 is not None:
            params['ip6'] = ip6

        if dry_run or self.dry_run:
            logger.debug(f'DRYRUN: updating with {params}')
            r = 'DRYRUN, nothing performed'
        else:
            r = requests.get(self.duckdns_url, params).text
            logger.debug(f'updating with {params}')
            with open(file=lastipfile
                , mode='w') as i:
                i.write(f'{ip if ip else self.ip}')

        logger.debug(f'r: {r}')
        return r.strip()

    def check_and_update(self):
        if self.check():
            return self.update()
        else:
            return ''
