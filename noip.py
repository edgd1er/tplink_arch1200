#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import logging
import os
import socket

import requests

# Largely inspired by
# https://raw.githubusercontent.com/hbldh/duckdns-upd8/master/duckdns.py

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class NoIp:
    """
    duckdns client to update domains according to specs
    https://www.duckdns.org/spec.jsp

    largely inspired from https://github.com/hbldh/duckdns-upd8/blob/master/duckdns.py
    """
    noip_url = "https://www.duckdns.org/update"

    def __init__(self, login='', passwd='', hosts='', dry_run=False, ip=None, force=False):
        """
        create noip dns client with login, password and hosts to update.
        If no or empty params, env values are used.

        :param login: to allow dns record updates
        :param passwd: to allow dns record updates
        :param hosts: hosts to update
        """
        self.login = login if login else os.environ.get("NOIP_LOGIN")
        self.passwd = passwd if passwd else os.environ.get("NOIP_PASSWD")
        self.hosts = hosts if hosts else os.environ.get("NOIP_HOSTS")
        logger.debug(f'Instance: login: {login},pass: {hash(passwd)}, hosts: {hosts}, ip: {ip}, force: {force}')
        self.ip = ip
        if self.ip == None:
            self.ip = self.get_external_ip()
        if self.ip == '':
            self.ip = self.get_external_ip2()
        self.dry_run = dry_run
        self.force = force

    def get_external_ip(self):
        """Get your external IP address as string.

        Uses httpbin(1): HTTP Request & Response Service

        """
        return requests.get("http://httpbin.org/ip").json().get('origin')

    def get_external_ip2(self):
        """Get your external IP address as string.

        Uses http://myexternalip.com/raw: HTTP Request & Response Service

        """
        # http://ip1.dynupdate.no-ip.com/
        return requests.get("http://myexternalip.com/raw").text

    def check(self):
        if self.force:
            return True
        to_update = False
        try:
            with open('/tmp/lastip', mode='r') as i:
                ipfile = i.read()
        except FileNotFoundError as fnf:
            logger.debug(f'{fnf}')
            logger.warning('/tmp/lastip not found.')
            ipfile = self.ip
            with open('/tmp/lastip',mode='w') as i:
                i.write(self.ip)

        for h in self.hosts.split(','):
            ip = socket.gethostbyname(h)
            if ipfile == self.ip and ip != self.ip:
                logger.debug(f'Recently updated, no change needed for {h}: {ip} != {ipfile} == {self.ip}')
            elif ip != self.ip:
                logger.debug(f'{h} need to be updated: {self.ip} != ${ip}')
                to_update = True
            else:
                logger.debug(f'no change needed for {h}: {ip}')
        return to_update

    def update(self, ip=None, dry_run=False):
        """Update noip dynamic DNS record.

        Args:
            ip (str): external ip to test.
            dry_run: (bool): true to simulate update.

        Returns:
            "OK" or "KO" depending on success or failure. Verbose adds IP and change
            status as well.

        """
        encbyt = str.encode(self.login + ":" + self.passwd, 'utf-8')
        params = {
            "b64creds": base64.standard_b64encode(encbyt),
            "hostname": self.hosts,
            "myip": ip if ip else self.ip,
        }
        if dry_run or self.dry_run:
            logger.debug(f'DRYRUN: updating with {params}')
            r = 'DRYRUN, nothing performed'
        else:
            re = requests.get('http://{}@dynupdate.no-ip.com/nic/update?hostname={}&myip={}'.format(*params))
            if re.status_code != requests.codes.ok:
                logger.error(f'NoIP not updated: {(re.content).decode()}')
            else:
                logger.info(f'NoIP update result: {(re.content).decode()}')
            r = (re.content).decode()
            logger.debug(f'updating with {params}: status: {re.status_code}, content: {re.content}')
        return r.strip()

    def check_and_update(self):
        if self.check():
            return self.update(ip=self.ip)
        else:
            return 'No update needed'
