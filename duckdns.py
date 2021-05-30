import logging
import os

import requests

# Largely inspired by
# https://raw.githubusercontent.com/hbldh/duckdns-upd8/master/duckdns.py

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class duckdns:
    """
    duckdns client to update domains according to specs
    https://www.duckdns.org/spec.jsp

    largely inspired from https://github.com/hbldh/duckdns-upd8/blob/master/duckdns.py
    """
    duckdns_url = "https://www.duckdns.org/update"

    def __init__(self, token='', domains=''):
        """
        create duck dns client with token and domains to update.
        If no or empty params, env values are used.

        :param token: to allow dns record updates
        :param domains: selection of previously defined domains to update
        """
        self.token = token if token else os.environ.get("DUCKDNS_TOKEN")
        self.domains = domains if domains else os.environ.get("DUCKDNS_DOMAINS")
        logger.debug(f'Instance: token: {token}, domains: {domains}')

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

    def duckdns_update(self, ip=None, verbose=False, clear=False, txt=None, ip6=None, dry_run=False):
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
        params = {
            "domains": self.domains,
            "token": self.token,
            "ip": ip if ip else self.get_external_ip(),
            "verbose": verbose,
            "clear": clear,
            "txt": txt
        }
        if txt is not None:
            params['txt'] = txt

        if ip6 is not None:
            params['ip6'] = ip6

        if dry_run:
            logger.debug(f'DRYRUN: updating with {params}')
            r = 'DRYRUN, nothing performed'
        else:
            r = requests.get(self.duckdns_url, params).text
            logger.debug(f'updating with {params}')

        return r.strip()
