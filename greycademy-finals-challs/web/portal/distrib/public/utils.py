import socket
import ipaddress
import requests
from urllib3.util import parse_url


def validate_host(url):
    """Check if URL's host resolves to a non-private IP"""
    parsed = parse_url(url)
    host = parsed.hostname

    if not host or parsed.scheme not in ('http', 'https'):
        return False, 'Invalid URL'

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return False, 'Could not resolve host'

    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_link_local:
        return False, 'Host resolves to a private or restricted IP'

    return True, parsed


def fetch_url(url):
    res = requests.get(url,timeout=5, allow_redirects=False)
    return res

