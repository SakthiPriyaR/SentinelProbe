"""
Security helpers for the API server: request trust checks and an SSRF guard.
"""
import ipaddress
import os
import secrets
import socket
from urllib.parse import urlparse

from fastapi import Request

LOOPBACK_CLIENTS = {'127.0.0.1', '::1', 'localhost', 'testclient'}
_DEFAULT_ALLOWED_HOSTS = {'localhost', '127.0.0.1', '::1', 'testserver'}


def _allowed_hosts() -> set[str]:
    extra = os.environ.get('SENTINELPROBE_ALLOWED_HOSTS', '')
    return _DEFAULT_ALLOWED_HOSTS | {h.strip().lower() for h in extra.split(',') if h.strip()}


def _host_of(value: str | None) -> str:
    """Hostname (no port) from a Host header value."""
    if not value:
        return ''
    try:
        return (urlparse(f'//{value}').hostname or '').lower()
    except ValueError:
        return ''


def is_trusted_local_request(request: Request) -> bool:
    """True only for a direct loopback client talking to a loopback host name.

    Rejects requests that carry proxy headers (the peer address would then be
    the proxy, not the real client), a foreign ``Host`` header (DNS rebinding)
    or a cross-site ``Origin`` (a web page driving the local API).
    """
    client_ip = request.client.host if request.client else ''
    if client_ip not in LOOPBACK_CLIENTS:
        return False
    if request.headers.get('x-forwarded-for') or request.headers.get('forwarded'):
        return False

    host_header = request.headers.get('host')
    if _host_of(host_header) not in _allowed_hosts():
        return False

    origin = request.headers.get('origin')
    if origin and origin != 'null':
        if urlparse(origin).netloc.lower() != (host_header or '').lower():
            return False
    elif origin == 'null':
        return False

    if request.headers.get('sec-fetch-site') not in (None, 'same-origin', 'none'):
        return False
    return True


def is_authorized(request: Request, secret_key: str) -> bool:
    """Trusted local request, or a valid ``SECRET-KEY`` header."""
    if is_trusted_local_request(request):
        return True
    provided = request.headers.get('SECRET-KEY')
    if not provided:
        return False
    return secrets.compare_digest(provided.encode('utf-8'), secret_key.encode('utf-8'))


def assert_target_allowed(hostname: str | None) -> None:
    """Refuses link-local / metadata targets (e.g. 169.254.169.254).

    Private and loopback ranges stay allowed because scanning internal APIs is a
    normal use of this tool; cloud metadata endpoints never are.
    """
    if not hostname:
        raise ValueError('target host is missing')
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return  # unresolvable: the scan itself will report the host as down
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError(f'target {hostname} resolves to a blocked address ({ip})')
