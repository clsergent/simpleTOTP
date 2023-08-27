#!/usr/bin/env python3

# simple TOTP library

import argparse
import hmac
import base64
import hashlib
import time
import re

PERIOD = 30
ALGORITHM = 'sha1'
DIGITS = 6

TOTP_URI_RE = '^otpauth://totp(/(?P<issuer>\w*?)?:?(?P<name>(\w|[@.])*)?)?\?secret=(?P<secret>[A-Z]+)&' \
              'algorithm=(?P<algorithm>[a-z0-9]+)&digits=(?P<digits>\d+)&period=((?P<period>\d+))$'


def otp(secret: str | bytes, msg: bytes, algorithm=ALGORITHM, digits=DIGITS, **kwargs):
    if type(secret) is str:
        secret = secret.encode()
    key = base64.b32decode(secret + b'=' * (len(secret) % 5))
    hasher = getattr(hashlib, algorithm)
    mac = hmac.new(key, msg, digestmod=hasher).digest()
    offset = mac[-1] & 15
    result = (int.from_bytes(mac[offset: offset + 4], 'big') & 0x7fffffff) % 10**int(digits)
    return f'{result:0{digits}}'


def totp(secret: bytes | str, period=PERIOD, **kwargs):
    now = int(time.time() // int(period)).to_bytes(8, 'big')
    return otp(secret, now, **kwargs)


def totpFromURI(uri: str):
    if match := re.match(TOTP_URI_RE, uri):
        kwargs = match.groupdict()
        return totp(**kwargs)


def run():
    parser = argparse.ArgumentParser('TOTP program')
    # pass arguments individually
    params = parser.add_mutually_exclusive_group()
    parser.add_argument('secret', type=str, help='TOTP secret as base32  | uri if --uri is provided')
    params.add_argument('-a', '--algorithm', choices=hashlib.algorithms_available,
                        default=ALGORITHM, help=f'algorithm used to hash')
    params.add_argument('-d', '--digits', type=int, default=DIGITS, help=f'password number of digit (default is {DIGITS})')
    params.add_argument('-p', '--period', type=int, default=PERIOD, help=f'password period of validity (default is {PERIOD})')
    # pass arguments as uri
    uri = parser.add_mutually_exclusive_group()
    uri.add_argument('-u', '--uri', action='store_true', default=False,
                     help='provide parameters as uri (otpauth://totp?secret=<base32>&algorithm=<hasher>&digits=<int>&period=<secs>)')

    args = parser.parse_args()

    if args.uri:
        print(totpFromURI(args.secret))
    else:
        print(totp(args.secret, period=args.period, algorithm=args.algorithm, digits=args.digits))


if __name__ == '__main__':
    run()

