import argparse
import sys
import os
import json
import codecs
import binascii
import base64
import time
from collections import defaultdict
from urllib.parse import quote_plus
from roadtools.roadlib.auth import Authentication, get_data
from roadtools.roadlib.constants import WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES, WELLKNOWN_USER_AGENTS
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadtx.selenium import SeleniumAuthentication
from roadtools.roadtx.federation import EncryptedPFX, SAMLSigner, encode_object_guid
import pyotp

RR_HELP = 'ROADtools Token eXchange by Dirk-jan Mollema (@_dirkjan) / Outsider Security (outsidersecurity.nl)'

def main():
    # Primary argument parser
    parser = argparse.ArgumentParser(add_help=True, description=RR_HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-p', '--proxy', action='store', help="Proxy requests through a proxy (format: proxyip:port). Ignores TLS validation if specified, unless --secure is used.")
    parser.add_argument('-s', '--secure', action='store_true', help="Enforce certificate validation even if using a proxy")

    # Add subparsers for modules
    subparsers = parser.add_subparsers(dest='command')

    # Construct authentication module options
    auth = Authentication()
    auth_parser = subparsers.add_parser('gettokens', aliases=['auth','gettoken'], help='Authenticate to Azure AD and get access/refresh tokens. Supports various authentication methods.')
    auth.get_sub_argparse(auth_parser, for_rr=False)

    # Refresh token helper
    rttsauth_parser = subparsers.add_parser('refreshtokento', help='Use cached refresh token to switch between resources or clients')
    clienthelptext = 'Client ID (application ID) to use when authenticating. Accepts aliases (list with roadtx listaliases). Read from token file if not supplied'
    rttsauth_parser.add_argument('-c',
                                 '--client',
                                 action='store',
                                 help=clienthelptext)
    rttsauth_parser.add_argument('-r',
                                 '--resource',
                                 action='store',
                                 help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                 default='https://graph.windows.net')
    rttsauth_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password secret of the application if not a public app')
    rttsauth_parser.add_argument('-s',
                                 '--scope',
                                 action='store',
                                 help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    rttsauth_parser.add_argument('-t',
                                 '--tenant',
                                 action='store',
                                 help='Tenant ID or domain to auth to')
    rttsauth_parser.add_argument('--tokenfile',
                                 action='store',
                                 help='File to read and store the tokens from/to (default: .roadtools_auth)',
                                 default='.roadtools_auth')
    rttsauth_parser.add_argument('--tokens-stdout',
                                 action='store_true',
                                 help='Do not store tokens on disk, pipe to stdout instead')
    rttsauth_parser.add_argument('-ua', '--user-agent', action='store',
                                 help='Custom user agent to use. Default: Python requests user agent')
    rttsauth_parser.add_argument('--cae',
                                 action='store_true',
                                 help='Request Continuous Access Evaluation tokens (requires use of scope parameter instead of resource)')

    # Construct device module
    device_parser = subparsers.add_parser('device', help='Register or join devices to Azure AD')
    device_parser.add_argument('-a',
                               '--action',
                               action='store',
                               choices=['join','register','delete'],
                               default='join',
                               help='Action to perform (default: join)')
    device_parser.add_argument('-c', '--cert-pem', action='store', metavar='file', help='Certificate file to save device cert to (default: <devicename>.pem)')
    device_parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file for certificate (default: <devicename>.key)')
    device_parser.add_argument('-n', '--name', action='store', help='Device display name (default: DESKTOP-<RANDOM>)')
    device_parser.add_argument('--access-token', action='store', help='Access token for device registration service. If not specified, taken from .roadtools_auth')
    device_parser.add_argument('--device-type', action='store', help='Device OS type (default: Windows)')
    device_parser.add_argument('--os-version', action='store', help='Device OS version (default: 10.0.19041.928)')
    device_parser.add_argument('--deviceticket', action='store', help='Device MSA ticket to match with existing device')

    # Construct hybrid device module
    hdevice_parser = subparsers.add_parser('hybriddevice', help='Join an on-prem device to Azure AD')
    hdevice_parser.add_argument('-c', '--cert-pem', action='store', metavar='file', help='Certificate file containing on-prem device cert')
    hdevice_parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file for device certificate')
    hdevice_parser.add_argument('--cert-pfx', action='store', metavar='file', help='Device cert and key as PFX file')
    hdevice_parser.add_argument('--pfx-pass', action='store', metavar='password', help='PFX file password')
    hdevice_parser.add_argument('--pfx-base64', action='store', metavar='BASE64', help='PFX file as base64 string')
    hdevice_parser.add_argument('-n', '--name', action='store', help='Device display name (default: DESKTOP-<RANDOM>)')
    hdevice_parser.add_argument('--device-type', action='store', help='Device OS type (default: Windows)')
    hdevice_parser.add_argument('--os-version', action='store', help='Device OS version (default: 10.0.19041.928)')
    hdevice_parser.add_argument('--sid', action='store', required=True, help='Device SID in AD')
    hdevice_parser.add_argument('-t', '--tenant', action='store', required=True, help='Tenant ID where device exists')

    # Construct PRT module
    prt_parser = subparsers.add_parser('prt', help='PRT request/renewal module')
    prt_parser.add_argument('-a',
                            '--action',
                            action='store',
                            choices=['request', 'renew'],
                            default='request',
                            help='Action to perform (default: request)')
    prt_parser.add_argument('-c', '--cert-pem', action='store', metavar='file', help='Certificate file with device certificate')
    prt_parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file for device')
    prt_parser.add_argument('--cert-pfx', action='store', metavar='file', help='Device cert and key as PFX file')
    prt_parser.add_argument('--pfx-pass', action='store', metavar='password', help='PFX file password')
    prt_parser.add_argument('--pfx-base64', action='store', metavar='BASE64', help='PFX file as base64 string')
    prt_parser.add_argument('-tk', '--transport-key-pem', action='store', metavar='file', help='Private key file containing transport key (if different from device key)')

    prt_parser.add_argument('-u', '--username', action='store', metavar='USER', help='User to authenticate')
    prt_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password')
    prt_parser.add_argument('-r', '--refresh-token', action='store', help='Refresh token')
    prt_parser.add_argument('--saml-token', action='store', help='SAML token for federated auth (use value stdin to read from input)')



    prt_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (to save or load in case of renewal)')
    prt_parser.add_argument('--prt', action='store', metavar='PRT', help='Primary Refresh Token (for renewal)')
    prt_parser.add_argument('-s', '--prt-sessionkey', action='store', help='Primary Refresh Token session key (as hex key)')

    prt_parser.add_argument('-hk', '--hello-key', action='store', help='Windows Hello PEM file')
    prt_parser.add_argument('-ha', '--hello-assertion', action='store', help='Windows Hello assertion as JWT')

    # Construct winhello module
    winhello_parser = subparsers.add_parser('winhello', help='Register Windows Hello key')
    winhello_parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file for key storage (default: winhello.key)')
    winhello_parser.add_argument('--access-token', action='store', help='Access token for device registration service. If not specified, taken from .roadtools_auth')

    # Construct winhello key generation module - included for reference
    # winhello_parser = subparsers.add_parser('genhellokey', help='Generate Windows Hello key')
    # winhello_parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file for key storage (default: winhello.key)')
    # winhello_parser.add_argument('-d', '--device-id', action='store', help='Device ID to use for key object')

    # Construct PRT authmodule
    prtauth_parser = subparsers.add_parser('prtauth', help='Authenticate using a PRT (emulates WAM token broker)')
    helptext = 'Client ID to use when authenticating.'
    prtauth_parser.add_argument('-c',
                                '--client',
                                action='store',
                                help=helptext,
                                default='1b730954-1685-4b74-9bfd-dac224a7b894')
    prtauth_parser.add_argument('-r',
                                '--resource',
                                action='store',
                                help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                default='https://graph.windows.net')
    prtauth_parser.add_argument('-ru', '--redirect-url', action='store', metavar='URL',
                                 help='Custom redirect URL used when authenticating (default: ms-appx-web://Microsoft.AAD.BrokerPlugin/<clientid>)')
    prtauth_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (default: roadtx.prt)')
    prtauth_parser.add_argument('--prt',
                                action='store',
                                help='Primary Refresh Token')
    prtauth_parser.add_argument('--prt-sessionkey',
                                action='store',
                                help='Primary Refresh Token session key (as hex key)')
    prtauth_parser.add_argument('--tokenfile',
                                action='store',
                                help='File to store the credentials (default: .roadtools_auth)',
                                default='.roadtools_auth')
    prtauth_parser.add_argument('--tokens-stdout',
                                action='store_true',
                                help='Do not store tokens on disk, pipe to stdout instead')
    prtauth_parser.add_argument('-ua', '--user-agent', action='store',
                                help='Custom user agent to use. Default: Python requests user agent')
    prtauth_parser.add_argument('-t',
                                '--tenant',
                                action='store',
                                help='Tenant ID or domain to auth to')
    prtauth_parser.add_argument('--cae',
                                action='store_true',
                                help='Request Continuous Access Evaluation tokens')

    prtauth_parser.add_argument('-s',
                                '--scope',
                                action='store',
                                help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    prtauth_parser.add_argument('-v3', '--prt-protocol-v3', action='store_true', help='Use PRT protocol version v3')

    # Application auth
    appauth_parser = subparsers.add_parser('appauth', help='Authenticate as an application')
    helptext = 'Client ID (application ID) to use when authenticating.'
    appauth_parser.add_argument('-c',
                                '--client',
                                action='store',
                                help=helptext,
                                default='1b730954-1685-4b74-9bfd-dac224a7b894')
    appauth_parser.add_argument('-p',
                                '--password',
                                action='store',
                                help="Client secret or password credential for the application, if not using certificates")
    appauth_parser.add_argument('-r',
                                '--resource',
                                action='store',
                                help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                default='https://graph.windows.net')
    appauth_parser.add_argument('-s',
                                '--scope',
                                action='store',
                                help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    appauth_parser.add_argument('-t',
                                '--tenant',
                                action='store',
                                help='Tenant ID or domain to auth to',
                                required=True)
    appauth_parser.add_argument('--cert-pem', action='store', metavar='file', help='Certificate file with Application certificate')
    appauth_parser.add_argument('--key-pem', action='store', metavar='file', help='Private key file for Application')
    appauth_parser.add_argument('--cert-pfx', action='store', metavar='file', help='Application cert and key as PFX file')
    appauth_parser.add_argument('--pfx-pass', action='store', metavar='password', help='PFX file password')
    appauth_parser.add_argument('--pfx-base64', action='store', metavar='BASE64', help='PFX file as base64 string')
    appauth_parser.add_argument('--cae',
                                action='store_true',
                                help='Request Continuous Access Evaluation tokens (requires use of scope parameter instead of resource)')
    appauth_parser.add_argument('-ua', '--user-agent', action='store',
                                help='Custom user agent to use. Default: Python requests user agent')
    appauth_parser.add_argument('--tokenfile',
                                action='store',
                                help='File to store the credentials (default: .roadtools_auth)',
                                default='.roadtools_auth')
    appauth_parser.add_argument('--tokens-stdout',
                                action='store_true',
                                help='Do not store tokens on disk, pipe to stdout instead')

    # Code grant flow auth
    codeauth_parser = subparsers.add_parser('codeauth', help='Code grant flow - exchange code for auth tokens')
    clienthelptext = 'Client ID (application ID) to use when authenticating. Accepts aliases (list with roadtx listaliases)'
    codeauth_parser.add_argument('-c',
                                 '--client',
                                 action='store',
                                 help=clienthelptext,
                                 default='1b730954-1685-4b74-9bfd-dac224a7b894')
    codeauth_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password secret of the application if not a public app')
    codeauth_parser.add_argument('-r',
                                 '--resource',
                                 action='store',
                                 help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                 default='https://graph.windows.net')
    codeauth_parser.add_argument('-s',
                                 '--scope',
                                 action='store',
                                 help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    codeauth_parser.add_argument('-ru', '--redirect-url', action='store', metavar='URL',
                                 help='Redirect URL used when authenticating (default: https://login.microsoftonline.com/common/oauth2/nativeclient)',
                                 default="https://login.microsoftonline.com/common/oauth2/nativeclient")
    codeauth_parser.add_argument('-t',
                                 '--tenant',
                                 action='store',
                                 help='Tenant ID or domain to auth to')
    codeauth_parser.add_argument('--tokenfile',
                                 action='store',
                                 help='File to store the credentials (default: .roadtools_auth)',
                                 default='.roadtools_auth')
    codeauth_parser.add_argument('--tokens-stdout',
                                 action='store_true',
                                 help='Do not store tokens on disk, pipe to stdout instead')
    codeauth_parser.add_argument('--cae',
                                 action='store_true',
                                 help='Request Continuous Access Evaluation tokens (requires use of scope parameter instead of resource)')
    codeauth_parser.add_argument('code',
                                 action='store',
                                 help="Code to auth with that you got from Azure AD")

    # Bulk enrollment token
    bulkenrollment_parser = subparsers.add_parser('bulkenrollmenttoken', help='Request / use bulk enrollment tokens')
    bulkenrollment_parser.add_argument('--access-token', action='store', help='Access token for the device registration service. If not specified, taken from .roadtools_auth or file specified with --tokenfile')
    bulkenrollment_parser.add_argument('-a',
                                       '--action',
                                       action='store',
                                       choices=['request', 'use'],
                                       default='request',
                                       help='Action to perform (default: request)')
    bulkenrollment_parser.add_argument('--bulktokenfile',
                                       action='store',
                                       default='.bulktoken',
                                       help='File to save / load bulk enrollment token from (default: .bulktoken)')
    bulkenrollment_parser.add_argument('--tokenfile',
                                       action='store',
                                       default='.roadtools_auth',
                                       help='File to save / load the access token for device registration service to / from')
    bulkenrollment_parser.add_argument('--tokens-stdout',
                                       action='store_true',
                                       help='Do not store tokens on disk, pipe to stdout instead')

    # Desktop SSO auth
    desktopsso_parser = subparsers.add_parser('desktopsso', help='Desktop SSO authentication - either with plaintext creds or Kerberos auth')
    clienthelptext = 'Client ID (application ID) to use when authenticating. Accepts aliases (list with roadtx listaliases)'
    desktopsso_parser.add_argument('-c',
                                   '--client',
                                   action='store',
                                   help=clienthelptext,
                                   default='1b730954-1685-4b74-9bfd-dac224a7b894')
    desktopsso_parser.add_argument('-u', '--username', action='store', metavar='USER', help='User to authenticate')
    desktopsso_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password of the user')
    desktopsso_parser.add_argument('--krbtoken',
                                   action='store',
                                   help='Kerberos auth data from krbsso.py')
    desktopsso_parser.add_argument('-r',
                                   '--resource',
                                   action='store',
                                   help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                   default='https://graph.windows.net')
    desktopsso_parser.add_argument('-t',
                                   '--tenant',
                                   action='store',
                                   required=True,
                                   help='Tenant ID or domain to auth to')
    desktopsso_parser.add_argument('--tokenfile',
                                   action='store',
                                   help='File to store the credentials (default: .roadtools_auth)',
                                   default='.roadtools_auth')
    desktopsso_parser.add_argument('--tokens-stdout',
                                   action='store_true',
                                   help='Do not store tokens on disk, pipe to stdout instead')
    desktopsso_parser.add_argument('-ua', '--user-agent', action='store',
                                   help='Custom user agent to use. By default the user agent from FireFox is used without modification')


    # List aliases
    subparsers.add_parser('listaliases', help='List aliases that can be used as client ID or resource URL')

    # Decrypt utilities
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt data using session key or transport key')
    decrypt_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (to load the session key)')
    decrypt_parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file containing transport key')
    decrypt_parser.add_argument('--cert-pfx', action='store', metavar='file', help='Device cert and key as PFX file')
    decrypt_parser.add_argument('--pfx-pass', action='store', metavar='password', help='PFX file password')
    decrypt_parser.add_argument('--pfx-base64', action='store', metavar='BASE64', help='PFX file as base64 string')
    decrypt_parser.add_argument('-s', '--prt-sessionkey', action='store', help='Primary Refresh Token session key (as hex key)')
    decrypt_parser.add_argument('-v', '--verbose', action='store_true', help='Show extra information')
    decrypt_parser.add_argument('data', action='store', metavar='FILE', help='Data to decrypt (as JWE token)')

    # Describe token
    describe_parser = subparsers.add_parser('describe', help='Decode and describe an access token')
    describe_parser.add_argument('-t', '--token', default=None, action='store', metavar='TOKEN', help='Token data to describe. Defaults to reading from stdin')
    describe_parser.add_argument('-f', '--tokenfile', action='store', help='File to read the token from (default: .roadtools_auth)', default='.roadtools_auth')
    describe_parser.add_argument('-v', '--verbose', action='store_true', help='Show extra information')

    # Find scope
    getscope_parser = subparsers.add_parser('getscope', aliases=['findscope'], help='Find first-party apps with the right pre-approved scope')
    getscope_parser.add_argument('-s', '--scope', default=None, action='store', required=False, metavar='SCOPE', help='Desired scope (API URL + scope on that API, for example https://graph.microsoft.com/files.read).')
    getscope_parser.add_argument('-a', '--all', action='store_true', help='List all scopes instead')
    getscope_parser.add_argument('--foci', action='store_true', help='Only list FOCI clients')
    getscope_parser.add_argument('--csv', action='store_true', help='Output in CSV format')

    # Get OTP
    otpparser = subparsers.add_parser('getotp', help='Get OTP code from seed, either supplied or from KeePass file')
    otpparser.add_argument('-u', '--username', action='store', help='User to query from KeePass file')
    otpparser.add_argument('-s', '--otpseed', action='store', help='OTP secret seed')
    otpparser.add_argument('-kp', '--keepass', action='store', metavar='KPFILE', default='roadtx.kdbx', help='KeePass file (default: roadtx.kdbx)')
    otpparser.add_argument('-kpp', '--keepass-password', action='store', metavar='KPPASS', help='KeePass file password. Can also be provided via KPPASS environment variable.')


    # Interactive auth using Selenium
    urlhelp = 'Url to initiate browsing. Will be constructed from below parameters if not supplied.'
    intauth_parser = subparsers.add_parser('interactiveauth', help='Interactive authentication in Selenium browser window, optional autofill')
    intauth_parser.add_argument('-u', '--username', action='store', metavar='USER', help='User to authenticate')
    intauth_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password of the user')
    intauth_parser.add_argument('--krbtoken',
                                action='store',
                                help='Kerberos auth data from krbsso.py')
    intauth_parser.add_argument('--estscookie',
                                action='store',
                                help='ESTSAUTHPERSISTENT cookie from browser')
    intauth_parser.add_argument('-url', '--auth-url', action='store', metavar='URL', help=urlhelp)
    intauth_parser.add_argument('-c',
                                '--client',
                                action='store',
                                help=clienthelptext,
                                default='1b730954-1685-4b74-9bfd-dac224a7b894')
    intauth_parser.add_argument('-r',
                                '--resource',
                                action='store',
                                help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                default='https://graph.windows.net')
    intauth_parser.add_argument('-s',
                                '--scope',
                                action='store',
                                help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    intauth_parser.add_argument('-ru', '--redirect-url', action='store', metavar='URL',
                                help='Redirect URL used when authenticating (default: https://login.microsoftonline.com/common/oauth2/nativeclient)',
                                default="https://login.microsoftonline.com/common/oauth2/nativeclient")
    intauth_parser.add_argument('-ua', '--user-agent', action='store',
                                help='Custom user agent to use. By default the user agent from FireFox is used without modification')
    intauth_parser.add_argument('-t',
                                '--tenant',
                                action='store',
                                help='Tenant ID or domain to auth to')
    intauth_parser.add_argument('--tokenfile',
                                action='store',
                                help='File to store the credentials (default: .roadtools_auth)',
                                default='.roadtools_auth')
    intauth_parser.add_argument('--tokens-stdout',
                                action='store_true',
                                help='Do not store tokens on disk, pipe to stdout instead')
    intauth_parser.add_argument('-d', '--driver-path',
                                action='store',
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)')
    intauth_parser.add_argument('-k', '--keep-open',
                                action='store_true',
                                help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')
    intauth_parser.add_argument('--capture-code',
                                action='store_true',
                                help='Do not attempt to redeem any authentication code but print it instead')
    intauth_parser.add_argument('--federated',
                                action='store_true',
                                help='Fill in password on Federation server login page (assumes AD FS)')
    intauth_parser.add_argument('--cae',
                                action='store_true',
                                help='Request Continuous Access Evaluation tokens (requires use of scope parameter instead of resource)')

    # Interactive auth using Selenium - creds from keepass
    kdbauth_parser = subparsers.add_parser('keepassauth', help='Selenium based authentication with credentials from a KeePass database')
    kdbauth_parser.add_argument('-u', '--username', action='store', help='User to authenticate as (must exist as username in KeePass)')
    kdbauth_parser.add_argument('-kp', '--keepass', action='store', metavar='KPFILE', default='roadtx.kdbx', help='KeePass file (default: roadtx.kdbx)')
    kdbauth_parser.add_argument('-kpp', '--keepass-password', action='store', metavar='KPPASS', help='KeePass file password. Can also be provided via KPPASS environment variable.')
    kdbauth_parser.add_argument('-url', '--auth-url', action='store', metavar='URL', help=urlhelp)
    kdbauth_parser.add_argument('-c',
                                '--client',
                                action='store',
                                help=clienthelptext,
                                default='1b730954-1685-4b74-9bfd-dac224a7b894')
    kdbauth_parser.add_argument('-r',
                                '--resource',
                                action='store',
                                help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                default='https://graph.windows.net')
    kdbauth_parser.add_argument('-s',
                                '--scope',
                                action='store',
                                help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    kdbauth_parser.add_argument('-ru', '--redirect-url', action='store', metavar='URL',
                                help='Redirect URL used when authenticating (default: https://login.microsoftonline.com/common/oauth2/nativeclient)',
                                default="https://login.microsoftonline.com/common/oauth2/nativeclient")
    kdbauth_parser.add_argument('-ua', '--user-agent', action='store',
                                help='Custom user agent to use. By default the user agent from FireFox is used without modification')
    kdbauth_parser.add_argument('-t',
                                '--tenant',
                                action='store',
                                help='Tenant ID or domain to auth to')
    kdbauth_parser.add_argument('--tokenfile',
                                action='store',
                                help='File to store the credentials (default: .roadtools_auth)',
                                default='.roadtools_auth')
    kdbauth_parser.add_argument('--tokens-stdout',
                                action='store_true',
                                help='Do not store tokens on disk, pipe to stdout instead')
    kdbauth_parser.add_argument('-d', '--driver-path',
                                action='store',
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)')
    kdbauth_parser.add_argument('-k', '--keep-open',
                                action='store_true',
                                help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')
    kdbauth_parser.add_argument('--capture-code',
                                action='store_true',
                                help='Do not attempt to redeem any authentication code but print it instead')
    kdbauth_parser.add_argument('--federated',
                                action='store_true',
                                help='Fill in password on Federation server login page (assumes AD FS)')
    kdbauth_parser.add_argument('--device-code',
                                action='store',
                                help='Authenticate with the given device code')
    kdbauth_parser.add_argument('--cae',
                                action='store_true',
                                help='Request Continuous Access Evaluation tokens (requires use of scope parameter instead of resource)')



    # Interactive auth using Selenium - inject PRT
    browserprtauth_parser = subparsers.add_parser('browserprtauth', help='Selenium based auth with automatic PRT usage. Emulates Edge browser with PRT')
    browserprtauth_parser.add_argument('-url', '--auth-url', action='store', metavar='URL', help=urlhelp)
    browserprtauth_parser.add_argument('-c',
                                       '--client',
                                       action='store',
                                       help=helptext,
                                       default='1b730954-1685-4b74-9bfd-dac224a7b894')
    browserprtauth_parser.add_argument('-r',
                                       '--resource',
                                       action='store',
                                       help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                       default='https://graph.windows.net')
    browserprtauth_parser.add_argument('-s',
                                       '--scope',
                                       action='store',
                                       help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    browserprtauth_parser.add_argument('-ru', '--redirect-url', action='store', metavar='URL',
                                       help='Redirect URL used when authenticating (default: https://login.microsoftonline.com/common/oauth2/nativeclient)',
                                       default="https://login.microsoftonline.com/common/oauth2/nativeclient")
    browserprtauth_parser.add_argument('-ua', '--user-agent', action='store',
                                       help='Custom user agent to use. Default: Chrome on Windows user agent')
    browserprtauth_parser.add_argument('-t',
                                       '--tenant',
                                       action='store',
                                       help='Tenant ID or domain to auth to')
    browserprtauth_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (default: roadtx.prt)')
    browserprtauth_parser.add_argument('--prt',
                                       action='store',
                                       help='Primary Refresh Token')
    browserprtauth_parser.add_argument('--prt-sessionkey',
                                       action='store',
                                       help='Primary Refresh Token session key (as hex key)')
    browserprtauth_parser.add_argument('--prt-cookie',
                                       action='store',
                                       help='Primary Refresh Token cookie from ROADtoken (JWT)')
    browserprtauth_parser.add_argument('--tokenfile',
                                       action='store',
                                       help='File to store the credentials (default: .roadtools_auth)',
                                       default='.roadtools_auth')
    browserprtauth_parser.add_argument('--tokens-stdout',
                                       action='store_true',
                                       help='Do not store tokens on disk, pipe to stdout instead')
    browserprtauth_parser.add_argument('-d', '--driver-path',
                                       action='store',
                                       help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)')
    browserprtauth_parser.add_argument('-k', '--keep-open',
                                       action='store_true',
                                       help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')
    browserprtauth_parser.add_argument('--capture-code',
                                       action='store_true',
                                       help='Do not attempt to redeem any authentication code but print it instead')
    browserprtauth_parser.add_argument('--cae',
                                       action='store_true',
                                       help='Request Continuous Access Evaluation tokens (requires use of scope parameter instead of resource)')

    # Interactive auth using Selenium - inject PRT to other user
    injauth_parser = subparsers.add_parser('browserprtinject', help='Selenium based auth with automatic PRT injection. Can be used with other users to add device state to session')
    injauth_parser.add_argument('-u', '--username', action='store', metavar='USER', help='User to authenticate (optional, otherwise you have to specify it by hand)')
    injauth_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password of the user (can be left out if using PRT, or KeePass creds)')
    injauth_parser.add_argument('-kp', '--keepass', action='store', metavar='KPFILE', default='roadtx.kdbx', help='KeePass file (default: roadtx.kdbx)')
    injauth_parser.add_argument('-kpp', '--keepass-password', action='store', metavar='KPPASS', help='KeePass file password. Can also be provided via KPPASS environment variable.')
    injauth_parser.add_argument('-url', '--auth-url', action='store', metavar='URL', help=urlhelp)
    injauth_parser.add_argument('-c',
                                '--client',
                                action='store',
                                help=clienthelptext,
                                default='1b730954-1685-4b74-9bfd-dac224a7b894')
    injauth_parser.add_argument('-r',
                                '--resource',
                                action='store',
                                help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                default='https://graph.windows.net')
    injauth_parser.add_argument('-s',
                                '--scope',
                                action='store',
                                help='Scope to use. Will automatically switch to v2.0 auth endpoint if specified. If unsure use -r instead.')
    injauth_parser.add_argument('-ru', '--redirect-url', action='store', metavar='URL',
                                help='Redirect URL used when authenticating (default: https://login.microsoftonline.com/common/oauth2/nativeclient)',
                                default="https://login.microsoftonline.com/common/oauth2/nativeclient")
    injauth_parser.add_argument('-ua', '--user-agent', action='store',
                                help='Custom user agent to use. Default: Chrome on Windows user agent')
    injauth_parser.add_argument('-t',
                                '--tenant',
                                action='store',
                                help='Tenant ID or domain to auth to')
    injauth_parser.add_argument('-d', '--driver-path',
                                action='store',
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)')
    injauth_parser.add_argument('-k', '--keep-open',
                                action='store_true',
                                help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')
    injauth_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (default: roadtx.prt)')
    injauth_parser.add_argument('--prt',
                                action='store',
                                help='Primary Refresh Token')
    injauth_parser.add_argument('--prt-sessionkey',
                                action='store',
                                help='Primary Refresh Token session key (as hex key)')
    injauth_parser.add_argument('--prt-cookie',
                                action='store',
                                help='Primary Refresh Token cookie from ROADtoken (JWT)')
    injauth_parser.add_argument('--tokenfile',
                                action='store',
                                help='File to store the credentials (default: .roadtools_auth)',
                                default='.roadtools_auth')
    injauth_parser.add_argument('--tokens-stdout',
                                action='store_true',
                                help='Do not store tokens on disk, pipe to stdout instead')
    injauth_parser.add_argument('--cae',
                                action='store_true',
                                help='Request Continuous Access Evaluation tokens (requires use of scope parameter instead of resource)')

    # Interactive auth using Selenium - enrich PRT
    enrauth_parser = subparsers.add_parser('prtenrich', help='Interactive authentication to add MFA claim to a PRT')
    enrauth_parser.add_argument('-u', '--username', action='store', metavar='USER', help='User in the prt')
    enrauth_parser.add_argument('-kp', '--keepass', action='store', metavar='KPFILE', default='roadtx.kdbx', help='KeePass file (default: roadtx.kdbx)')
    enrauth_parser.add_argument('-kpp', '--keepass-password', action='store', metavar='KPPASS', help='KeePass file password. Can also be provided via KPPASS environment variable.')
    enrauth_parser.add_argument('-d', '--driver-path',
                                action='store',
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)')
    enrauth_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (default: roadtx.prt)')
    enrauth_parser.add_argument('-ua', '--user-agent', action='store',
                                help='Custom user agent to use. Default: Chrome on Windows user agent')
    enrauth_parser.add_argument('--no-prt', action='store_true', help='Perform the flow without a PRT')
    enrauth_parser.add_argument('--prt',
                                action='store',
                                help='Primary Refresh Token')
    enrauth_parser.add_argument('--prt-sessionkey',
                                action='store',
                                help='Primary Refresh Token session key (as hex key)')
    enrauth_parser.add_argument('--ngcmfa-drs-auth', action='store_true', help="Don't request PRT with MFA claim but get access token with ngcmfa claim for DRS instead.")
    enrauth_parser.add_argument('--tokenfile',
                                action='store',
                                help='File to store the credentials (default: .roadtools_auth)',
                                default='.roadtools_auth')
    enrauth_parser.add_argument('--tokens-stdout',
                                action='store_true',
                                help='Do not store tokens on disk, pipe to stdout instead')

    # ADFS Encrypted blob decrypt
    adfsdec_parser = subparsers.add_parser('decryptadfskey', help='Decrypt Encrypted PFX blob from ADFSpoof into PEM or PFX file')
    adfsdec_parser.add_argument('-c', '--cert-pem', action='store', metavar='file', default='roadtx_adfs.pem', help='Certificate file to save ADFS cert (default: roadtx_adfs.pem)')
    adfsdec_parser.add_argument('-k', '--key-pem', action='store', metavar='file', default='roadtx_adfs.key', help='Private key file to save ADFS key (default: roadtx_adfs.key)')
    adfsdec_parser.add_argument('--cert-pfx', action='store', metavar='file', default='roadtx_adfs.pfx', help='File to store the key (default: roadtx_adfs.pfx)')
    adfsdec_parser.add_argument('-o', '--output-format', action='store', metavar='format', default='pem', choices=['pem', 'pfx'], help='Output format (pem or pfx), default: pem')
    adfsdec_parser.add_argument('encryptedpfx', action='store', metavar='pfxblob', help='EncryptedPFX data from ADFSpoof')
    adfsdec_parser.add_argument('key', action='store', metavar='key', help='Decryption key (DKM key)')
    adfsdec_parser.add_argument('-v', '--verbose', action='store_true', help='Show extra information')

    # ADFS token generation
    samltoken_parser = subparsers.add_parser('samltoken', help='Create a SAML token using an AD FS key')
    samltoken_parser.add_argument('-c', '--cert-pem', action='store', metavar='file', help='Certificate file with AD FS cert')
    samltoken_parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file with AD FS key')
    samltoken_parser.add_argument('--cert-pfx', action='store', metavar='file', help='PFX file with AD FS cert/key')
    samltoken_parser.add_argument('--pfx-pass', action='store', metavar='password', help='PFX file password')
    samltoken_parser.add_argument('--pfx-base64', action='store', metavar='BASE64', help='PFX file as base64 string')
    samltoken_parser.add_argument('-i', '--issuer', action='store', required=True, help='Token issuer, must match the federated domain name (without http/https, example: federated.mycompany.com)')
    samltoken_parser.add_argument('-u', '--unique-id', action='store', help='Unique ID of user to spoof (immutableId in roadrecon)')
    samltoken_parser.add_argument('-g', '--guid', action='store', help='GUID of user to spoof (from AD), if not specifying the unique id')
    samltoken_parser.add_argument('-m', '--mfa', action='store_true', help='Include MFA claim in token')
    samltoken_parser.add_argument('--upn', action='store', required=True, help='userPrincipalName of user to spoof')

    # PRT cookie creations
    prtcookie_parser = subparsers.add_parser('prtcookie', help='Create a PRT cookie from a PRT for external usage')
    prtcookie_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (default: roadtx.prt)')
    prtcookie_parser.add_argument('--prt',
                                  action='store',
                                  help='Primary Refresh Token')
    prtcookie_parser.add_argument('--prt-sessionkey',
                                  action='store',
                                  help='Primary Refresh Token session key (as hex key)')

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
        return

    deviceauth = DeviceAuthentication(auth)
    args = parser.parse_args()
    seleniumproxy = None

    if args.proxy:
        auth.proxies = deviceauth.proxies = {
            'https': f'http://{args.proxy}'
        }
        seleniumproxy = f'http://{args.proxy}'
        if not args.secure:
            auth.verify = deviceauth.verify = False

    if args.command in ('auth', 'gettokens', 'gettoken'):
        auth.parse_args(args)
        if not args.tokens_stdout:
            if args.scope:
                print(f'Requesting token with scope {auth.scope}')
            else:
                print(f'Requesting token for resource {auth.resource_uri}')
        res = auth.get_tokens(args)
        if not res:
            return
        auth.save_tokens(args)
    elif args.command == 'refreshtokento':
        try:
            with codecs.open('.roadtools_auth', 'r', 'utf-8') as infile:
                tokenobject = json.load(infile)
            _, tokendata = auth.parse_accesstoken(tokenobject['accessToken'])
        except FileNotFoundError:
            print('This command requires the .roadtools_auth file, which was not found. Use the gettokens command to supply a refresh token manually.')
            return
        auth.set_client_id(tokenobject['_clientId'])
        auth.set_resource_uri(args.resource)
        auth.set_user_agent(args.user_agent)
        auth.outfile = args.tokenfile
        # Tenant from arguments or from tokenfile
        if args.tenant:
            auth.tenant = args.tenant
        elif 'tenantId' in tokenobject:
            auth.tenant = tokenobject['tenantId']
        if args.client:
            auth.set_client_id(args.client)
        if args.cae:
            auth.use_cae = args.cae
        if not args.tokens_stdout:
            if args.scope:
                print(f'Requesting token with scope {args.scope}')
            else:
                print(f'Requesting token for resource {auth.resource_uri}')
        if args.scope:
            auth.scope = args.scope
            auth.authenticate_with_refresh_native_v2(tokenobject['refreshToken'], client_secret=args.password)
        else:
            auth.authenticate_with_refresh_native(tokenobject['refreshToken'], client_secret=args.password)
        auth.save_tokens(args)
    elif args.command == 'appauth':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        auth.scope = args.scope
        auth.use_cae = args.cae
        auth.tenant = args.tenant
        auth.outfile = args.tokenfile
        if args.password:
            # Password based flow
            if args.scope:
                auth.authenticate_as_app_native_v2(client_secret=args.password)
            else:
                auth.authenticate_as_app_native(client_secret=args.password)
        else:
            if not auth.loadappcert(args.cert_pem, args.key_pem, args.cert_pfx, args.pfx_pass, args.pfx_base64):
                return
            if args.scope:
                assertion = auth.generate_app_assertion(use_v2=True)
                auth.authenticate_as_app_native_v2(assertion=assertion)
            else:
                assertion = auth.generate_app_assertion(use_v2=False)
                auth.authenticate_as_app_native(assertion=assertion)
        auth.save_tokens(args)
    elif args.command == 'device':
        if args.action in ('register', 'join'):
            if args.access_token:
                tokenobject, tokendata = auth.parse_accesstoken(args.access_token)
            else:
                try:
                    with codecs.open('.roadtools_auth', 'r', 'utf-8') as infile:
                        tokenobject = json.load(infile)
                    _, tokendata = auth.parse_accesstoken(tokenobject['accessToken'])
                except FileNotFoundError:
                    print('No auth data found. Ether supply an access token with --access-token or make sure a token is present on disk in .roadtools_auth')
                    return
            if tokendata['aud'] != 'urn:ms-drs:enterpriseregistration.windows.net':
                print(f"Wrong token audience, got {tokendata['aud']} but expected: urn:ms-drs:enterpriseregistration.windows.net")
                print("Make sure to request a token with -r urn:ms-drs:enterpriseregistration.windows.net")
                return
            if args.action == 'join':
                jointype = 0
            else:
                jointype = 4
            deviceauth.register_device(tokenobject['accessToken'], jointype=jointype, certout=args.cert_pem, privout=args.key_pem, device_type=args.device_type, device_name=args.name, os_version=args.os_version, deviceticket=args.deviceticket)
        elif args.action == 'delete':
            if not deviceauth.loadcert(args.cert_pem, args.key_pem):
                return
            deviceauth.delete_device(args.cert_pem, args.key_pem)
    elif args.command == 'hybriddevice':
        if not deviceauth.loadcert(args.cert_pem, args.key_pem, args.cert_pfx, args.pfx_pass, args.pfx_base64):
            return
        deviceauth.register_hybrid_device(args.sid, args.tenant, certout=args.cert_pem, privout=args.key_pem, device_type=args.device_type, device_name=args.name, os_version=args.os_version)
    elif args.command == 'prt':
        if args.action == 'request':
            if not deviceauth.loadcert(args.cert_pem, args.key_pem, args.cert_pfx, args.pfx_pass, args.pfx_base64):
                return
            if args.transport_key_pem:
                # Try loading transport key separately
                if not deviceauth.loadkey(args.transport_key_pem, transport_only=True):
                    return
            prtdata = None
            if args.username and args.password:
                prtdata = deviceauth.get_prt_with_password(args.username, args.password)
            if args.saml_token:
                if args.saml_token.lower() == 'stdin':
                    samltoken = sys.stdin.read()
                else:
                    samltoken = args.saml_token
                prtdata = deviceauth.get_prt_with_samltoken(samltoken)
            if args.refresh_token:
                if args.refresh_token.lower() == 'file':
                    with codecs.open('.roadtools_auth', 'r', 'utf-8') as infile:
                        tokenobject = json.load(infile)
                    try:
                        refresh_token = tokenobject['refreshToken']
                    except KeyError:
                        print('No refresh token found in token file!')
                        return
                else:
                    refresh_token = args.refresh_token
                prtdata = deviceauth.get_prt_with_refresh_token(refresh_token)

            if args.username and deviceauth.loadhellokey(args.hello_key):
                prtdata = deviceauth.get_prt_with_hello_key(args.username)
            if args.username and args.hello_assertion:
                prtdata = deviceauth.get_prt_with_hello_key(args.username, args.hello_assertion)
            if not prtdata:
                print('You must specify a username + password or refresh token that can be used to request a PRT')
                return
            print(f"Obtained PRT: {prtdata['refresh_token']}")
            print(f"Obtained session key: {prtdata['session_key']}")
            deviceauth.saveprt(prtdata, args.prt_file)
        if args.action == 'renew':
            if args.prt and args.prt_sessionkey:
                deviceauth.setprt(args.prt, args.prt_sessionkey)
            elif args.prt_file and deviceauth.loadprt(args.prt_file):
                pass
            else:
                print('You must either supply a PRT and session key on the command line or a file that contains them')
                return
            print("Renewing PRT")
            prtdata = deviceauth.renew_prt()
            deviceauth.saveprt(prtdata, args.prt_file)
    elif args.command == 'prtauth':
        auth.set_user_agent(args.user_agent)
        auth.use_cae = args.cae
        auth.scope = args.scope
        if args.tenant:
            auth.tenant = args.tenant
        if args.prt and args.prt_sessionkey:
            deviceauth.setprt(args.prt, args.prt_sessionkey)
        elif args.prt_file and deviceauth.loadprt(args.prt_file):
            pass
        else:
            print('You must either supply a PRT and session key on the command line or a file that contains them')
            return
        tokendata = deviceauth.aad_brokerplugin_prt_auth(args.client, args.resource, redirect_uri=args.redirect_url)
        # We need to convert this to a token format roadlib understands
        if 'access_token' in tokendata:
            tokenobject, _ = auth.parse_accesstoken(tokendata['access_token'])
            tokenobject['expiresIn'] = tokendata['expires_in']
            tokenobject['refreshToken'] = tokendata['refresh_token']
            auth.outfile = args.tokenfile
            auth.tokendata = tokenobject
            auth.save_tokens(args)
        else:
            print('No access token in token data, assuming custom request')
            print(tokendata)
    elif args.command == 'decrypt':
        header, enc_key, iv, ciphertext, auth_tag = auth.parse_compact_jwe(args.data, args.verbose)
        if header['alg'] == 'RSA-OAEP':
            if not deviceauth.loadkey(args.key_pem, args.cert_pfx, args.pfx_pass, args.pfx_base64):
                print('Data is encrypted with transport key but no such key could be loaded with the specified parameters')
                return
            decrypted = deviceauth.decrypt_jwe_with_transport_key(args.data)
            print('Decrypted key (hex):')
            print(binascii.hexlify(decrypted).decode('utf-8'))
            print('Decrypted key plain:')
            print(repr(decrypted))
        else:
            if args.prt_sessionkey:
                deviceauth.setprt(None, args.prt_sessionkey)
            elif args.prt_file and deviceauth.loadprt(args.prt_file):
                pass
            else:
                print('You must either supply a session key on the command line or a file that contains them')
                print('Data is encrypted with session key but no such key could be loaded with the specified parameters')
                return
            data = auth.decrypt_auth_response(args.data, deviceauth.session_key)
            print('Decrypted data:')
            print(repr(data))
            try:
                parsed = json.loads(data)
                print('Decrypted data (parsed)')
                print(json.dumps(parsed, sort_keys=True, indent=4))
            except (json.decoder.JSONDecodeError, UnicodeDecodeError):
                print('Decrypted data (hex)')
                print(binascii.hexlify(data))

    elif args.command == 'codeauth':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        auth.tenant = args.tenant
        if args.cae:
            auth.use_cae = args.cae
        if args.scope:
            # Switch to identity platform v2 and use scope instead of resource
            auth.scope = args.scope
            auth.authenticate_with_code_native_v2(args.code, args.redirect_url, client_secret=args.password)
        else:
            auth.authenticate_with_code_native(args.code, args.redirect_url, client_secret=args.password)
        auth.outfile = args.tokenfile
        auth.save_tokens(args)
    elif args.command == 'desktopsso':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        auth.set_user_agent(args.user_agent)
        auth.tenant = args.tenant
        if args.krbtoken and args.krbtoken.lower() == 'stdin':
            krbtoken = sys.stdin.read().strip()
        else:
            krbtoken = args.krbtoken
        dsso_code = auth.get_desktopsso_token(args.username, args.password, krbtoken)
        if dsso_code:
            auth.authenticate_with_desktopsso_token(dsso_code)
            auth.outfile = args.tokenfile
            auth.save_tokens(args)
    elif args.command == 'listaliases':
        print('Well-known clients. Can be used as alias with -c or --client')
        print()
        for alias, clientid in WELLKNOWN_CLIENTS.items():
            print(f"{alias:<10} - {clientid}")
        print()
        print('Well-known resources. Can be used as alias with -r or --resource')
        print()
        for alias, resourceurl in WELLKNOWN_RESOURCES.items():
            print(f"{alias:<10} - {resourceurl}")
        print()
        print('Well-known user agents. Can be used as alias with -ua or --user-agent')
        print()
        for alias, useragent in WELLKNOWN_USER_AGENTS.items():
            print(f"{alias:<15} - {useragent}")
    elif args.command == 'interactiveauth':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        auth.set_user_agent(args.user_agent)
        auth.tenant = args.tenant
        auth.use_cae = args.cae
        if args.scope:
            auth.scope = args.scope
        # Intercept if custom UA is set
        custom_ua = args.user_agent is not None
        selauth = SeleniumAuthentication(auth, deviceauth, args.redirect_url, proxy=seleniumproxy)
        if args.auth_url:
            url = args.auth_url
        else:
            url = auth.build_auth_url(args.redirect_url, 'code', args.scope)
        service = selauth.get_service(args.driver_path)
        if not service:
            return
        selauth.driver = selauth.get_webdriver(service, intercept=True)
        if args.krbtoken:
            if args.krbtoken.lower() == 'stdin':
                krbtoken = sys.stdin.read().strip()
            else:
                krbtoken = args.krbtoken
            result = selauth.selenium_login_with_kerberos(url, args.username, args.password, capture=args.capture_code, krbdata=krbtoken, keep=args.keep_open)
        elif args.estscookie:
            result = selauth.selenium_login_with_estscookie(url, args.username, args.password, capture=args.capture_code, estscookie=args.estscookie, keep=args.keep_open)
        elif custom_ua:
            result = selauth.selenium_login_with_custom_useragent(url, args.username, args.password, capture=args.capture_code, federated=args.federated, keep=args.keep_open)
        else:
            result = selauth.selenium_login(url, args.username, args.password, capture=args.capture_code, federated=args.federated, keep=args.keep_open)
        if args.capture_code:
            if result:
                print(f'Captured auth code: {result}')
            return
        elif result:
            auth.outfile = args.tokenfile
            auth.save_tokens(args)
    elif args.command == 'keepassauth':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        auth.set_user_agent(args.user_agent)
        auth.tenant = args.tenant
        auth.use_cae = args.cae
        # Intercept if custom UA is set
        custom_ua = args.user_agent is not None
        selauth = SeleniumAuthentication(auth, deviceauth, args.redirect_url, proxy=seleniumproxy)
        password, otpseed = selauth.get_keepass_cred(args.username, args.keepass, args.keepass_password)
        if args.auth_url:
            url = args.auth_url
        else:
            url = auth.build_auth_url(args.redirect_url, 'code', args.scope)
        service = selauth.get_service(args.driver_path)
        if not service:
            return
        selauth.driver = selauth.get_webdriver(service, intercept=custom_ua)
        if custom_ua:
            result = selauth.selenium_login_with_custom_useragent(url, args.username, password, otpseed, keep=args.keep_open, capture=args.capture_code, federated=args.federated, devicecode=args.device_code)
        else:
            result = selauth.selenium_login(url, args.username, password, otpseed, keep=args.keep_open, capture=args.capture_code, federated=args.federated, devicecode=args.device_code)
        if args.capture_code:
            if result:
                print(f'Captured auth code: {result}')
            return
        auth.outfile = args.tokenfile
        auth.save_tokens(args)
    elif args.command == 'browserprtauth':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        auth.set_user_agent(args.user_agent)
        auth.tenant = args.tenant
        auth.use_cae = args.cae
        auth.scope = args.scope
        if args.prt and args.prt_sessionkey:
            deviceauth.setprt(args.prt, args.prt_sessionkey)
        elif args.prt_cookie:
            pass
        elif args.prt_file and deviceauth.loadprt(args.prt_file):
            pass
        else:
            print('You must either supply a PRT and session key on the command line or a file that contains them')
            return
        selauth = SeleniumAuthentication(auth, deviceauth, args.redirect_url, proxy=seleniumproxy)
        if args.auth_url:
            url = args.auth_url
        else:
            if not args.tokens_stdout:
                if args.scope:
                    print(f'Running in token request mode - Requesting token with scope {auth.scope}\nIf you want a browser window instead, use the -url parameter to start browsing.')
                else:
                    print(f'Running in token request mode - Requesting token for {auth.resource_uri}\nIf you want a browser window instead, use the -url parameter to start browsing.')
            url = auth.build_auth_url(args.redirect_url, 'code', args.scope)
        service = selauth.get_service(args.driver_path)
        if not service:
            return
        selauth.driver = selauth.get_webdriver(service, intercept=True)
        result = selauth.selenium_login_with_prt(url, keep=args.keep_open, prtcookie=args.prt_cookie, capture=args.capture_code)
        if not result and not args.keep_open:
            return
        if args.capture_code:
            if result:
                print(f'Captured auth code: {result}')
            if not args.keep_open:
                return
        else:
            auth.outfile = args.tokenfile
            auth.save_tokens(args)
        if args.keep_open:
            try:
                time.sleep(99999)
            except KeyboardInterrupt:
                return
            return
    elif args.command == 'browserprtinject':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        auth.set_user_agent(args.user_agent)
        auth.tenant = args.tenant
        auth.use_cae = args.cae
        if args.prt and args.prt_sessionkey:
            deviceauth.setprt(args.prt, args.prt_sessionkey)
        elif args.prt_cookie:
            pass
        elif args.prt_file and deviceauth.loadprt(args.prt_file):
            pass
        else:
            print('You must either supply a PRT and session key on the command line or a file that contains them')
            return
        selauth = SeleniumAuthentication(auth, deviceauth, args.redirect_url)
        if args.auth_url:
            url = args.auth_url
        else:
            url = auth.build_auth_url(args.redirect_url, 'code', args.scope)
            if args.username:
                url += '&login_hint=' + quote_plus(args.username)
            else:
                url += '&prompt=select_account'

        if args.keepass and args.username and (args.keepass_password or 'KPPASS' in os.environ or args.keepass.endswith('.xml')):
            password, otpseed = selauth.get_keepass_cred(args.username, args.keepass, args.keepass_password)
        else:
            password = args.password
            otpseed = None
        service = selauth.get_service(args.driver_path)
        if not service:
            return
        selauth.driver = selauth.get_webdriver(service, intercept=True)
        if not selauth.selenium_login_with_prt(url, identity=args.username, prtcookie=args.prt_cookie, password=password, otpseed=otpseed, keep=args.keep_open):
            return
        auth.outfile = args.tokenfile
        auth.save_tokens(args)
    elif args.command == 'prtenrich':
        if not args.no_prt:
            if args.prt and args.prt_sessionkey:
                deviceauth.setprt(args.prt, args.prt_sessionkey)
            elif args.prt_file and deviceauth.loadprt(args.prt_file):
                pass
            else:
                print('You must either supply a PRT and session key on the command line or a file that contains them')
                return
        auth.set_client_id('29d9ed98-a469-4536-ade2-f981bc1d605e')
        auth.set_user_agent(args.user_agent)
        if args.username:
            hint = '&login_hint=' + quote_plus(args.username)
        else:
            hint = ''
        replyurl = "ms-appx-web://Microsoft.AAD.BrokerPlugin/DRS"
        url = f'https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=29d9ed98-a469-4536-ade2-f981bc1d605e&redirect_uri=ms-appx-web%3a%2f%2fMicrosoft.AAD.BrokerPlugin%2fDRS&resource=urn%3aaad%3atb%3aupdate%3aprt&add_account=noheadsup&scope=openid{hint}&response_mode=form_post&windows_api_version=2.0&amr_values=ngcmfa'

        if args.ngcmfa_drs_auth:
            # Get ngcmfa token for device registration service
            auth.set_client_id('dd762716-544d-4aeb-a526-687b73838a22')
            replyurl = "ms-appx-web://Microsoft.AAD.BrokerPlugin/dd762716-544d-4aeb-a526-687b73838a22"
            url = f'https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=dd762716-544d-4aeb-a526-687b73838a22&redirect_uri=ms-appx-web%3a%2f%2fMicrosoft.AAD.BrokerPlugin%2fdd762716-544d-4aeb-a526-687b73838a22&resource=urn%3ams-drs%3aenterpriseregistration.windows.net&add_account=noheadsup&scope=openid{hint}&response_mode=form_post&windows_api_version=2.0&amr_values=ngcmfa'

        selauth = SeleniumAuthentication(auth, deviceauth, replyurl, proxy=seleniumproxy)
        if args.username and args.keepass and (args.keepass_password or 'KPPASS' in os.environ or args.keepass.endswith('.xml')):
            _, otpseed = selauth.get_keepass_cred(args.username, args.keepass, args.keepass_password)
        else:
            otpseed = None
        service = selauth.get_service(args.driver_path)
        if not service:
            return
        selauth.driver = selauth.get_webdriver(service, intercept=True)
        tokenreply = selauth.selenium_enrich_prt(url, otpseed=otpseed)
        # Save tokens
        if args.ngcmfa_drs_auth:
            auth.tokendata = auth.tokenreply_to_tokendata(tokenreply)
            auth.outfile = args.tokenfile
            auth.save_tokens(args)
        else:
            if tokenreply and tokenreply['refresh_token']:
                print('Got refresh token. Can be used to request prt with roadtx prt -r <refreshtoken>')
                print(tokenreply['refresh_token'])
            else:
                print('No tokendata found. Something probably went wrong')

    elif args.command == 'getotp':
        selauth = SeleniumAuthentication(auth, deviceauth, None)
        if args.keepass and args.username and (args.keepass_password or 'KPPASS' in os.environ or args.keepass.endswith('.xml')):
            _, otpseed = selauth.get_keepass_cred(args.username, args.keepass, args.keepass_password)
        else:
            otpseed = args.otpseed

        if not otpseed:
            print('Please use --otpseed or supply a keepass file containing otp data')
            return
        otp = pyotp.TOTP(otpseed)
        now = str(otp.now())
        print(f'OTP value: {now}')
    elif args.command == 'describe':
        tokendata = None
        # Explicitly set token option
        if args.token is not None:
            if args.verbose:
                print("[debug] Reading token value from --token option.")
            tokendata = args.token
        # Reading from stdin if input is not a TTY
        elif not sys.stdin.isatty():
            if args.verbose:
                print("[debug] Reading token value from stdin.")
            tokendata = sys.stdin.read()
        # Maybe some of the above had already tokendata set. But in Docker isatty is false.. so check if tokendata is None at this point
        # Otherwise read it from default file
        if not tokendata or tokendata == "":
            # Describing saved token file args.tokenfile
            if os.path.exists(args.tokenfile):
                if args.verbose:
                    print("[debug] Reading token value from file '%s'." % (args.tokenfile))
                f = open(args.tokenfile, "r")
                tokendata = f.read()
                f.close()
        if tokendata[0] == '{':
            # assume json object
            tokenobject = json.loads(tokendata)
            try:
                tokendata = tokenobject['accessToken']
            except KeyError:
                try:
                    tokendata = tokenobject['access_token']
                except KeyError:
                    print('Unrecognized input format')
                    return
        if tokendata[0:2] == '0.':
            print('The supplied data looks like an encrypted token or nonce, nothing to decode here!')
            return
        header, body, signature = auth.parse_jwt(tokendata)
        print(json.dumps(header, sort_keys=True, indent=4))
        print(json.dumps(body, sort_keys=True, indent=4))
    elif args.command in ('getscope', 'findscope'):
        # Load scope data
        current_dir = os.path.abspath(os.path.dirname(__file__))
        datafile = os.path.join(current_dir, 'firstpartyscopes.json')
        with codecs.open(datafile,'r','utf-8') as infile:
            data = json.load(infile)
        if not args.scope and not args.all:
            getscope_parser.print_help()
            return

        if args.all:
            # Print all scopes
            results = set()

            app_resource_ids = defaultdict(set)
            for resource, app_id in data['resourceidentifiers'].items():
                app_resource_ids[app_id].add(resource)

            for app in data['apps'].values():
                if args.foci and not app['foci']:
                    continue

                for app_id, scopes in app['scopes'].items():
                    for resource in app_resource_ids.get(app_id, [f'https://{app_id}']):
                        resource = resource.rstrip('/')
                        for scope in map(str.lower, scopes):
                            results.add(f'{resource}/{scope}')

            if args.csv:
                print('"scope"')
            else:
                print("Listing all possible scopes")

            for scope in sorted(results):
                print(f'"{scope}"' if args.csv else scope)

            return

        try:
            resource, scope = args.scope.lower().rsplit('/', 1)
        except ValueError:
            print("No resource (API) specified in scope, defaulting to Microsoft Graph")
            resource = "https://graph.microsoft.com"
            scope = args.scope.lower()

        try:
            resourceid = data['resourceidentifiers'][resource.lower()]
        except KeyError:
            try:
                resourceid = data['resourceidentifiers'][resource.lower() + '/']
            except KeyError:
                print(f'The API {resource} is not a known resource')
                return

        # Loop through scopes
        results = []
        for appid, app in data['apps'].items():
            # Skip foci apps
            if args.foci and not app['foci']:
                continue
            try:
                scopes = app['scopes'][resourceid]
                if len([s for s in scopes if s.lower() == scope]) == 0:
                    continue
            except KeyError:
                # Not on this app
                continue
            results.append((appid, app))
        appid = 'App (client) ID'
        name = 'App name'
        scopes = 'Scope on this resource'
        if len(results) == 0:
            print("No apps found!")
            return
        if args.csv:
            print("App ID,App Name,FOCI,Scopes")
            for appid, app in results:
                scopes = ' '.join(app['scopes'][resourceid])
                foci = 'Yes' if app['foci'] else 'No'
                name = app['name'].replace('"',r'\"')
                print(f'"{appid}","{name}","{foci}","{scopes}"')
        else:
            print(f"{appid:<40} {name:<40} Foci?   {scopes}")
            for appid, app in results:
                scopes = ' '.join(app['scopes'][resourceid])
                foci = 'Yes' if app['foci'] else 'No'
                print(f"{appid:<40} {app['name']:<40} {foci:<7} {scopes}")
    elif args.command == 'winhello':
        if args.access_token:
            tokenobject, tokendata = auth.parse_accesstoken(args.access_token)
        else:
            try:
                with codecs.open('.roadtools_auth', 'r', 'utf-8') as infile:
                    tokenobject = json.load(infile)
                _, tokendata = auth.parse_accesstoken(tokenobject['accessToken'])
            except FileNotFoundError:
                print('No auth data found. Ether supply an access token with --access-token or make sure a token is present on disk in .roadtools_auth')
                return
        if tokendata['aud'] != 'urn:ms-drs:enterpriseregistration.windows.net':
            print(f"Wrong token audience, got {tokendata['aud']} but expected: urn:ms-drs:enterpriseregistration.windows.net")
            print("Make sure to request a token with -r urn:ms-drs:enterpriseregistration.windows.net")
            return
        key, pubkeycngblob = deviceauth.create_hello_key(args.key_pem)
        result = deviceauth.register_winhello_key(pubkeycngblob, tokenobject['accessToken'])
        print(result)

    elif args.command == 'genhellokey':
        key, pubkeycngblob = deviceauth.create_hello_key(args.key_pem)
        if not args.device_id:
            deviceid = "d22a8b4b-d138-4271-a677-de4208305cb3"
        else:
            deviceid = args.device_id
        data = {
            "usage": "NGC",
            "keyIdentifier": deviceauth.get_privkey_kid(key),
            "keyMaterial": pubkeycngblob.decode('utf-8'),
            "creationTime": "2022-10-12T18:29:51.3793062Z",
            "deviceId": deviceid,
            "customKeyInformation": "AQAAAAACAAAAAAAAAAAA",
            "fidoAaGuid": None,
            "fidoAuthenticatorVersion": None,
            "fidoAttestationCertificates": []
        }
        print(json.dumps(data, sort_keys=True, indent=4))
    elif args.command == 'bulkenrollmenttoken':
        if args.action == 'request':
            if args.access_token:
                tokenobject, tokendata = auth.parse_accesstoken(args.access_token)
            else:
                try:
                    with codecs.open(args.tokenfile, 'r', 'utf-8') as infile:
                        tokenobject = json.load(infile)
                    _, tokendata = auth.parse_accesstoken(tokenobject['accessToken'])
                except FileNotFoundError:
                    print('No auth data found. Ether supply an access token with --access-token or make sure a token is present on disk in .roadtools_auth')
                    return
            if tokendata['aud'] != 'urn:ms-drs:enterpriseregistration.windows.net':
                print(f"Wrong token audience, got {tokendata['aud']} but expected: urn:ms-drs:enterpriseregistration.windows.net")
                print("Make sure to request a token with -r urn:ms-drs:enterpriseregistration.windows.net")
                return
            result = auth.get_bulk_enrollment_token(access_token=tokenobject['accessToken'])
            if result:
                auth.outfile = args.bulktokenfile
                auth.save_tokens(args)
        else:
            # Use token
            auth.set_client_id('b90d5b8f-5503-4153-b545-b31cecfaece2')
            auth.set_resource_uri('drs')
            try:
                with codecs.open(args.bulktokenfile, 'r', 'utf-8') as infile:
                    tokenobject = json.load(infile)
                _, tokendata = auth.parse_accesstoken(tokenobject['accessToken'])
            except FileNotFoundError:
                print('No auth data found. Make sure the bulk enrollment token is present on disk in the file specified in --bulktokenfile')
                return
            result = auth.authenticate_with_refresh_native(tokenobject['refreshToken'])
            if result:
                auth.outfile = args.tokenfile
                auth.save_tokens(args)

    elif args.command == 'decryptadfskey':
        rawblob = base64.b64decode(args.encryptedpfx)
        rawkey = binascii.unhexlify(args.key.replace('-',''))
        pfx = EncryptedPFX(rawblob, rawkey, args.verbose)
        decrypted_pfx = pfx.decrypt_pfx()
        if args.output_format == 'pfx':
            pfx.save_pfx(decrypted_pfx, args.cert_pfx)
            print(f'Saved decrypted key to {args.cert_pfx}')
        else:
            pfx.save_pem(decrypted_pfx, args.cert_pem, args.key_pem)
            print(f'Saved decrypted certificate to {args.cert_pem} and key to {args.key_pem}')
    elif args.command == 'samltoken':
        signer = SAMLSigner()
        if not signer.loadcert(args.cert_pem, args.key_pem, args.cert_pfx, args.pfx_pass, args.pfx_base64):
            sys.exit(1)
        if not args.unique_id and not args.guid:
            print('Either the unique-id or guid of the user to spoof is required')
            sys.exit(1)
        elif args.unique_id:
            uid = args.unique_id
        else:
            uid = encode_object_guid(args.guid)
        template, assertionid = signer.format_template(uid, args.upn, args.issuer, args.mfa)
        signed = signer.sign_xml(template, assertionid)
        print(signed.decode('utf-8'))
    elif args.command == 'prtcookie':
        if args.prt and args.prt_sessionkey:
            deviceauth.setprt(args.prt, args.prt_sessionkey)
        elif args.prt_file and deviceauth.loadprt(args.prt_file):
            pass
        else:
            print('You must either supply a PRT and session key on the command line or a file that contains them')
            return
        challenge = auth.get_srv_challenge()['Nonce']
        cookie = auth.create_prt_cookie_kdf_ver_2(deviceauth.prt, deviceauth.session_key, challenge)
        print(f"PRT cookie: {cookie}")
        print("Can be used in external browsers using the x-ms-RefreshTokenCredential header or cookie. Note that a PRT cookie is only valid for 5 minutes.")

if __name__ == '__main__':
    main()
