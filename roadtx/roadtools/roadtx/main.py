import argparse
import sys
import os
import json
import codecs
import binascii
import base64
from urllib.parse import quote_plus
from roadtools.roadlib.auth import Authentication, get_data, WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadtx.selenium import SeleniumAuthentication
import pyotp

RR_HELP = 'ROADtools Token eXchange by Dirk-jan Mollema (@_dirkjan) / Outsider Security (outsidersecurity.nl)'

def main():
    # Primary argument parser
    parser = argparse.ArgumentParser(add_help=True, description=RR_HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    # Add subparsers for modules
    subparsers = parser.add_subparsers(dest='command')

    # Construct authentication module options
    auth = Authentication()
    auth_parser = subparsers.add_parser('gettokens', aliases=['auth','gettoken'], help='Authenticate to Azure AD and get access/refresh tokens. Supports various authentication methods.')
    auth.get_sub_argparse(auth_parser, for_rr=False)

    # Construct device module
    device_parser = subparsers.add_parser('device', help='Register or join devices to Azure AD')
    device_parser.add_argument('-a',
                                '--action',
                                action='store',
                                choices=['join','register'],
                                default='join',
                                help='Action to perform (default: join)')
    device_parser.add_argument('-c', '--cert-pem', action='store', metavar='file', help='Certificate file to save device cert to (default: <devicename>.pem)')
    device_parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file for certificate (default: <devicename>.key)')
    device_parser.add_argument('-n', '--name', action='store', help='Device display name (default: DESKTOP-<RANDOM>)')
    device_parser.add_argument('--access-token', action='store', help='Access token for device registration service. If not specified, taken from .roadtools_auth')
    device_parser.add_argument('--device-type', action='store', help='Device OS type (default: Windows)')
    device_parser.add_argument('--os-version', action='store', help='Device OS version (default: 10.0.19041.928)')

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

    prt_parser.add_argument('-u', '--username', action='store', metavar='USER', help='User to authenticate')
    prt_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password')
    prt_parser.add_argument('-r', '--refresh-token', action='store', help='Refresh token')


    prt_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (to save or load in case of renewal)')
    prt_parser.add_argument('--prt', action='store', metavar='PRT', help='Primary Refresh Token (for renewal)')
    prt_parser.add_argument('-s', '--prt-sessionkey', action='store', help='Primary Refresh Token session key (as hex key)')

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

    # Application auth
    # appauth_parser = subparsers.add_parser('appauth', help='Authenticate as an application')
    # helptext = 'Client ID (application ID) to use when authenticating.'
    # appauth_parser.add_argument('-c',
    #                             '--client',
    #                             action='store',
    #                             help=helptext,
    #                             default='1b730954-1685-4b74-9bfd-dac224a7b894')
    # appauth_parser.add_argument('-r',
    #                             '--resource',
    #                             action='store',
    #                             help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
    #                             default='https://graph.windows.net')
    # appauth_parser.add_argument('-s',
    #                             '--scope',
    #                             action='store',
    #                             help='Token scope. Either a full URL or alias (msgraph, aadgraph, devicereg) to use the default.')
    # appauth_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password secret of the appliction')
    # appauth_parser.add_argument('-t',
    #                             '--tenant',
    #                             action='store',
    #                             help='Tenant ID or domain to auth to',
    #                             required=True)

    # Code grant flow auth
    codeauth_parser = subparsers.add_parser('codeauth', help='Code grant flow - exchange code for auth tokens')
    clienthelptext = 'Client ID (application ID) to use when authenticating. Accepts aliases (list with roadtx listaliases)'
    codeauth_parser.add_argument('-c',
                                 '--client',
                                 action='store',
                                 help=clienthelptext,
                                 default='1b730954-1685-4b74-9bfd-dac224a7b894')
    codeauth_parser.add_argument('-p', '--password', action='store', metavar='PASSWORD', help='Password secret of the appliction if not a public app')
    codeauth_parser.add_argument('-r',
                                 '--resource',
                                 action='store',
                                 help='Resource to authenticate to. Either a full URL or alias (list with roadtx listaliases)',
                                 default='https://graph.windows.net')
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
    codeauth_parser.add_argument('code',
                                 action='store',
                                 help="Code to auth with that you got from Azure AD")

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
    describe_parser.add_argument('-t', '--token', default="stdin", action='store', metavar='TOKEN', help='Token data to describe. Defaults to reading from stdin')


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
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)',
                                default='geckodriver')
    intauth_parser.add_argument('-k', '--keep-open',
                                action='store_true',
                                help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')

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
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)',
                                default='geckodriver')
    kdbauth_parser.add_argument('-k', '--keep-open',
                                action='store_true',
                                help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')

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
    browserprtauth_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (default: roadtx.prt)')
    browserprtauth_parser.add_argument('--prt',
                                       action='store',
                                       help='Primary Refresh Token')
    browserprtauth_parser.add_argument('--prt-sessionkey',
                                       action='store',
                                       help='Primary Refresh Token session key (as hex key)')
    browserprtauth_parser.add_argument('--tokenfile',
                                       action='store',
                                       help='File to store the credentials (default: .roadtools_auth)',
                                       default='.roadtools_auth')
    browserprtauth_parser.add_argument('--tokens-stdout',
                                       action='store_true',
                                       help='Do not store tokens on disk, pipe to stdout instead')
    browserprtauth_parser.add_argument('-d', '--driver-path',
                                       action='store',
                                       help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)',
                                       default='geckodriver')
    browserprtauth_parser.add_argument('-k', '--keep-open',
                                       action='store_true',
                                       help='Do not close the browser window after timeout. Useful if you want to browse online apps with the obtained credentials')

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
    injauth_parser.add_argument('-t',
                                '--tenant',
                                action='store',
                                help='Tenant ID or domain to auth to')
    injauth_parser.add_argument('-d', '--driver-path',
                                action='store',
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)',
                                default='geckodriver')
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
    injauth_parser.add_argument('--tokenfile',
                                action='store',
                                help='File to store the credentials (default: .roadtools_auth)',
                                default='.roadtools_auth')
    injauth_parser.add_argument('--tokens-stdout',
                                action='store_true',
                                help='Do not store tokens on disk, pipe to stdout instead')

    # Interactive auth using Selenium - enrich PRT
    enrauth_parser = subparsers.add_parser('prtenrich', help='Interactive authentication to add MFA claim to a PRT')
    enrauth_parser.add_argument('-u', '--username', action='store', metavar='USER', help='User in the prt')
    enrauth_parser.add_argument('-kp', '--keepass', action='store', metavar='KPFILE', default='roadtx.kdbx', help='KeePass file (default: roadtx.kdbx)')
    enrauth_parser.add_argument('-kpp', '--keepass-password', action='store', metavar='KPPASS', help='KeePass file password. Can also be provided via KPPASS environment variable.')
    enrauth_parser.add_argument('-d', '--driver-path',
                                action='store',
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)',
                                default='geckodriver')
    enrauth_parser.add_argument('-f', '--prt-file', default="roadtx.prt", action='store', metavar='FILE', help='PRT storage file (default: roadtx.prt)')
    enrauth_parser.add_argument('--prt',
                                action='store',
                                help='Primary Refresh Token')
    enrauth_parser.add_argument('--prt-sessionkey',
                                action='store',
                                help='Primary Refresh Token session key (as hex key)')
    # enrauth_parser.add_argument('--ngcmfa-drs-auth', action='store_true', help="Don't request PRT with MFA claim but get access token with ngcmfa claim for DRS instead.")
    enrauth_parser.add_argument('--tokenfile',
                                action='store',
                                help='File to store the credentials (default: .roadtools_auth)',
                                default='.roadtools_auth')
    enrauth_parser.add_argument('--tokens-stdout',
                                action='store_true',
                                help='Do not store tokens on disk, pipe to stdout instead')


    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
        return

    deviceauth = DeviceAuthentication()
    args = parser.parse_args()
    if args.command in ('auth', 'gettokens', 'gettoken'):
        auth.parse_args(args)
        res = auth.get_tokens(args)
        if not res:
            return
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
            deviceauth.register_device(tokenobject['accessToken'], jointype=jointype, certout=args.cert_pem, privout=args.key_pem, device_type=args.device_type, device_name=args.name, os_version=args.os_version)
    elif args.command == 'prt':
        if args.action == 'request':
            if not deviceauth.loadcert(args.cert_pem, args.key_pem, args.cert_pfx, args.pfx_pass, args.pfx_base64):
                return
            prtdata = None
            if args.username and args.password:
                prtdata = deviceauth.get_prt_with_password(args.username, args.password)
            if args.refresh_token:
                prtdata = deviceauth.get_prt_with_refresh_token(args.refresh_token)
            # if args.username and deviceauth.loadhellokey(args.hello_key):
            #     prtdata = deviceauth.get_prt_with_hello_key(args.username)
            # if args.username and args.hello_assertion:
            #     prtdata = deviceauth.get_prt_with_hello_key(args.username, args.hello_assertion)
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
        if args.prt and args.prt_sessionkey:
            deviceauth.setprt(args.prt, args.prt_sessionkey)
        elif args.prt_file and deviceauth.loadprt(args.prt_file):
            pass
        else:
            print('You must either supply a PRT and session key on the command line or a file that contains them')
            return
        tokendata = deviceauth.aad_brokerplugin_prt_auth(args.client, args.resource, redirect_uri=args.redirect_url)
        # We need to convert this to a token format roadlib understands
        tokenobject, _ = auth.parse_accesstoken(tokendata['access_token'])
        tokenobject['expiresIn'] = tokendata['expires_in']
        tokenobject['refreshToken'] = tokendata['refresh_token']
        auth.outfile = args.tokenfile
        auth.tokendata = tokenobject
        auth.save_tokens(args)
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
        auth.authenticate_with_code_native(args.code, args.redirect_url)
        auth.outfile = args.tokenfile
        auth.save_tokens(args)
    elif args.command == 'listaliases':
        print('Well-known clients. Can be used as alias with -c or --client')
        print()
        for alias, clientid in WELLKNOWN_CLIENTS.items():
            print(f"{alias} - {clientid}")
        print()
        print('Well-known resources. Can be used as alias with -r or --resource')
        print()
        for alias, resourceurl in WELLKNOWN_RESOURCES.items():
            print(f"{alias} - {resourceurl}")
    elif args.command == 'interactiveauth':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        selauth = SeleniumAuthentication(auth, deviceauth, args.redirect_url)
        if args.auth_url:
            url = args.auth_url
        else:
            url = auth.build_auth_url(args.redirect_url, 'code', args.scope)
        service = selauth.get_service(args.driver_path)
        if not service:
            return
        selauth.driver = selauth.get_webdriver(service)
        selauth.selenium_login(url, args.username, args.password)
        auth.outfile = args.tokenfile
        auth.save_tokens(args)
    elif args.command == 'keepassauth':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        selauth = SeleniumAuthentication(auth, deviceauth, args.redirect_url)
        password, otpseed = selauth.get_keepass_cred(args.username, args.keepass, args.keepass_password)
        if args.auth_url:
            url = args.auth_url
        else:
            url = auth.build_auth_url(args.redirect_url, 'code', args.scope)
        service = selauth.get_service(args.driver_path)
        if not service:
            return
        selauth.driver = selauth.get_webdriver(service)
        selauth.selenium_login(url, args.username, password, otpseed, keep=args.keep_open)
        auth.outfile = args.tokenfile
        auth.save_tokens(args)
    elif args.command == 'browserprtauth':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        if args.prt and args.prt_sessionkey:
            deviceauth.setprt(args.prt, args.prt_sessionkey)
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
        service = selauth.get_service(args.driver_path)
        if not service:
            return
        selauth.driver = selauth.get_webdriver(service, intercept=True)
        if not selauth.selenium_login_with_prt(url, keep=args.keep_open):
            return
        auth.outfile = args.tokenfile
        auth.save_tokens(args)
    elif args.command == 'browserprtinject':
        auth.set_client_id(args.client)
        auth.set_resource_uri(args.resource)
        if args.prt and args.prt_sessionkey:
            deviceauth.setprt(args.prt, args.prt_sessionkey)
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
        if not selauth.selenium_login_with_prt(url, identity=args.username, password=password, otpseed=otpseed, keep=args.keep_open):
            return
        auth.outfile = args.tokenfile
        auth.save_tokens(args)
    elif args.command == 'prtenrich':
        if args.prt and args.prt_sessionkey:
            deviceauth.setprt(args.prt, args.prt_sessionkey)
        elif args.prt_file and deviceauth.loadprt(args.prt_file):
            pass
        else:
            print('You must either supply a PRT and session key on the command line or a file that contains them')
            return
        auth.set_client_id('29d9ed98-a469-4536-ade2-f981bc1d605e')
        if args.username:
            hint = '&login_hint=' + quote_plus(args.username)
        else:
            hint = ''
        replyurl = "ms-appx-web://Microsoft.AAD.BrokerPlugin/DRS"
        url = f'https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=29d9ed98-a469-4536-ade2-f981bc1d605e&redirect_uri=ms-appx-web%3a%2f%2fMicrosoft.AAD.BrokerPlugin%2fDRS&resource=urn%3aaad%3atb%3aupdate%3aprt&add_account=noheadsup&scope=openid{hint}&response_mode=form_post&windows_api_version=2.0&amr_values=ngcmfa'

        # if args.ngcmfa_drs_auth:
        #     # Get ngcmfa token for device registration service
        #     auth.set_client_id('dd762716-544d-4aeb-a526-687b73838a22')
        #     replyurl = "ms-appx-web://Microsoft.AAD.BrokerPlugin/dd762716-544d-4aeb-a526-687b73838a22"
        #     url = f'https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=dd762716-544d-4aeb-a526-687b73838a22&redirect_uri=ms-appx-web%3a%2f%2fMicrosoft.AAD.BrokerPlugin%2fdd762716-544d-4aeb-a526-687b73838a22&resource=urn%3ams-drs%3aenterpriseregistration.windows.net&add_account=noheadsup&scope=openid{hint}&response_mode=form_post&windows_api_version=2.0&amr_values=ngcmfa'

        selauth = SeleniumAuthentication(auth, deviceauth, replyurl)
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
            if tokenreply['refresh_token']:
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
        if args.token == 'stdin':
            tokendata = sys.stdin.read()
        else:
            tokendata = args.token
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
if __name__ == '__main__':
    main()
