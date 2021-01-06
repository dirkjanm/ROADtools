import getpass
import sys
import json
import argparse
import base64
import datetime
import uuid
import binascii
import time
from urllib.parse import urlparse, parse_qs
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.backends import default_backend
import requests
import adal
import jwt

class Authentication():
    """
    Authentication class for ROADtools
    """
    def __init__(self, username=None, password=None, tenant=None, client_id='1b730954-1685-4b74-9bfd-dac224a7b894'):
        self.username = username
        self.password = password
        self.tenant = tenant
        self.client_id = client_id
        self.resource_uri = 'https://graph.windows.net/'
        self.tokendata = {}
        self.refresh_token = None
        self.access_token = None
        self.proxies = None
        self.verify = True
        self.outfile = None
        self.debug = False

    def get_authority_url(self):
        """
        Returns the authority URL for the tenant specified, or the
        common one if no tenant was specified
        """
        if self.tenant is not None:
            return 'https://login.microsoftonline.com/{}'.format(self.tenant)
        return 'https://login.microsoftonline.com/common'

    def authenticate_device_code(self):
        """
        Authenticate the end-user using device auth.
        """

        authority_host_uri = self.get_authority_url()

        context = adal.AuthenticationContext(authority_host_uri, api_version=None, proxies=self.proxies, verify_ssl=self.verify)
        code = context.acquire_user_code(self.resource_uri, self.client_id)
        print(code['message'])
        self.tokendata = context.acquire_token_with_device_code(self.resource_uri, code, self.client_id)
        return self.tokendata

    def authenticate_username_password(self):
        """
        Authenticate using user w/ username + password.
        This doesn't work for users or tenants that have multi-factor authentication required.
        """
        authority_uri = self.get_authority_url()
        context = adal.AuthenticationContext(authority_uri, api_version=None, proxies=self.proxies, verify_ssl=self.verify)
        self.tokendata = context.acquire_token_with_username_password(self.resource_uri, self.username, self.password, self.client_id)

        return self.tokendata


    def authenticate_as_app(self):
        """
        Authenticate with an APP id + secret (password credentials assigned to serviceprinicpal)
        """
        authority_uri = self.get_authority_url()

        context = adal.AuthenticationContext(authority_uri, api_version=None, proxies=self.proxies, verify_ssl=self.verify)
        self.tokendata = context.acquire_token_with_client_credentials(self.resource_uri, self.client_id, self.password)
        return self.tokendata

    def authenticate_with_code(self, code, redirurl, client_secret=None):
        """
        Authenticate with a code plus optional secret in case of a non-public app (authorization grant)
        """
        authority_uri = self.get_authority_url()

        context = adal.AuthenticationContext(authority_uri, api_version=None, proxies=self.proxies, verify_ssl=self.verify)
        self.tokendata = context.acquire_token_with_authorization_code(code, redirurl, self.resource_uri, self.client_id, client_secret)
        return self.tokendata

    def authenticate_with_refresh(self, oldtokendata):
        """
        Authenticate with a refresh token, refreshes the refresh token
        and obtains an access token
        """
        authority_uri = self.get_authority_url()

        context = adal.AuthenticationContext(authority_uri, api_version=None, proxies=self.proxies, verify_ssl=self.verify)
        newtokendata = context.acquire_token_with_refresh_token(oldtokendata['refreshToken'], self.client_id, self.resource_uri)
        # Overwrite fields
        for ikey, ivalue in newtokendata.items():
            self.tokendata[ikey] = ivalue
        return self.tokendata

    def authenticate_with_prt(self, prt, context, derived_key=None, sessionkey=None):
        """
        Authenticate with a PRT and given context/derived key
        """
        # If raw key specified, use that
        if not derived_key and sessionkey:
            context, derived_key = self.calculate_derived_key(sessionkey, context)
        secret = derived_key.replace(' ','')
        sdata = binascii.unhexlify(secret)
        headers = {
            'ctx': base64.b64encode(binascii.unhexlify(context)).decode('utf-8') #.rstrip('=')
        }
        if not '_' in prt:
            prt = base64.b64decode(prt+('='*(len(prt)%4))).decode('utf-8')
        nonce = self.get_prt_cookie_nonce()
        if not nonce:
            return False
        payload = {
            "refresh_token": prt,
            "is_primary": "true",
            "request_nonce": nonce
        }
        cookie = jwt.encode(payload, sdata, algorithm='HS256', headers=headers).decode('utf-8')
        return self.authenticate_with_prt_cookie(cookie)

    def calculate_derived_key(self, sessionkey, context=None):
        """
        Calculate the derived key given a session key and optional context using KBKDFHMAC
        """
        label = b"AzureAD-SecureConversation"
        if not context:
            context = os.urandom(24)
        else:
            context = binascii.unhexlify(context)
        backend = default_backend()
        kdf = KBKDFHMAC(
            algorithm=hashes.SHA256(),
            mode=Mode.CounterMode,
            length=32,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=label,
            context=context,
            fixed=None,
            backend=backend
        )
        if len(sessionkey) == 44:
            keybytes = base64.b64decode(sessionkey)
        else:
            keybytes = binascii.unhexlify(sessionkey)
        derived_key = kdf.derive(keybytes)
        # This is not ideal but further code expects it as hex string
        return binascii.hexlify(context).decode('utf-8'), binascii.hexlify(derived_key).decode('utf-8')

    def get_prt_cookie_nonce(self):
        """
        Request a nonce to sign in with
        """
        ses = requests.session()
        params = {
            'resource': self.resource_uri,
            'client_id': self.client_id,
            'response_type': 'code',
            'haschrome': '1',
            'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
            'client-request-id': str(uuid.uuid4()),
            'x-client-SKU': 'PCL.Desktop',
            'x-client-Ver': '3.19.7.16602',
            'x-client-CPU': 'x64',
            'x-client-OS': 'Microsoft Windows NT 10.0.19569.0',
            'site_id': 501358,
            'mscrid': str(uuid.uuid4())
        }
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)',
            'UA-CPU': 'AMD64',
        }
        res = ses.get('https://login.microsoftonline.com/Common/oauth2/authorize', params=params, headers=headers, allow_redirects=False)
        if self.debug:
            with open('roadtools.debug.html','w') as outfile:
                outfile.write(str(res.headers))
                outfile.write('------\n\n\n-----')
                outfile.write(res.content.decode('utf-8'))
        if res.status_code == 302 and res.headers['Location']:
            ups = urlparse(res.headers['Location'])
            qdata = parse_qs(ups.query)
            if not 'sso_nonce' in qdata:
                print('No nonce found in redirect!')
                return
            return qdata['sso_nonce'][0]
        else:
            # Try to find SSO nonce in json config
            startpos = res.content.find(b'$Config=')
            stoppos = res.content.find(b'//]]></script>')
            if startpos == -1 or stoppos == -1:
                print('No redirect or nonce config was returned!')
                return
            else:
                jsonbytes = res.content[startpos+8:stoppos-2]
                try:
                    jdata = json.loads(jsonbytes)
                except json.decoder.JSONDecodeError:
                    print('Failed to parse config JSON')
                try:
                    nonce = jdata['bsso']['nonce']
                except KeyError:
                    print('No nonce found in browser config')
                    return
                return nonce


    def authenticate_with_prt_cookie(self, cookie, context=None, derived_key=None, verify_only=False, sessionkey=None):
        """
        Authenticate with a PRT cookie, optionally re-signing the cookie if a key is given
        """
        # Load cookie
        jdata = jwt.decode(cookie, options={"verify_signature":False}, algorithms=['HS256'])
        # Does it have a nonce?
        if not 'request_nonce' in jdata:
            nonce = self.get_prt_cookie_nonce()
            if not nonce:
                return False
            print('Requested nonce from server to use with ROADtoken: %s' % nonce)
            if not derived_key and not sessionkey:
                return False
        else:
            nonce = jdata['request_nonce']

        # If raw key specified, use that
        if not derived_key and sessionkey:
            context, derived_key = self.calculate_derived_key(sessionkey, context)

        # If a derived key was specified, we use that
        if derived_key:
            secret = derived_key.replace(' ', '')
            sdata = binascii.unhexlify(secret)
            headers = jwt.get_unverified_header(cookie)
            if context is None or verify_only:
                # Verify JWT
                try:
                    jdata = jwt.decode(cookie, sdata, algorithms=['HS256'])
                except jwt.exceptions.InvalidSignatureError:
                    print('Signature invalid with given derived key')
                    return False
                if verify_only:
                    print('PRT verified with given derived key!')
                    return False
            else:
                # Don't verify JWT, just load it
                jdata = jwt.decode(cookie, sdata, options={"verify_signature":False}, algorithms=['HS256'])
            # Since a derived key was specified, we get a new nonce
            nonce = self.get_prt_cookie_nonce()
            jdata['request_nonce'] = nonce
            if context:
                # Resign with custom context
                # convert from ascii to base64
                newheaders = {
                    'ctx': base64.b64encode(binascii.unhexlify(context)).decode('utf-8') #.rstrip('=')
                }
                cookie = jwt.encode(jdata, sdata, algorithm='HS256', headers=newheaders).decode('utf-8')
                print('Re-signed PRT cookie using custom context')
            else:
                newheaders = {
                    'ctx': headers['ctx']
                }
                cookie = jwt.encode(jdata, sdata, algorithm='HS256', headers=newheaders).decode('utf-8')
                print('Re-signed PRT cookie using derived key')

        ses = requests.session()
        params = {
            'resource': self.resource_uri,
            'client_id': self.client_id,
            'response_type': 'code',
            'haschrome': '1',
            'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
            'client-request-id': str(uuid.uuid4()),
            'x-client-SKU': 'PCL.Desktop',
            'x-client-Ver': '3.19.7.16602',
            'x-client-CPU': 'x64',
            'x-client-OS': 'Microsoft Windows NT 10.0.19569.0',
            'site_id': 501358,
            'sso_nonce': nonce,
            'mscrid': str(uuid.uuid4())
        }
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)',
            'UA-CPU': 'AMD64',
        }
        cookies = {
            'x-ms-RefreshTokenCredential': cookie
        }
        res = ses.get('https://login.microsoftonline.com/Common/oauth2/authorize', params=params, headers=headers, cookies=cookies, allow_redirects=False)
        if res.status_code == 302 and params['redirect_uri'].lower() in res.headers['Location'].lower():
            ups = urlparse(res.headers['Location'])
            qdata = parse_qs(ups.query)
            return self.authenticate_with_code(qdata['code'][0], params['redirect_uri'])
        if self.debug:
            with open('roadtools.debug.html','w') as outfile:
                outfile.write(str(res.headers))
                outfile.write('------\n\n\n-----')
                outfile.write(res.content.decode('utf-8'))
        print('No authentication code was returned, make sure the PRT cookie is valid')
        print('It is also possible that the sign-in was blocked by Conditional Access policies')
        return False

    @staticmethod
    def get_sub_argparse(auth_parser, for_rr=False):
        """
        Get an argparse subparser for authentication
        """
        auth_parser.add_argument('-u',
                                 '--username',
                                 action='store',
                                 help='Username for authentication')
        auth_parser.add_argument('-p',
                                 '--password',
                                 action='store',
                                 help='Password (leave empty to prompt)')
        auth_parser.add_argument('-t',
                                 '--tenant',
                                 action='store',
                                 help='Tenant ID to auth to (leave blank for default tenant for account)')
        if for_rr:
            helptext = 'Client ID to use when authenticating. (Must be a public client from Microsoft with user_impersonation permissions!). Default: Azure AD PowerShell module App ID'
        else:
            helptext = 'Client ID to use when authenticating. (Must have the required OAuth2 permissions or Application Role for what you want to achieve)'
        auth_parser.add_argument('-c',
                                 '--client',
                                 action='store',
                                 help=helptext,
                                 default='1b730954-1685-4b74-9bfd-dac224a7b894')
        auth_parser.add_argument('-r',
                                 '--resource',
                                 action='store',
                                 help='Resource to authenticate to (Default: https://graph.windows.net)',
                                 default='https://graph.windows.net')
        auth_parser.add_argument('--as-app',
                                 action='store_true',
                                 help='Authenticate as App (requires password and client ID set)')
        auth_parser.add_argument('--device-code',
                                 action='store_true',
                                 help='Authenticate using a device code')
        auth_parser.add_argument('--access-token',
                                 action='store',
                                 help='Access token (JWT)')
        auth_parser.add_argument('--refresh-token',
                                 action='store',
                                 help='Refresh token (JWT)')
        auth_parser.add_argument('--prt-cookie',
                                 action='store',
                                 help='Primary Refresh Token cookie from ROADtoken (JWT)')
        auth_parser.add_argument('--prt-init',
                                 action='store_true',
                                 help='Initialize Primary Refresh Token authentication flow (get nonce)')
        auth_parser.add_argument('--prt',
                                 action='store',
                                 help='Primary Refresh Token cookie from mimikatz CloudAP')
        auth_parser.add_argument('--derived-key',
                                 action='store',
                                 help='Derived key used to re-sign the PRT cookie (as hex key)')
        auth_parser.add_argument('--prt-context',
                                 action='store',
                                 help='Primary Refresh Token context for the derived key (as hex key)')
        auth_parser.add_argument('--prt-sessionkey',
                                 action='store',
                                 help='Primary Refresh Token session key (as hex key)')
        auth_parser.add_argument('--prt-verify',
                                 action='store_true',
                                 help='Verify the Primary Refresh Token and exit')
        auth_parser.add_argument('-f',
                                 '--tokenfile',
                                 action='store',
                                 help='File to store the credentials (default: .roadtools_auth)',
                                 default='.roadtools_auth')
        auth_parser.add_argument('--tokens-stdout',
                                 action='store_true',
                                 help='Do not store tokens on disk, pipe to stdout instead')
        auth_parser.add_argument('--debug',
                                 action='store_true',
                                 help='Enable debug logging to disk')
        return auth_parser

    def parse_args(self, args):
        self.username = args.username
        self.password = args.password
        self.tenant = args.tenant
        self.client_id = args.client
        self.access_token = args.access_token
        self.refresh_token = args.refresh_token
        self.outfile = args.tokenfile
        self.debug = args.debug
        self.resource_uri = args.resource

        if not self.username is None and self.password is None:
            self.password = getpass.getpass()

    def get_tokens(self, args):
        if self.tokendata:
            return self.tokendata
        if self.refresh_token and not self.access_token:
            token_data = {'refreshToken': self.refresh_token}
            return self.authenticate_with_refresh(token_data)
        if self.access_token and not self.refresh_token:
            tokens = self.access_token.split('.')
            inputdata = json.loads(base64.b64decode(tokens[1]+('='*(len(tokens[1])%4))))
            self.tokendata = {
                'accessToken': self.access_token,
                'tokenType': 'Bearer',
                'expiresOn': datetime.datetime.fromtimestamp(inputdata['exp']).strftime('%Y-%m-%d %H:%M:%S'),
                'tenantId': inputdata['tid'],
                '_clientId': inputdata['appid']
            }
            return self.tokendata
        if self.username and self.password:
            return self.authenticate_username_password()
        if args.as_app and self.password:
            return self.authenticate_as_app()
        if args.device_code:
            return self.authenticate_device_code()
        if args.prt_init:
            nonce = self.get_prt_cookie_nonce()
            if nonce:
                print('Requested nonce from server to use with ROADtoken: %s' % nonce)
            return False
        if args.prt_cookie:
            return self.authenticate_with_prt_cookie(args.prt_cookie, args.prt_context, args.derived_key, args.prt_verify, args.prt_sessionkey)
        if args.prt and args.prt_context and args.derived_key:
            return self.authenticate_with_prt(args.prt, args.prt_context, derived_key=args.derived_key)
        if args.prt and args.prt_sessionkey:
            return self.authenticate_with_prt(args.prt, args.prt_context, sessionkey=args.prt_sessionkey)
        # If we are here, no auth to try
        print('Not enough information was supplied to authenticate')
        return False

    def save_tokens(self, args):
        if args.tokens_stdout:
            sys.stdout.write(json.dumps(self.tokendata))
        else:
            with open(self.outfile, 'w') as outfile:
                json.dump(self.tokendata, outfile)
            print('Tokens were written to {}'.format(self.outfile))

def main():
    parser = argparse.ArgumentParser(add_help=True, description='ROADtools Authentication utility', formatter_class=argparse.RawDescriptionHelpFormatter)
    auth = Authentication()
    # auth_parser = subparsers.add_parser('auth', dest='command', help='Authenticate to Azure AD')
    auth.get_sub_argparse(parser)
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    auth.parse_args(args)
    if not auth.get_tokens(args):
        return
    auth.save_tokens(args)

if __name__ == '__main__':
    main()
