import getpass
import sys
import json
import argparse
import base64
import datetime
import adal

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
        self.tokendata = None
        self.refresh_token = None
        self.access_token = None
        self.proxies = None
        self.verify = True
        self.outfile = None

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
        auth_parser.add_argument('-f',
                                 '--tokenfile',
                                 action='store',
                                 help='File to store the credentials (default: .roadtools_auth)',
                                 default='.roadtools_auth')
        auth_parser.add_argument('--tokens-stdout',
                                 action='store_true',
                                 help='Do not store tokens on disk, pipe to stdout instead')
        return auth_parser

    def parse_args(self, args):
        self.username = args.username
        self.password = args.password
        self.tenant = args.tenant
        self.client_id = args.client
        self.access_token = args.access_token
        self.refresh_token = args.refresh_token
        self.outfile = args.tokenfile

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
            inputdata = json.loads(base64.b64decode(tokens[1]))
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
        # If we are here, no auth to try
        print('Not enough information was supplied to authenticate')

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
    auth.get_tokens(args)
    auth.save_tokens(args)

if __name__ == '__main__':
    main()
