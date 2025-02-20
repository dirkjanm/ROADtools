import getpass
import sys
import json
import argparse
import base64
import datetime
import uuid
import binascii
import time
import codecs
import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs, quote_plus
from urllib3.util import SKIP_HEADER
from xml.sax.saxutils import escape as xml_escape
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString
import os
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from roadtools.roadlib.constants import WELLKNOWN_RESOURCES, WELLKNOWN_CLIENTS, WELLKNOWN_USER_AGENTS, \
    DSSO_BODY_KERBEROS, DSSO_BODY_USERPASS, SAML_TOKEN_TYPE_V1, SAML_TOKEN_TYPE_V2, GRANT_TYPE_SAML1_1, \
    WSS_SAML_TOKEN_PROFILE_V1_1, WSS_SAML_TOKEN_PROFILE_V2, GRANT_TYPE_SAML2
from roadtools.roadlib.wstrust import Mex, build_rst, parse_wstrust_response
from roadtools.roadlib.auth import Authentication, AuthenticationException, get_data
import requests
import jwt

class AsyncAuthentication(Authentication):
    """
    Authentication class for ROADtools, but with asyncio / aiohttp as base
    """
    def __init__(self, username=None, password=None, tenant=None, client_id='1b730954-1685-4b74-9bfd-dac224a7b894'):
        super().__init__(username, password, tenant, client_id)
        self.ahsession = None
        self.requestcounter = 0
        self.proxies = {}
        self.cache_nonce = False
        self.nonce = None
        self.nonce_request_time = 0

    async def user_discovery_v1(self, username):
        """
        Discover whether this is a federated user
        """
        # Tenant specific endpoint seems to not work for this?
        authority_uri = 'https://login.microsoftonline.com/common'
        user = quote_plus(username)
        res = await self.requests_get(f"{authority_uri}/UserRealm/{user}?api-version=1.0")
        response = await res.json()
        return response

    async def user_discovery_v2(self, username):
        """
        Discover whether this is a federated user
        """
        # Tenant specific endpoint seems to not work for this?
        authority_uri = 'https://login.microsoftonline.com/common'
        user = quote_plus(username)
        res = await self.requests_get(f"{authority_uri}/UserRealm/{user}?api-version=2.0")
        response = await res.json()
        return response

    async def authenticate_device_code_native(self, additionaldata=None, returnreply=False):
        """
        Authenticate with device code flow
        Native version without adal
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "resource": self.resource_uri,
        }
        if self.scope:
            data['scope'] = self.scope
        if additionaldata:
            data = {**data, **additionaldata}
        if self.has_force_mfa():
            data['amr_values'] = 'ngcmfa'
        res = await self.requests_post(f"{authority_uri}/oauth2/devicecode", data=data)
        if res.status != 200:
            text = await res.text()
            raise AuthenticationException(text)
        responsedata = await res.json()
        print(responsedata['message'])
        # print(f"Code expires in {responsedata['expires_in']} seconds")
        interval = float(responsedata['interval'])
        device_code = responsedata['device_code']

        polldata = {
            "client_id": self.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "code": device_code
        }
        while True:
            await asyncio.sleep(interval)
            res = await self.requests_post(f"{authority_uri}/oauth2/token", data=polldata)
            tokenreply = await res.json()
            if res.status != 200:
                # Keep polling
                if tokenreply['error'] == 'authorization_pending':
                    continue
                if tokenreply['error'] in ('expired_token', 'code_expired'):
                    raise AuthenticationException("The code has expired.")
                if tokenreply['error'] == 'authorization_declined':
                    raise AuthenticationException("The user declined the sign-in.")
                # If not handled, raise
                raise AuthenticationException(await res.text())
            # Else break out of the loop
            break
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_device_code_native_v2(self, additionaldata=None, returnreply=False):
        """
        Authenticate with device code flow
        Native version without adal
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "scope": self.scope,
        }
        if additionaldata:
            data = {**data, **additionaldata}
        if self.use_cae:
            self.set_cae()
        if self.claims:
            data['claims'] = json.dumps(self.claims)
        res = await self.requests_post(f"{authority_uri}/oauth2/v2.0/devicecode", data=data)
        if res.status != 200:
            text = await res.text()
            raise AuthenticationException(text)
        responsedata = await res.json()
        print(responsedata['message'])
        # print(f"Code expires in {responsedata['expires_in']} seconds")
        interval = float(responsedata['interval'])
        device_code = responsedata['device_code']

        polldata = {
            "client_id": self.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "code": device_code
        }
        while True:
            await asyncio.sleep(interval)
            res = await self.requests_post(f"{authority_uri}/oauth2/v2.0/token", data=polldata)
            tokenreply = await res.json()
            if res.status != 200:
                # Keep polling
                if tokenreply['error'] == 'authorization_pending':
                    continue
                if tokenreply['error'] in ('expired_token', 'code_expired'):
                    raise AuthenticationException("The code has expired.")
                if tokenreply['error'] == 'authorization_declined':
                    raise AuthenticationException("The user declined the sign-in.")
                # If not handled, raise
                raise AuthenticationException(await res.text())
            # Else break out of the loop
            break
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def find_federation_endpoint(self, mex_endpoint):
        """
        Finder usernamemixed endpoint on the federation server
        """
        mex_resp = self.requests_get(mex_endpoint)
        text = await mex_resp.text()
        try:
            return Mex(text).get_wstrust_username_password_endpoint()
        except ET.ParseError:
            print("Malformed MEX document: %s, %s", mex_resp.status, text)
            raise

    async def get_saml_token_with_username_password(self, federationdata):
        """
        Fetch saml token from usernamemixed endpoint on the federation server
        """
        wstrust_endpoint = self.find_federation_endpoint(federationdata['federation_metadata_url'])
        cloud_audience_urn = wstrust_endpoint.get("cloud_audience_urn", "urn:federation:MicrosoftOnline")
        endpoint_address =  wstrust_endpoint.get("address", federationdata.get("federation_active_auth_url"))
        soap_action = wstrust_endpoint.get("action")
        if soap_action is None:
            if '/trust/2005/usernamemixed' in endpoint_address:
                soap_action = Mex.ACTION_2005
            elif '/trust/13/usernamemixed' in endpoint_address:
                soap_action = Mex.ACTION_13
        if soap_action not in (Mex.ACTION_13, Mex.ACTION_2005):
            raise ValueError("Unsupported soap action: %s. "
                "Contact your administrator to check your ADFS's MEX settings." % soap_action)
        data = build_rst( self.username, self.password, cloud_audience_urn, endpoint_address, soap_action)
        headers = {
            'Content-type':'application/soap+xml; charset=utf-8',
            'SOAPAction': soap_action,
        }
        resp = await self.requests_post(endpoint_address, data=data, headers=headers)
        text = await resp.text()
        if resp.status >= 400:
            print(f"Unsuccessful federation server response received: {text}")
        # It turns out ADFS uses 5xx status code even with client-side incorrect password error
        # so we ignore the 5xx error and parse the XML instead
        wstrust_result = parse_wstrust_response(text)
        if not ("token" in wstrust_result and "type" in wstrust_result):
            raise AuthenticationException("Unsuccessful authentication against the federation server. %s" % wstrust_result)

        grant_type = {
            SAML_TOKEN_TYPE_V1: GRANT_TYPE_SAML1_1,
            SAML_TOKEN_TYPE_V2: GRANT_TYPE_SAML2,
            WSS_SAML_TOKEN_PROFILE_V1_1: GRANT_TYPE_SAML1_1,
            WSS_SAML_TOKEN_PROFILE_V2: GRANT_TYPE_SAML2
            }.get(wstrust_result.get("type"))
        if not grant_type:
            raise AuthenticationException(
                "RSTR returned unknown token type: %s", wstrust_result.get("type"))
        return wstrust_result, grant_type

    async def authenticate_username_password_federation_native(self, federationdata, additionaldata=None, returnreply=False):
        """
        Authenticate using user w/ username + password in federated environments
        This doesn't work for users or tenants that have multi-factor authentication required.
        Native version without adal
        """
        wstrust_result, grant_type = self.get_saml_token_with_username_password(federationdata)
        if self.scope:
            return self.authenticate_with_saml_native_v2(wstrust_result['token'], grant_type=grant_type, additionaldata=additionaldata, returnreply=returnreply)
        return self.authenticate_with_saml_native(wstrust_result['token'], grant_type=grant_type, additionaldata=additionaldata, returnreply=returnreply)

    async def authenticate_username_password_native(self, client_secret=None, additionaldata=None, returnreply=False):
        """
        Authenticate using user w/ username + password.
        This doesn't work for users or tenants that have multi-factor authentication required.
        Native version without adal
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "password",
            "resource": self.resource_uri,
            "username": self.username,
            "password": self.password
        }
        if self.scope:
            data['scope'] = self.scope
        if client_secret:
            data['client_secret'] = client_secret
        if additionaldata:
            data = {**data, **additionaldata}
        res = await self.requests_post(f"{authority_uri}/oauth2/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_username_password_native_v2(self, client_secret=None, additionaldata=None, returnreply=False):
        """
        Authenticate using user w/ username + password.
        This doesn't work for users or tenants that have multi-factor authentication required.
        Native version without adal, for identity platform v2 endpoint
        """
        authority_uri = self.get_authority_url('organizations')
        data = {
            "client_id": self.client_id,
            "grant_type": "password",
            "scope": self.scope,
            "username": self.username,
            "password": self.password
        }
        if client_secret:
            data['client_secret'] = client_secret
        if additionaldata:
            data = {**data, **additionaldata}
        if self.use_cae:
            self.set_cae()
        if self.claims:
            data['claims'] = json.dumps(self.claims)
        res = await self.requests_post(f"{authority_uri}/oauth2/v2.0/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_as_app_native(self, client_secret=None, assertion=None, additionaldata=None, returnreply=False):
        """
        Authenticate with a client id + secret or assertion
        Essentially an implementation of the oauth2 client credentials grant on the v1 auth endpoint
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "client_credentials",
            "resource": self.resource_uri,
        }
        if assertion:
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = assertion
        else:
            if client_secret:
                data['client_secret'] = client_secret
            else:
                data['client_secret'] = self.password
        if additionaldata:
            data = {**data, **additionaldata}
        res = await self.requests_post(f"{authority_uri}/oauth2/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_as_app_native_v2(self, client_secret=None, assertion=None, additionaldata=None, returnreply=False):
        """
        Authenticate with a client id + secret or assertion
        Essentially an implementation of the oauth2 client credentials grant on the v2 auth endpoint
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "client_credentials",
            "scope": self.scope,
        }
        if assertion:
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = assertion
        else:
            if client_secret:
                data['client_secret'] = client_secret
            else:
                data['client_secret'] = self.password
        if additionaldata:
            data = {**data, **additionaldata}
        if self.use_cae:
            self.set_cae()
        if self.claims:
            data['claims'] = json.dumps(self.claims)
        res = await self.requests_post(f"{authority_uri}/oauth2/v2.0/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_on_behalf_of_native(self, token, client_secret=None, assertion=None, additionaldata=None, returnreply=False):
        """
        Authenticate on-behalf-of a user, providing their token
        plus a middle tier app client id + secret (client secret or certificate based assertion)
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "resource": self.resource_uri,
            "assertion": token,
            "requested_token_use": "on_behalf_of"
        }
        if assertion:
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = assertion
        else:
            if client_secret:
                data['client_secret'] = client_secret
            else:
                data['client_secret'] = self.password
        if additionaldata:
            data = {**data, **additionaldata}
        res = await self.requests_post(f"{authority_uri}/oauth2/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_on_behalf_of_native_v2(self, token, client_secret=None, assertion=None, additionaldata=None, returnreply=False):
        """
        Authenticate on-behalf-of a user, providing their token
        plus a middle tier app client id + secret (client secret or certificate based assertion)
        v2 endpoint implementation which uses a scope instead of a resource
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "scope": self.scope,
            "assertion": token,
            "requested_token_use": "on_behalf_of"
        }
        if assertion:
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = assertion
        else:
            if client_secret:
                data['client_secret'] = client_secret
            else:
                data['client_secret'] = self.password
        if additionaldata:
            data = {**data, **additionaldata}
        if self.use_cae:
            self.set_cae()
        if self.claims:
            data['claims'] = json.dumps(self.claims)
        res = await self.requests_post(f"{authority_uri}/oauth2/v2.0/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata


    async def authenticate_with_refresh_native(self, refresh_token, client_secret=None, additionaldata=None, returnreply=False):
        """
        Authenticate with a refresh token plus optional secret in case of a non-public app (authorization grant)
        Native ROADlib implementation without adal requirement
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "resource": self.resource_uri,
        }
        if client_secret:
            data['client_secret'] = client_secret
        if additionaldata:
            data = {**data, **additionaldata}
        res = await self.requests_post(f"{authority_uri}/oauth2/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        if self.origin:
            self.tokendata['originheader'] = self.origin
        return self.tokendata

    async def authenticate_with_refresh_native_v2(self, refresh_token, client_secret=None, additionaldata=None, returnreply=False):
        """
        Authenticate with a refresh token plus optional secret in case of a non-public app (authorization grant)
        Native ROADlib implementation without adal requirement
        This function calls identity platform v2 and thus requires a scope instead of resource
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": self.scope,
        }
        if client_secret:
            data['client_secret'] = client_secret
        if self.use_cae:
            self.set_cae()
        if self.claims:
            data['claims'] = json.dumps(self.claims)
        if additionaldata:
            data = {**data, **additionaldata}
        res = await self.requests_post(f"{authority_uri}/oauth2/v2.0/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        if self.origin:
            self.tokendata['originheader'] = self.origin
        return self.tokendata

    async def authenticate_with_code_native(self, code, redirurl, client_secret=None, pkce_secret=None, additionaldata=None, returnreply=False):
        """
        Authenticate with a code plus optional secret in case of a non-public app (authorization grant)
        Native ROADlib implementation without adal requirement - also supports PKCE
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirurl,
            "resource": self.resource_uri,
        }
        if client_secret:
            data['client_secret'] = client_secret
        if additionaldata:
            data = {**data, **additionaldata}
        if not pkce_secret and self.use_pkce:
            pkce_secret = self.pkce_secret
        if pkce_secret:
            data['code_verifier'] = pkce_secret
        res = await self.requests_post(f"{authority_uri}/oauth2/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_with_code_native_v2(self, code, redirurl, client_secret=None, pkce_secret=None, additionaldata=None, returnreply=False):
        """
        Authenticate with a code plus optional secret in case of a non-public app (authorization grant)
        Native ROADlib implementation without adal requirement - also supports PKCE
        This function calls identity platform v2 and thus requires a scope instead of resource
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirurl,
            "scope": self.scope,
        }
        if client_secret:
            data['client_secret'] = client_secret
        if additionaldata:
            data = {**data, **additionaldata}
        if self.use_cae:
            self.set_cae()
        if self.claims:
            data['claims'] = json.dumps(self.claims)
        if not pkce_secret and self.use_pkce:
            pkce_secret = self.pkce_secret
        if pkce_secret:
            data['code_verifier'] = pkce_secret
        res = await self.requests_post(f"{authority_uri}/oauth2/v2.0/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_with_code_encrypted(self, code, sessionkey, redirurl):
        '''
        Encrypted code redemption. Like normal code flow but requires
        session key to decrypt response.
        '''
        authority_uri = self.get_authority_url()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirurl,
            "client_id": self.client_id,
            "client_info":1,
            "windows_api_version":"2.0"
        }
        res = await self.requests_post(f"{authority_uri}/oauth2/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        prtdata = await res.text()
        data = self.decrypt_auth_response(prtdata, sessionkey, asjson=True)
        return data

    async def authenticate_with_saml_native(self, saml_token, additionaldata=None, returnreply=False, grant_type=GRANT_TYPE_SAML1_1):
        """
        Authenticate with a SAML token from the Federation Server
        Native ROADlib implementation without adal requirement
        """
        authority_uri = self.get_authority_url()
        data = {
            "client_id": self.client_id,
            "grant_type": grant_type,
            "assertion": base64.b64encode(saml_token.encode('utf-8')).decode('utf-8'),
            "resource": self.resource_uri,
        }
        if additionaldata:
            data = {**data, **additionaldata}
        res = await self.requests_post(f"{authority_uri}/oauth2/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def authenticate_with_saml_native_v2(self, saml_token, additionaldata=None, returnreply=False, grant_type=GRANT_TYPE_SAML1_1):
        """
        Authenticate with a SAML token from the Federation Server
        Native ROADlib implementation without adal requirement
        This function calls identity platform v2 and thus requires a scope instead of resource
        """
        authority_uri = self.get_authority_url('organizations')
        data = {
            "client_id": self.client_id,
            "grant_type": grant_type,
            "assertion": base64.b64encode(saml_token.encode('utf-8')).decode('utf-8'),
            "scope": self.scope,
        }
        if self.use_cae:
            self.set_cae()
        if self.claims:
            data['claims'] = json.dumps(self.claims)
        if additionaldata:
            data = {**data, **additionaldata}
        res = await self.requests_post(f"{authority_uri}/oauth2/v2.0/token", data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def get_desktopsso_token(self, username=None, password=None, krbtoken=None):
        '''
        Get desktop SSO token either with plain username and password, or with a Kerberos auth token
        '''
        if username and password:
            rbody = DSSO_BODY_USERPASS.format(username=xml_escape(username), password=xml_escape(password), tenant=self.tenant)
            headers = {
                'Content-Type':'application/soap+xml; charset=utf-8',
                'SOAPAction': 'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
            }
            res = await self.requests_post(f'https://autologon.microsoftazuread-sso.com/{self.tenant}/winauth/trust/2005/usernamemixed?client-request-id=19ac39db-81d2-4713-8046-b0b7240592be', headers=headers, data=rbody)
            content = await res.text()
            tree = ET.fromstring(content)
            els = tree.findall('.//DesktopSsoToken')
            if len(els) > 0:
                token = els[0].text
                return token
            else:
                # Try finding error
                elres = tree.iter('{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}text')
                if elres:
                    errtext = next(elres)
                    raise AuthenticationException(errtext.text)
                else:
                    raise AuthenticationException(parseString(content).toprettyxml(indent='  '))
        elif krbtoken:
            rbody = DSSO_BODY_KERBEROS.format(tenant=self.tenant)
            headers = {
                'Content-Type':'application/soap+xml; charset=utf-8',
                'SOAPAction': 'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
                'Authorization': f'Negotiate {krbtoken}'
            }
            res = await self.requests_post(f'https://autologon.microsoftazuread-sso.com/{self.tenant}/winauth/trust/2005/windowstransport?client-request-id=19ac39db-81d2-4713-8046-b0b7240592be', headers=headers, data=rbody)
            content = await res.text()
            tree = ET.fromstring(content)
            els = tree.findall('.//DesktopSsoToken')
            if len(els) > 0:
                token = els[0].text
                return token
            else:
                print(parseString(content).toprettyxml(indent='  '))
                return False
        else:
            return False

    async def authenticate_with_desktopsso_token(self, dssotoken, returnreply=False, additionaldata=None):
        '''
        Authenticate with Desktop SSO token
        '''
        headers = {
            'x-client-SKU': 'PCL.Desktop',
            'x-client-Ver': '3.19.7.16602',
            'x-client-CPU': 'x64',
            'x-client-OS': 'Microsoft Windows NT 10.0.18363.0',
            'x-ms-PKeyAuth': '1.0',
            'client-request-id': '19ac39db-81d2-4713-8046-b0b7240592be',
            'return-client-request-id': 'true',
        }
        claim = base64.b64encode('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><DesktopSsoToken>{0}</DesktopSsoToken></saml:Assertion>'.format(dssotoken).encode('utf-8')).decode('utf-8')
        data = {
            'resource': self.resource_uri,
            'client_id': self.client_id,
            'grant_type': 'urn:ietf:params:oauth:grant-type:saml1_1-bearer',
            'assertion': claim,
        }
        authority_uri = self.get_authority_url()
        if additionaldata:
            data = {**data, **additionaldata}
        res = await self.requests_post(f"{authority_uri}/oauth2/token", headers=headers, data=data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        tokenreply = await res.json()
        if returnreply:
            return tokenreply
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        return self.tokendata

    async def get_bulk_enrollment_token(self, access_token):
        body = {
            "pid": str(uuid.uuid4()),
            "name": "bulktoken",
            "exp": (datetime.datetime.now() + datetime.timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
        }
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        url = 'https://login.microsoftonline.com/webapp/bulkaadjtoken/begin'
        res = await self.requests_post(url, json=body, headers=headers)
        data = await res.json()
        state = data.get('state')
        if not state:
            print(f'No state returned. Server said: {data}')
            return False

        if state == 'CompleteError':
            print(f'Error occurred: {data["resultData"]}')
            return False

        flowtoken = data.get('flowToken')
        if not flowtoken:
            print(f'Error. No flow token found. Data: {data}')
            return False
        print('Got flow token, polling for token creation')
        url = 'https://login.microsoftonline.com/webapp/bulkaadjtoken/poll'
        while True:
            res = self.requests_get(url, params={'flowtoken':flowtoken}, headers=headers)
            data = await res.json()
            state = data.get('state')
            if not state:
                print(f'No state returned. Server said: {data}')
                return False
            if state == 'CompleteError':
                print(f'Error occurred: {data["resultData"]}')
                return False
            if state == 'CompleteSuccess':
                tokenresult = json.loads(data['resultData'])
                # The function below needs one so lets supply it
                tokenresult['access_token'] = tokenresult['id_token']
                self.tokendata = self.tokenreply_to_tokendata(tokenresult, client_id='b90d5b8f-5503-4153-b545-b31cecfaece2')
                return self.tokendata
            time.sleep(1.0)

    async def get_srv_challenge(self):
        """
        Request server challenge (nonce) to use with a PRT
        Returns Nonce as a dict {'Nonce':'data'}
        """
        data = {'grant_type':'srv_challenge'}
        if self.cache_nonce:
            # Return cached nonce when we use that and it's fresh enough
            if self.nonce_request_time + 180 > time.time():
                return self.nonce
            # Not fresh, request new one
            self.nonce_request_time = time.time()
            res = await self.requests_post('https://login.microsoftonline.com/common/oauth2/token', data=data)
            self.nonce = await res.json(content_type=None)
            return self.nonce
        res = await self.requests_post('https://login.microsoftonline.com/common/oauth2/token', data=data)
        return await res.json(content_type=None)

    async def get_srv_challenge_nonce(self):
        """
        Request server challenge (nonce) to use with a PRT
        Returns Nonce as a string
        """
        noncedata = await self.get_srv_challenge()
        return noncedata['Nonce']

    async def authenticate_with_prt_cookie(self, cookie, context=None, derived_key=None, verify_only=False, sessionkey=None, redirurl=None, return_code=False):
        """
        Authenticate with a PRT cookie, optionally re-signing the cookie if a key is given
        """
        # Load cookie
        jdata = jwt.decode(cookie, options={"verify_signature":False}, algorithms=['HS256'])
        # Does it have a nonce?
        if not 'request_nonce' in jdata:
            nonce = await self.get_srv_challenge_nonce()
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
            sdata = derived_key
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
            nonce = await self.get_srv_challenge_nonce()
            jdata['request_nonce'] = nonce
            if context:
                # Resign with custom context, should be in base64
                newheaders = {
                    'ctx': base64.b64encode(context).decode('utf-8') #.rstrip('=')
                }
                cookie = jwt.encode(jdata, sdata, algorithm='HS256', headers=newheaders)
                print('Re-signed PRT cookie using custom context')
            else:
                newheaders = {
                    'ctx': headers['ctx']
                }
                cookie = jwt.encode(jdata, sdata, algorithm='HS256', headers=newheaders)
                print('Re-signed PRT cookie using derived key')

        authority_uri = self.get_authority_url()
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'haschrome': '1',
            'redirect_uri': 'https://login.microsoftonline.com/common/oauth2/nativeclient',
            'client-request-id': str(uuid.uuid4()),
            'x-client-SKU': 'PCL.Desktop',
            'x-client-Ver': '3.19.7.16602',
            'x-client-CPU': 'x64',
            'x-client-OS': 'Microsoft Windows NT 10.0.19569.0',
            'site_id': 501358,
            'sso_nonce': nonce,
            'mscrid': str(uuid.uuid4())
        }
        if self.scope:
            # Switch to identity platform v2 endpoint
            params['scope'] = self.scope
            url = f'{authority_uri}/oauth2/v2.0/authorize'
            coderedeemfunc = self.authenticate_with_code_native_v2
        else:
            params['resource'] = self.resource_uri
            url = f'{authority_uri}/oauth2/authorize'
            coderedeemfunc = self.authenticate_with_code_native

        headers = {
            'UA-CPU': 'AMD64',
        }
        if not self.user_agent:
            # Add proper user agent if we don't have one yet
            headers['User-Agent'] = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)'

        cookies = {
            'x-ms-RefreshTokenCredential': cookie
        }
        if redirurl:
            params['redirect_uri'] = redirurl

        res = await self.requests_get(url, params=params, headers=headers, cookies=cookies, allow_redirects=False)
        if res.status == 302 and params['redirect_uri'].lower() in res.headers['Location'].lower():
            ups = urlparse(res.headers['Location'])
            qdata = parse_qs(ups.query)
            # Return code if requested, otherwise redeem it
            if return_code:
                return qdata['code'][0]
            return await coderedeemfunc(qdata['code'][0], params['redirect_uri'])
        if res.status == 302 and 'sso_nonce' in res.headers['Location'].lower():
            ups = urlparse(res.headers['Location'])
            qdata = parse_qs(ups.query)
            if 'sso_nonce' in qdata:
                nonce = qdata['sso_nonce'][0]
                print(f'Redirected with new nonce. Old nonce may be expired. New nonce: {nonce}')
        if self.debug:
            with open('roadtools.debug.html','w') as outfile:
                outfile.write(str(res.headers))
                outfile.write('------\n\n\n-----')
                outfile.write(res.content.decode('utf-8'))

        # Try to find SSO nonce in json config
        startpos = res.content.find(b'$Config=')
        stoppos = res.content.find(b'//]]></script>')
        if startpos != -1 and stoppos != -1:
            jsonbytes = res.content[startpos+8:stoppos-2]
            try:
                jdata = json.loads(jsonbytes)
                try:
                    error = jdata['strMainMessage']
                    print(f'Error from STS: {error}')
                    error = jdata['strAdditionalMessage']
                    print(f'Additional info: {error}')
                    error = jdata['strServiceExceptionMessage']
                    print(f'Exception: {error}')
                except KeyError:
                    pass
            except json.decoder.JSONDecodeError:
                pass
        print('No authentication code was returned, make sure the PRT cookie is valid')
        print('It is also possible that the sign-in was blocked by Conditional Access policies')
        return False

    async def requests_get(self, *args, **kwargs):
        '''
        Wrapper around aiohttp.get to set all the options uniformly
        '''
        if not self.ahsession:
            # Don't save cookies
            jar = aiohttp.DummyCookieJar()
            self.ahsession = aiohttp.ClientSession(cookie_jar=jar)
        if self.proxies and 'https' in self.proxies:
            kwargs['proxy'] = self.proxies['https']
        kwargs['ssl'] = self.verify
        if self.user_agent:
            headers = kwargs.get('headers',{})
            headers['User-Agent'] = self.user_agent
            kwargs['headers'] = headers
        async with self.ahsession.get(*args, **kwargs) as response:
            await response.read()
        self.requestcounter += 1
        return response

    async def requests_post(self, *args, **kwargs):
        '''
        Wrapper around aiohttp.post to set all the options uniformly
        '''
        if not self.ahsession:
            # Don't save cookies
            jar = aiohttp.DummyCookieJar()
            self.ahsession = aiohttp.ClientSession(cookie_jar=jar)
        if self.proxies and 'https' in self.proxies:
            kwargs['proxy'] = self.proxies['https']
        kwargs['ssl'] = self.verify
        if self.user_agent:
            headers = kwargs.get('headers',{})
            headers['User-Agent'] = self.user_agent
            kwargs['headers'] = headers
        if self.origin:
            headers = kwargs.get('headers',{})
            headers['Origin'] = self.origin
            kwargs['headers'] = headers
        async with self.ahsession.post(*args, **kwargs) as response:
            await response.read()
        self.requestcounter += 1
        return response

    async def requests_put(self, *args, **kwargs):
        '''
        Wrapper around aiohttp.put to set all the options uniformly
        '''
        if not self.ahsession:
            # Don't save cookies
            jar = aiohttp.DummyCookieJar()
            self.ahsession = aiohttp.ClientSession(cookie_jar=jar)
        if self.proxies and 'https' in self.proxies:
            kwargs['proxy'] = self.proxies['https']
        kwargs['ssl'] = self.verify
        if self.user_agent:
            headers = kwargs.get('headers',{})
            headers['User-Agent'] = self.user_agent
            kwargs['headers'] = headers
        if self.origin:
            headers = kwargs.get('headers',{})
            headers['Origin'] = self.origin
            kwargs['headers'] = headers
        async with self.ahsession.put(*args, **kwargs) as response:
            await response.read()
        self.requestcounter += 1
        return response

    async def close_session(self):
        '''
        Close aiohttp client session
        '''
        if self.ahsession:
            await self.ahsession.close()

    async def get_tokens(self, args):
        """
        Get tokens based on the arguments specified.
        Expects args to be generated from get_sub_argparse
        """
        try:
            if self.tokendata:
                return self.tokendata
            if self.refresh_token and not self.access_token:
                if self.refresh_token == 'file':
                    with codecs.open(args.tokenfile, 'r', 'utf-8') as infile:
                        token_data = json.load(infile)
                else:
                    token_data = {'refreshToken': self.refresh_token}
                if self.scope:
                    return await self.authenticate_with_refresh_native_v2(token_data['refreshToken'], client_secret=self.password)
                return await self.authenticate_with_refresh_native(token_data['refreshToken'], client_secret=self.password)
            if self.access_token and not self.refresh_token:
                self.tokendata, _ = self.parse_accesstoken(self.access_token)
                return self.tokendata
            if self.username and self.password:
                discovery = await self.user_discovery_v1(self.username)
                if discovery['account_type'] == 'Federated':
                    # Use the federation flow
                    return await self.authenticate_username_password_federation_native(discovery)
                # Use native implementation
                if self.scope:
                    return await self.authenticate_username_password_native_v2()
                return await self.authenticate_username_password_native()
            if self.saml_token:
                if self.saml_token.lower() == 'stdin':
                    samltoken = sys.stdin.read()
                else:
                    samltoken = self.saml_token
                if self.scope:
                    return await self.authenticate_with_saml_native_v2(samltoken)
                return await self.authenticate_with_saml_native(samltoken)
            if args.as_app and self.password:
                if self.scope:
                    return await self.authenticate_as_app_native_v2()
                return await self.authenticate_as_app_native()
            if args.device_code:
                if self.scope:
                    return await self.authenticate_device_code_native_v2()
                return await self.authenticate_device_code_native()
            if args.prt_init:
                nonce = await self.get_srv_challenge_nonce()
                if nonce:
                    print(f'Requested nonce from server to use with ROADtoken: {nonce}')
                return False
            if args.prt_cookie:
                derived_key = self.ensure_binary_derivedkey(args.derived_key)
                context = self.ensure_binary_context(args.prt_context)
                sessionkey = self.ensure_binary_sessionkey(args.prt_sessionkey)
                return await self.authenticate_with_prt_cookie(args.prt_cookie, context, derived_key, args.prt_verify, sessionkey)
            if args.prt and args.prt_context and args.derived_key:
                derived_key = self.ensure_binary_derivedkey(args.derived_key)
                context = self.ensure_binary_context(args.prt_context)
                prt = self.ensure_plain_prt(args.prt)
                return await self.authenticate_with_prt(prt, context, derived_key=derived_key)
            if args.prt and args.prt_sessionkey:
                prt = self.ensure_plain_prt(args.prt)
                sessionkey = self.ensure_binary_sessionkey(args.prt_sessionkey)
                if args.kdf_v1:
                    return await self.authenticate_with_prt(prt, None, sessionkey=sessionkey)
                else:
                    return await self.authenticate_with_prt_v2(prt, sessionkey)
        except AuthenticationException as ex:
            try:
                error_data = json.loads(str(ex))
                print(f"Error during authentication: {error_data['error_description']}")
            except (TypeError, json.decoder.JSONDecodeError):
                # No json
                print(str(ex))
            return False

        # If we are here, no auth to try
        print('Not enough information was supplied to authenticate')
        return False

    async def get_tokens_async(self, args):
        """
        Get tokens based on the arguments specified.
        Expects args to be generated from get_sub_argparse
        """
        tokenresult = await self.get_tokens(args)
        await self.close_session()
        return tokenresult


def main():
    parser = argparse.ArgumentParser(add_help=True, description='ROADtools Authentication utility', formatter_class=argparse.RawDescriptionHelpFormatter)
    auth = AsyncAuthentication()
    auth.get_sub_argparse(parser)
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    auth.parse_args(args)
    if not asyncio.run(auth.get_tokens_async(args)):
        return
    auth.save_tokens(args)

if __name__ == '__main__':
    main()
