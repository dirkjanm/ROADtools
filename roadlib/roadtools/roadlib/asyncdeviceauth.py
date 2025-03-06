import base64
import binascii
import struct
import json
import sys
import pprint
import random
import string
import codecs
import jwt
import requests
import os
import time
import warnings
import datetime
import uuid
import urllib3
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.utils import CryptographyDeprecationWarning
from roadtools.roadlib.asyncauth import AsyncAuthentication
from roadtools.roadlib.auth import get_data, AuthenticationException
from roadtools.roadlib.deviceauth import DeviceAuthentication

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

class AsyncDeviceAuthentication(DeviceAuthentication):
    """
    Device authentication for ROADtools. Handles device registration,
    PRT request/renew and token request using WAM emulation.
    """
    def __init__(self, auth=None):
        # Make sure we instantiate the Async Version of auth
        if auth:
            self.auth = auth
        else:
            self.auth = auth = AsyncAuthentication()
        super().__init__(auth)

    async def create_hello_prt_assertion(self, username):
        now = int(time.time())
        payload = {
          "iss": username,
          # Should be tenant ID, but this is not verified
          "aud": "common",
          "iat": now-3600,
          "exp": now+3600,
          "request_nonce": await self.auth.get_srv_challenge_nonce(),
          "scope": "openid aza ugs"
        }
        headers = {
            "kid": self.get_privkey_kid(),
            "use": "ngc"
        }
        reqjwt = jwt.encode(payload, algorithm='RS256', key=self.hellokeydata, headers=headers)
        return reqjwt

    async def get_prt_with_hello_key(self, username, assertion=None):
        challenge = await self.auth.get_srv_challenge_nonce()
        if not assertion:
            assertion = await self.create_hello_prt_assertion(username)
        # Construct
        payload = {
            "client_id": "38aa3b87-a06d-4817-b275-7a316988d93b",
            "request_nonce": challenge,
            "scope": "openid aza ugs",
            # Not sure if these matter
            "group_sids": [],
            "win_ver": "10.0.19041.868",
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            # Windows includes this, but it is not required or used
            # user is instead taken from JWT assertion
            "username": username,
            "assertion": assertion
        }
        return await self.request_token_with_devicecert_signed_payload(payload)

    async def register_winhello_key(self, pubkeycngblob, access_token):
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': 'Dsreg/10.0 (Windows 10.0.19044.1826)',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        data = {
            "kngc": pubkeycngblob.decode('utf-8')
        }
        res = await self.auth.requests_post('https://enterpriseregistration.windows.net/EnrollmentServer/key/?api-version=1.0', json=data, headers=headers, proxies=self.proxies, verify=self.verify)
        return await res.json()

    async def register_device(self, access_token, jointype=0, certout=None, privout=None, device_type=None, device_name=None, os_version=None, deviceticket=None, device_domain=None):
        """
        Registers or joins a device in Azure AD. Requires an access token to the device registration service.
        """
        # Fill in names if not supplied
        if not device_name:
            device_name = 'DESKTOP-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        # Fill in names if not supplied
        if not certout:
            certout = device_name.lower() + '.pem'

        if not privout:
            privout = device_name.lower() + '.key'

        if not device_type:
            device_type = "Windows"

        if not os_version:
            if device_type.lower() == "windows":
                os_version = "10.0.19041.928"
            elif device_type.lower() == "macos":
                os_version = "12.2.0"
            elif device_type.lower() == "macos14":
                os_version = "14.5.0"
            elif device_type.lower() == "android":
                os_version = "13.0"
            else:
                os_version = "1"

        if not device_domain:
            device_domain = "iminyour.cloud"

        if device_type.lower() != "macos14":
            # Generate our key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # Write device key to disk
            print(f'Saving private key to {privout}')
            with open(privout, "wb") as keyf:
                keyf.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
        else:
            key = ec.generate_private_key(
                ec.SECP256R1()
            )
            print(f'Saving private key to {privout}')
            with open(privout, "wb") as keyf:
                keyf.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "7E980AD9-B86D-4306-9425-9AC066FB014A"),
        ])).sign(key, hashes.SHA256())

        # Get parameters needed to construct the CNG blob
        certreq = csr.public_bytes(serialization.Encoding.DER)
        certbytes = base64.b64encode(certreq)

        api_version = "2.0"
        if device_type.lower() == 'macos':
            user_agent = 'DeviceRegistrationClient'
            data = {
                "DeviceDisplayName" : device_name,
                "CertificateRequest" : {
                    "Type" : "pkcs10",
                    "Data" : certbytes.decode('utf-8')
                },
                "OSVersion" : os_version,
                "TargetDomain" : device_domain,
                "AikCertificate" : "",
                "DeviceType" : "MacOS",
                "TransportKey" : base64.b64encode(self.create_public_jwk_from_key(key, True).encode('utf-8')).decode('utf-8'),
                "JoinType" : jointype,
                "AttestationData" : ""
            }
        elif device_type.lower() == 'macos14':
            user_agent = 'DeviceRegistrationClient'
            api_version = "3.0"
            data = {
              "AikCertificate" : "",
              "AttestationData" : "",
              "CertificateRequest" : {
                "Data" : certbytes.decode('utf-8'),
                "KeySecurity" : "SecureEnclave",
                "KeyType" : "ECC",
                "Type" : "pkcs10"
              },
              "DeviceDisplayName" : device_name,
              "DeviceKeys" : [
                {
                  "Data" : self.create_public_jwk_from_ec_key(key),
                  "Encoding" : "JWK",
                  "Type" : "ECC",
                  "Usage" : "STK"
                }
              ],
              "DeviceType" : "MacOS",
              "JoinType" : jointype,
              "OSVersion" : "14.5.0",
              "TargetDomain" : "iminyour.cloud"
            }
        elif device_type.lower() == 'android':
            user_agent = 'DeviceRegistrationClient'
            data = {
                "Attributes": {},
                "CertificateRequest":
                {
                    "Data": certbytes.decode('utf-8'),
                    "Type": "pkcs10"
                },
                "DeviceDisplayName": device_name,
                "DeviceType": "Android",
                "JoinType": jointype,
                "OSVersion": os_version,
                "TargetDomain": "6287f28f-4f7f-4322-9651-a8697d8fe1bc",
                "TransportKey": base64.b64encode(self.create_public_jwk_from_key(key, True).encode('utf-8')).decode('utf-8'),
            }
        else:
            user_agent = f'Dsreg/10.0 (Windows {os_version})'
            pubkeycngblob = base64.b64encode(self.create_pubkey_blob_from_key(key))
            data = {
                "CertificateRequest":
                    {
                        "Type": "pkcs10",
                        "Data": certbytes.decode('utf-8')
                    },
                "TransportKey": pubkeycngblob.decode('utf-8'),
                # Can likely be edited to anything, are not validated afaik
                "TargetDomain": device_domain,
                "DeviceType": device_type,
                "OSVersion": os_version,
                "DeviceDisplayName": device_name,
                "JoinType": jointype,
                "attributes": {
                    "ReuseDevice": "true",
                    "ReturnClientSid": "true"
                }
            }
            # Add device ticket if requested
            if deviceticket:
                data['attributes']['MSA-DDID'] = base64.b64encode(deviceticket.encode('utf-8')).decode('utf-8')


        headers = {
            'User-Agent': user_agent,
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        print('Registering device')
        res = await self.auth.requests_post(f'https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version={api_version}', json=data, headers=headers, proxies=self.proxies, verify=self.verify)
        returndata = await res.json()
        if not 'Certificate' in returndata:
            print('Error registering device! Got response:')
            pprint.pprint(returndata)
            return False
        cert = x509.load_der_x509_certificate(base64.b64decode(returndata['Certificate']['RawBody']))
        # There is only one, so print it
        for attribute in cert.subject:
            print(f"Device ID: {attribute.value}")
        with open(certout, "wb") as certf:
            certf.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f'Saved device certificate to {certout}')
        return True

    async def register_hybrid_device(self, objectsid, tenantid, certout=None, privout=None, device_type=None, device_name=None, os_version=None):
        '''
        Register hybrid device. Requires existing key/cert to be already loaded and the SID to be specified.
        Device should be synced to AAD already, otherwise this will fail.
        Note that certout and privout will be suffixed with the _aad suffix in the actual output to prevent overwriting the original self-signed cert
        '''
        # Get device name from cert if not supplied
        if not device_name:
            certname = certout.rsplit('.', 1)
            if len(certname) > 1:
                device_name = certname[0]
            else:
                device_name = certname
            print(f"Assuming device name {device_name} from certificate file name")

        if not device_type:
            device_type = "Windows"

        if not os_version:
            os_version = "10.0.19041.928"

        # Output keys have the _aad suffix to prevent overwriting original cert + key
        certout = device_name.lower() + '_aad.pem'
        privout = device_name.lower() + '_aad.key'

        # Generate our new shiny key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Write device key to disk
        print(f'Saving private key to {privout}')
        with open(privout, "wb") as keyf:
            keyf.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Generate a CSR that will give us an Azure AD signed cert
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "7E980AD9-B86D-4306-9425-9AC066FB014A"),
        ])).sign(key, hashes.SHA256())

        # Get parameters needed to construct the CNG blob
        certreq = csr.public_bytes(serialization.Encoding.DER)
        certbytes = base64.b64encode(certreq)

        pubkeycngblob = base64.b64encode(self.create_pubkey_blob_from_key(key))
        curtime = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        signdata = f"{objectsid}.{curtime}Z"
        signedblob = base64.b64encode(self.privkey.sign(
            signdata.encode('utf-8'),
            apadding.PKCS1v15(),
            hashes.SHA256()
        ))

        data = {
            "CertificateRequest":
                {
                    "Type": "pkcs10",
                    "Data": certbytes.decode('utf-8')
                },
            "ServerAdJoinData":
            {
                "TransportKey": pubkeycngblob.decode('utf-8'),
                "TargetDomain": tenantid,
                "DeviceType": device_type,
                "OSVersion": os_version,
                "DeviceDisplayName": device_name,
                "TargetDomainId": f"{tenantid}",
                "ClientIdentity":
                {
                    "Type": "sha256signed",
                    "Sid": signdata,
                    "SignedBlob": signedblob.decode('utf-8')
                }
            },
            # Hybrid join = 6
            "JoinType": 6,
            "attributes": {
                "ReuseDevice": "true",
                "ReturnClientSid": "true"
            }
        }

        headers = {
            'User-Agent': f'Dsreg/10.0 (Windows {os_version})',
            'Content-Type': 'application/json'
        }
        # Extract device ID from certificate
        for attr in self.certificate.subject:
            deviceid = attr.value
        print(f"Device ID (from certificate): {deviceid}")
        print('Registering device')
        res = await self.auth.requests_put(f'https://enterpriseregistration.windows.net/EnrollmentServer/device/{deviceid}?api-version=2.0', json=data, headers=headers, proxies=self.proxies, verify=self.verify)
        returndata = await res.json()
        if not 'Certificate' in returndata:
            print('Error registering device! Got response:')
            pprint.pprint(returndata)
            return False
        cert = x509.load_der_x509_certificate(base64.b64decode(returndata['Certificate']['RawBody']))
        # There is only one, so print it
        for attribute in cert.subject:
            print(f"AAD device ID: {attribute.value}")
        with open(certout, "wb") as certf:
            certf.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f'Saved device certificate to {certout}')
        return True

    async def delete_device(self, certpath, keypath):
        """
        Delete the device from Azure ID. Requires client cert auth
        """
        # Get device ID from certificate
        deviceid = None
        for attribute in self.certificate.subject:
            deviceid = attribute.value
        if not deviceid:
            return
        # For now we use requests here since I'm too lazy to figure out TLS client certs in aiohttp
        res = requests.delete(f'https://enterpriseregistration.windows.net/EnrollmentServer/device/{deviceid}', cert=(certpath, keypath))
        if res.status_code != 200:
            print('Error deleting device:')
            print(res.content)
            return False
        print('Device was deleted in Azure AD')
        return True

    async def request_token_with_devicecert_signed_payload(self, payload, use_v3=False, reqclientinfo=True, reqtgt=True, returnreply=False):
        """
        Wrap the request payload in a JWT and sign this using the device cert / key
        """
        certder = self.certificate.public_bytes(serialization.Encoding.DER)
        certbytes = base64.b64encode(certder)
        authority_uri = self.auth.get_authority_url()
        if not use_v3:
            # Windows API flow - uses identity platform v1 endpoint
            headers = {
              "x5c": certbytes.decode('utf-8'),
              "kdf_ver": 2
            }
            reqjwt = jwt.encode(payload, algorithm='RS256', key=self.keydata, headers=headers)
            prt_request_data = {
                'windows_api_version':'2.2',
                'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'request':reqjwt,
            }
            if reqclientinfo:
                prt_request_data['client_info'] = '1'
            if reqtgt:
                prt_request_data['tgt'] = True
            url = f'{authority_uri}/oauth2/token'
        else:
            # PRT Protocol version 3 flow, uses identity platform v2
            headers = {
              "x5c": certbytes.decode('utf-8'),
            }
            reqjwt = jwt.encode(payload, algorithm='RS256', key=self.keydata, headers=headers)
            prt_request_data = {
                'prt_protocol_version':'3.0',
                'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'request':reqjwt,
            }
            if reqclientinfo:
                prt_request_data['client_info'] = '1'
            url = f'{authority_uri}/oauth2/v2.0/token'

        res = await self.auth.requests_post(url, data=prt_request_data)

        if res.status != 200:
            raise AuthenticationException(await res.text())
        prtdata = await res.json()

        # Return the reply if wanted, needed for non-prt flows using similar requests
        if returnreply:
            return prtdata

        # Encrypted session key that we need to unwrap
        sessionkey_jwe = prtdata['session_key_jwe']
        uwk = self.decrypt_jwe_with_transport_key(sessionkey_jwe)

        prtdata['session_key'] = binascii.hexlify(uwk).decode('utf-8')
        # Decrypt Kerberos keys
        for tgt in ['tgt_ad', 'tgt_cloud']:
            if tgt in prtdata:
                tgtdata = json.loads(prtdata[tgt])
                if tgtdata['keyType'] != 0:
                    # There is a key
                    tgt_sessionkey = self.auth.decrypt_auth_response(tgtdata['clientKey'], uwk)
                    prtdata[tgt + '_sessionkey'] = binascii.hexlify(tgt_sessionkey).decode('utf-8')

        return prtdata

    async def request_token_with_sessionkey_signed_payload(self, payload, reqtgt=True):
        """
        Request a token (access / refresh / PRT) using a payload signed
        with the PRT session key.
        """
        authority_uri = self.auth.get_authority_url()
        context = os.urandom(24)
        headers = {
            'ctx': base64.b64encode(context).decode('utf-8'), #.rstrip('=')
            'kdf_ver': 2
        }
        # Sign with random key just to get jwt body in right encoding
        tempjwt = jwt.encode(payload, os.urandom(32), algorithm='HS256', headers=headers)
        jbody = tempjwt.split('.')[1]
        jwtbody = base64.urlsafe_b64decode(jbody+('='*(len(jbody)%4)))
        # Now calculate the derived key based on random context plus jwt body
        _, derived_key = self.auth.calculate_derived_key_v2(self.session_key, context, jwtbody)
        reqjwt = jwt.encode(payload, derived_key, algorithm='HS256', headers=headers)

        token_request_data = {
            'windows_api_version':'2.2',
            'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'request':reqjwt,
            'client_info':'1'
        }
        if self.auth.use_cae:
            self.auth.set_cae()
        if self.auth.claims:
            token_request_data['claims'] = json.dumps(self.auth.claims)
        if reqtgt:
            token_request_data['tgt'] = True
        res = await self.auth.requests_post(f'{authority_uri}/oauth2/token', data=token_request_data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        responsedata = await res.text()
        return responsedata

    async def get_prt_with_password(self, username, password):
        challenge = await self.auth.get_srv_challenge_nonce()
        # Construct
        payload = {
            "client_id": "38aa3b87-a06d-4817-b275-7a316988d93b",
            "request_nonce": challenge,
            "scope": "openid aza ugs",
            # Not sure if these matter
            "group_sids": [],
            "win_ver": "10.0.19041.868",
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        return await self.request_token_with_devicecert_signed_payload(payload)

    async def get_prt_with_samltoken(self, samltoken):
        challenge = await self.auth.get_srv_challenge_nonce()
        # Construct request payload
        payload = {
            "client_id": "38aa3b87-a06d-4817-b275-7a316988d93b",
            "request_nonce": challenge,
            "scope": "openid aza ugs",
            # Not sure if these matter
            "group_sids": [],
            "win_ver": "10.0.19041.868",
            "grant_type": "urn:ietf:params:oauth:grant-type:saml1_1-bearer",
            "assertion": base64.b64encode(samltoken.encode('utf-8')).decode('utf-8'),
        }
        return await self.request_token_with_devicecert_signed_payload(payload)

    async def get_token_for_device(self, client_id, resource, redirect_uri=None):
        challenge = await self.auth.get_srv_challenge_nonce()
        # Construct request payload
        payload = {
          "resource": resource,
          "client_id": client_id,
          "request_nonce": challenge,
          "win_ver": "10.0.22621.608",
          "grant_type": "device_token",
          "redirect_uri": f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{client_id}",
          "iss": "aad:brokerplugin"
        }
        # Custom redirect_uri if needed
        if redirect_uri:
            payload['redirect_uri'] = redirect_uri
        return await self.request_token_with_devicecert_signed_payload(payload, reqtgt=False, reqclientinfo=False, returnreply=True)

    async def get_prt_with_refresh_token(self, refresh_token):
        challenge = await self.auth.get_srv_challenge_nonce()
        payload = {
            "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",
            "request_nonce": challenge,
            "scope": "openid aza ugs",
            # Not sure if these matter
            "group_sids": [],
            "win_ver": "10.0.19041.868",
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        return await self.request_token_with_devicecert_signed_payload(payload)

    async def renew_prt(self):
        challenge = await self.auth.get_srv_challenge_nonce()
        payload = {
            "client_id": "38aa3b87-a06d-4817-b275-7a316988d93b",
            "request_nonce": challenge,
            "scope": "openid aza ugs",
            "iss": "aad:brokerplugin",
            "grant_type": "refresh_token",
            "refresh_token": self.prt,
            "previous_refresh_token": self.prt,
            # Not sure if these matter
            "group_sids": [],
            "win_ver": "10.0.19041.868",
        }
        responsedata = await self.request_token_with_sessionkey_signed_payload(payload)
        prtdata = self.auth.decrypt_auth_response(responsedata, self.session_key, True)
        prtdata['session_key'] = binascii.hexlify(self.session_key).decode('utf-8')
        return prtdata

    async def aad_brokerplugin_prt_auth(self, client_id, resource=None, renew_prt=False, redirect_uri=None):
        """
        Auth using a PRT emulating the AAD Brokerplugin (WAM) client
        """
        client = self.auth.lookup_client_id(client_id).lower()
        payload = {
            "win_ver": "10.0.19041.1620",
            "scope": "openid",
            "refresh_token": self.prt,
            "redirect_uri": f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{client}",
            "iss": "aad:brokerplugin",
            "grant_type": "refresh_token",
            "client_id": client,
            "aud": "login.microsoftonline.com",
            "iat": str(int(time.time())),
            "exp": str(int(time.time())+(3600)),
        }
        # Resource is required to request an access token, but if we just want an id token and refresh token its optional
        if resource:
            payload['resource'] = self.auth.lookup_resource_uri(resource)
        # Request a new PRT, otherwise normal refresh token will be issued
        if renew_prt:
            payload['scope'] = "openid aza"
        payload['request_nonce'] = await self.auth.get_srv_challenge_nonce()
        # Custom redirect_uri if needed
        if redirect_uri:
            payload['redirect_uri'] = redirect_uri
        elif client == '1b730954-1685-4b74-9bfd-dac224a7b894':
            payload['redirect_uri'] = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
        responsedata = await self.request_token_with_sessionkey_signed_payload(payload, False)
        tokendata = self.auth.decrypt_auth_response(responsedata, self.session_key, True)
        return tokendata

    async def aad_brokerplugin_prt_auth_v3(self, client_id, scope=None, renew_prt=False, redirect_uri=None):
        """
        Auth using a PRT emulating the AAD Brokerplugin client on MacOS (and Android/etc)
        Uses PRT protocol v3
        """
        client = self.auth.lookup_client_id(client_id).lower()
        payload = {
            "refresh_token": self.prt,
            "iss": "0ec893e0-5785-4de6-99da-4ed124e5296c",
            "grant_type": "refresh_token",
            "client_id": f"{client}",
            "redirect_uri": "msauth://Microsoft.AAD.BrokerPlugin",
            "aud": "https://login.windows.net/common/oauth2/v2.0/token",
        }
        # payload['scope'] = 'urn:aad:tb:update:prt/.default openid profile offline_access'
        if not scope:
            scope = self.auth.scope
        payload['scope'] = scope
        # Request new PRT instead of access token
        if renew_prt and not 'aza' in scope.split(' '):
            payload['scope'] += ' aza'
        payload['request_nonce'] = await self.auth.get_srv_challenge_nonce()
        # Custom redirect_uri if needed
        if redirect_uri:
            payload['redirect_uri'] = redirect_uri
        responsedata = await self.request_token_with_sessionkey_signed_payload_prtprotocolv3(payload, False)
        tokendata = self.auth.decrypt_auth_response(responsedata, self.session_key, True)
        return tokendata

    async def request_token_with_sessionkey_signed_payload_prtprotocolv3(self, payload, reqtgt=True):
        """
        Request a token (access / refresh / PRT) using a payload signed
        with the PRT session key. Uses PRT Protocol version 3
        """
        context = os.urandom(24)
        headers = {
            'ctx': base64.b64encode(context).decode('utf-8'),
            'kdf_ver': 2
        }

        # Sign with random key just to get jwt body in right encoding
        tempjwt = jwt.encode(payload, os.urandom(32), algorithm='HS256', headers=headers)
        jbody = tempjwt.split('.')[1]
        jwtbody = base64.urlsafe_b64decode(jbody+('='*(len(jbody)%4)))

        # Now calculate the derived key based on random context plus jwt body
        _, derived_key = self.auth.calculate_derived_key_v2(self.session_key, context, jwtbody)

        # Uncomment to use KDFv1
        # _, derived_key = self.auth.calculate_derived_key(self.session_key, context)
        reqjwt = jwt.encode(payload, derived_key, algorithm='HS256', headers=headers)

        token_request_data = {
            'prt_protocol_version':'3.0',
            'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'request':reqjwt,
            'client_info':'1'
        }
        if reqtgt:
            token_request_data['tgt'] = True
        if self.auth.claims:
            token_request_data['claims'] = json.dumps(self.auth.claims)
        res = await self.auth.requests_post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=token_request_data)
        if res.status != 200:
            raise AuthenticationException(await res.text())
        responsedata = await res.text()
        return responsedata
