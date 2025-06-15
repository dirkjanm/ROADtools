import argparse
import os
import sys
import codecs
import datetime
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
TEMPLATE = """import os
ISSUER = os.environ.get("ISSUER", '{ISSUER}')
REALISSUER = os.environ.get("REALISSUER", '{REALISSUER}')
PRIVKEY = os.environ.get("PRIVKEY", '''{PRIVKEY}''')
KEYID = os.environ.get("KEYID", '''{KEYID}''')
CERT = os.environ.get('CERT','''{CERT}''')
# Whether to enable External Auth Method capabilities for a fake MFA provider
EAMENABLED = {EAM}
# Whether to enable the "backdoor" EAM provider that injects custom keys into existing EAM provider configurations
BACKDOORENABLED = {BACKDOOR}
"""

def main():
    # Primary argument parser
    parser = argparse.ArgumentParser(add_help=True, description='ROADoidc - minimal OpenID Connect config generator', formatter_class=argparse.RawDescriptionHelpFormatter)
    # Add subparsers for modules
    parser.add_argument('--cert-pem', action='store', default="roadoidc.pem", metavar='file', help='Certificate file to store IdP cert (default: roadoidc.pem)')
    parser.add_argument('--key-pem', action='store', default="roadoidc.key", metavar='file', help='Private key file to store IdP key (default: roadoidc.key)')
    parser.add_argument('-i',
                        '--issuer',
                        action='store',
                        help='Issuer of the federated credential - needs to be the base URL where the config is hosted',
                        required=True)
    parser.add_argument('-c',
                        '--configfile',
                        action='store',
                        default='flaskapp/app_config.py',
                        help='File to store the configuration (default: flaskapp/app_config.py)')
    parser.add_argument('-k',
                        '--kid',
                        action='store',
                        help='Key ID to use (default: SHA1 thumbprint of generated certificate)')
    parser.add_argument('--eam',
                        action='store_true',
                        help='Enable roadoidc as an External Authentication Method')
    parser.add_argument('--backdoor',
                        action='store_true',
                        help='Enable EAM backdoor that serves keys from a legit EAM provider plus our backdoor keys')
    parser.add_argument('--real-issuer',
                        action='store',
                        help='Real issuer that we serve backdoor keys for - required if specifying --backdoor')

    args = parser.parse_args()

    privout = args.key_pem
    certout = args.cert_pem
    configout = args.configfile
    issuer = args.issuer

    if args.backdoor and not args.real_issuer:
        print('Real issuer must be specified if enabling backdoor keys')
        return
    real_issuer = args.real_issuer

    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Write device key to disk
    print(f'Saving private key to {privout}')
    pkpem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(privout, "wb") as keyf:
        keyf.write(pkpem)

    # Generate a self-signed cert
    subject = cissuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        cissuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 years
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).sign(key, hashes.SHA256())

    # Write our certificate out to disk.

    print(f'Saving certificate to {certout}')
    certpem = cert.public_bytes(serialization.Encoding.PEM)
    with open(certout, "wb") as f:
        f.write(certpem)

    kid = args.kid
    if not kid:
        # Get cert thumbprint
        certbytes = cert.public_bytes(
            serialization.Encoding.DER
        )
        digest = hashes.Hash(hashes.SHA1())
        digest.update(certbytes)
        kid = base64.urlsafe_b64encode(digest.finalize()).decode('utf-8')

    print(f'Key ID: {kid}')
    filled_template = TEMPLATE.format(ISSUER=issuer,
                                      REALISSUER=real_issuer,
                                      CERT=certpem.decode('utf-8'),
                                      PRIVKEY=pkpem.decode('utf-8'),
                                      KEYID=kid,
                                      EAM=str(bool(args.eam)),
                                      BACKDOOR=str(bool(args.backdoor)))

    print(f'Saving configuration to {configout}')
    with codecs.open(configout, "w", "utf-8") as f:
        f.write(filled_template)

if __name__ == '__main__':
    main()
