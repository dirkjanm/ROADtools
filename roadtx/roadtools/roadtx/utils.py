import os
import codecs
import json
import base64, binascii, argparse, textwrap, uuid

def find_redirurl_for_client(client, interactive=True, broker=False):
    '''
    Get valid redirect URLs for specified client. Interactive means a https URL is preferred.
    In practice roadtx often prefers non-interactive URLs even with interactive flows since it rewrites
    the URLs on the fly anyway
    '''
    current_dir = os.path.abspath(os.path.dirname(__file__))
    datafile = os.path.join(current_dir, 'firstpartyscopes.json')
    with codecs.open(datafile,'r','utf-8') as infile:
        data = json.load(infile)
    try:
        app = data['apps'][client.lower()]
    except KeyError:
        return 'https://login.microsoftonline.com/common/oauth2/nativeclient'
    if broker:
        brokerurl = f'ms-appx-web://Microsoft.AAD.BrokerPlugin/{client.lower()}'
        if brokerurl in app['redirect_uris']:
            return brokerurl
        return app['preferred_noninteractive_redirurl']
    if interactive and app['preferred_interactive_redirurl'] is not None:
        return app['preferred_interactive_redirurl']
    if app['preferred_noninteractive_redirurl']:
        return app['preferred_noninteractive_redirurl']
    # Return default URL even if it might not work since some follow up functions break when called with a None value
    return 'https://login.microsoftonline.com/common/oauth2/nativeclient'

# Refresh token analysis by @blurbdust
def guid_to_string(binary_guid):
    return str(uuid.UUID(bytes_le=binary_guid)).lower()

def b64_d(string):
    return base64.b64decode(string + '=' * (-len(string) % 4))
def b64_url_d(string):
    return base64.urlsafe_b64decode(string + '=' * (-len(string) % 4))

def parse_encrypted_token(rhdata):
    refresh = rhdata.split(".")
    rh = refresh[1]
    print("Parsing encrypted token header")
    print(f"Version: {refresh[0]}")
    print(f"Preamble: {binascii.hexlify(b64_url_d(rh)[:3])}")
    tenant = b64_url_d(rh)[3:3+16]
    tenant = guid_to_string(tenant)
    print(f"Tenant ID: {tenant}")
    app = b64_url_d(rh)[3+16:3+16+16]
    app = guid_to_string(app)
    print(f"App ID: {app}")
    print(f"Postamble: {binascii.hexlify(b64_url_d(rh)[-5:])}")
    if len(refresh) > 2 and refresh[2] != '':
        print("Parsing encrypted token")
        a = b64_url_d(refresh[2])[:16]
        b = b64_url_d(refresh[2])[16:32]
        print(f"Possible type ID\n03=refresh_token, 04=auth_code {guid_to_string(a)}")
        print(f"Unknown data {guid_to_string(b)}")
        print("Dumping encrypted part")
        print(Hexdump(b64_url_d(refresh[2])[32:]))

class Hexdump(object):
    def __init__(self, buf, off=0):
        self.buf = buf
        self.off = off

    def __iter__(self):
        last_bs, last_line = None, None
        for i in range(0, len(self.buf), 16):
            bs = bytearray(self.buf[i : i + 16])
            line = "{:08x}  {:23}  {:23}  |{:16}|".format(
                self.off + i,
                " ".join(("{:02x}".format(x) for x in bs[:8])),
                " ".join(("{:02x}".format(x) for x in bs[8:])),
                "".join((chr(x) if 32 <= x < 127 else "." for x in bs)),
            )
            if bs == last_bs:
                line = "*"
            if bs != last_bs or line != last_line:
                yield line
            last_bs, last_line = bs, line
        yield "{:08x}".format(self.off + len(self.buf))

    def __str__(self):
        return "\n".join(self)

    def __repr__(self):
        return "\n".join(self)
