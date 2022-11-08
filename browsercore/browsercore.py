from subprocess import Popen, PIPE, STDOUT
import struct
import json
import sys
import binascii
import codecs
from urllib.parse import urlparse, parse_qs
from roadtools.roadlib.auth import Authentication
with codecs.open('roadtx.prt', 'r','utf-8') as prtfile:
    prtdata = json.load(prtfile)
prt = prtdata['refresh_token']
sessionkey = binascii.unhexlify(prtdata['session_key'])
auth = Authentication(client_id = '1fec8e78-bce4-4aaf-ab1b-5451cc387264')
lengthb = sys.stdin.buffer.read(4)
length = struct.unpack('L', lengthb)[0]
data = sys.stdin.buffer.read(length).decode('utf-8')
request = json.loads(data)

ups = urlparse(request["uri"])
qdata = parse_qs(ups.query)
cookie = auth.create_prt_cookie_kdf_ver_2(prt, sessionkey, qdata["sso_nonce"])
out = {
    "response": [
        {
            "name": "x-ms-RefreshTokenCredential",
            "data": cookie,
            "p3pHeader": "CP=\"CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT\"",
            "flags": 8256
        }
    ]
}
text = json.dumps(out)
lf = struct.pack('L', len(text))
sys.stdout.buffer.write(lf + text.encode('utf-8'))
