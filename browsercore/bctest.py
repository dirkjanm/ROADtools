from subprocess import Popen, PIPE, STDOUT
import json
import struct
out = {
    "uri": "https://login.microsoftadaa.com?sso_nonce=abc",
    "p3pHeader": "CP=\"CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT\"",
    "flags": 8256
}
text = json.dumps(out)
lf = struct.pack('L', len(text))
output = lf + text.encode('utf-8')
p = Popen(['python','browsercore.py'], stdout=PIPE, stdin=PIPE, stderr=PIPE)
stdout_data = p.communicate(input=output)
print(stdout_data[0])
print(stdout_data[1])
