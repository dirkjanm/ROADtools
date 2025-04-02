'''
Hacky KeePass file decrypt script
Based on https://gist.github.com/Evidlo/8bc69fb58dcd0c9e6ce748b6f2cb59f7
Modified to work with cryptography - some stuff from pycryptodome as cryptography does not have salsa20
'''
import struct
import hashlib
import zlib
import codecs
from xml.etree import ElementTree
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Cryptodome.Cipher import Salsa20, ChaCha20

class HackyKeePassFileReader():
    def __init__(self, database, password, plain=False):
        self.stream_key = None
        self.stream_cipher_id = None
        if plain:
            self.read_keepass_xml(database)
        else:
            self.data = self.decrypt_keepass(database, password)
        self.root = ElementTree.fromstring(self.data)
        self.decrypter = self.init_decrypt()

    def get_entry(self, search):
        '''
        Get entry from KeePass XML file
        '''
        # Renew each time we loop through file
        # since protected entries have to be decrypted sequentially
        self.decrypter = self.init_decrypt()
        for entry in self.root.iter('Entry'):
            entrydata = {}
            for kvpair in entry.findall('String'):
                kname = kvpair.find('Key').text
                kval = kvpair.find('Value').text
                crypted = kvpair.find('Value').get('Protected', None) == 'True'
                if crypted and kval:
                    decrypted = self.decrypter.decrypt(base64.b64decode(kval))
                    entrydata[kname] = decrypted.decode('utf-8')
                else:
                    entrydata[kname] = kval
            if entrydata['UserName'] and entrydata['UserName'].lower() == search.lower():
                return entrydata
        return {}

    def init_decrypt(self):
        '''
        Create encryption cipher, either salsa20 or chacha20
        '''
        if self.stream_cipher_id == 3:
            # Untested
            key_hash = hashlib.sha512(self.stream_key).digest()
            key = key_hash[:32]
            nonce = key_hash[32:44]
            cipher = ChaCha20.new(
                key=key,
                nonce=nonce
            )
            return cipher
        if self.stream_cipher_id == 2:
            # Salsa20
            key = hashlib.sha256(self.stream_key).digest()
            nonce = b'\xE8\x30\x09\x4B\x97\x20\x5D\x2A'
            cipher = Salsa20.new(key=key, nonce=nonce)
            return cipher

    def read_keepass_xml(self, database):
        '''
        Read plain XML file as string
        '''
        try:
            with codecs.open(database, 'rb', 'utf-8') as infile:
                self.data = infile.read()
        except FileNotFoundError:
            raise IOError(f'The file {database} does not exist!')

    def decrypt_keepass(self, database, password):
        '''
        Decrypt KeePass file
        '''
        b = []
        try:
            with open(database, 'rb') as infile:
                b = bytearray(infile.read())
        except FileNotFoundError:
            raise IOError(f'The file {database} does not exist!')

        # ---------- Header Stuff ----------
        # file magic number (4 bytes)
        # keepass version (2 bytes)
        # database minor version (2 bytes)
        # database major version (2 bytes)
        magic, version, minor_version, major_version = struct.unpack('<IIHH', b[0:12])
        if major_version != 3:
            raise IOError(f'KeePass file version should be 3 but found {major_version}. Please export your file to a compatible format or plain XML')
        # header item lookup table
        header_item_ids = {0: 'end',
                           1: 'comment',
                           2: 'cipher_id',
                           3: 'compression_flags',
                           4: 'master_seed',
                           5: 'transform_seed',
                           6: 'transform_rounds',
                           7: 'encryption_iv',
                           8: 'protected_stream_key',
                           9: 'stream_start_bytes',
                           10: 'protected_stream_id'
        }

        # read dynamic header

        # offset of first header byte
        offset = 12
        # dict containing header items
        header = {}

        # loop until end of header
        while b[offset] != 0:
            # read size of item (2 bytes)
            size = struct.unpack('<H', b[offset + 1:offset + 3])[0]
            # insert item into header dict
            header[header_item_ids[b[offset]]] = b[offset + 3:offset + 3 + size]
            # move to next header item
            # (1 byte for header item id, 2 bytes for item size, `size` bytes for data)
            offset += 1 + 2 + size

        self.stream_key = bytes(header['protected_stream_key'])
        self.stream_cipher_id = struct.unpack('<I',header['protected_stream_id'])[0]

        # move from `end` to start of payload
        size = struct.unpack('<H', b[offset + 1:offset + 3])[0]
        offset += 1 + 2 + size

        # ---------- Payload Stuff ----------
        encrypted_payload = b[offset:]

        # hash the password
        # no support for keyfiles
        password_composite = hashlib.sha256(password.encode('utf-8')).digest()

        # create composite key from password and keyfile composites
        key_composite = hashlib.sha256(password_composite).digest()

        cipher = Cipher(algorithms.AES(header['transform_seed']), modes.ECB())

        # get the number of rounds from the header and transform the key_composite
        rounds = struct.unpack('<Q', header['transform_rounds'])[0]
        transformed_key = key_composite
        for _ in range(0, rounds):
            encryptor = cipher.encryptor()
            transformed_key = encryptor.update(transformed_key) + encryptor.finalize()

        # combine the transformed key with the header master seed to find the master_key
        transformed_key = hashlib.sha256(transformed_key).digest()
        master_key = hashlib.sha256(bytes(header['master_seed']) + transformed_key).digest()

        # set up cipher for AES128-CBC decryption to find the decrypted payload
        cipher = Cipher(algorithms.AES(master_key), modes.CBC(bytes(header['encryption_iv'])))
        decryptor = cipher.decryptor()
        raw_payload_area = decryptor.update(bytes(encrypted_payload)) + decryptor.finalize()

        # verify decryption
        if header['stream_start_bytes'] != raw_payload_area[:len(header['stream_start_bytes'])]:
            raise IOError('KeePass file decryption failed, wrong password?')

        # remove stream start bytes
        offset = len(header['stream_start_bytes'])
        payload_data = b''

        # read payload block data, block by block
        while True:
            # read index of block (4 bytes)
            block_index = struct.unpack('<I', raw_payload_area[offset:offset + 4])[0]
            # read block_data sha256 hash (32 bytes)
            block_hash = raw_payload_area[offset + 4:offset + 36]
            # read block_data length (4 bytes)
            block_length = struct.unpack('<I', raw_payload_area[offset + 36:offset + 40])[0]
            # read block_data
            block_data = raw_payload_area[offset + 40:offset + 40 + block_length]

            # check if last block
            if block_hash == b'\x00' * 32 and block_length == 0:
                break

            # verify block validity
            if block_hash != hashlib.sha256(block_data).digest():
                raise IOError('Block hash verification failed')

            # append verified block_data and move to next block
            payload_data += block_data
            offset += 40 + block_length

        # check if payload_data is compressed
        if struct.unpack('<I', header['compression_flags']):
            # decompress using gzip
            xml_data = zlib.decompress(payload_data, 16 + 15)
        else:
            xml_data = payload_data
        return xml_data.decode('utf-8')
