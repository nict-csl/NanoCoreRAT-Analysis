#!/usr/bin/env python3
import argparse
import os
import uuid
import re
import io
import hashlib
import pefile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def pbkdf2(password, salt, iterations):
    dk = hashlib.pbkdf2_hmac('sha1', password, salt, iterations, dklen=32)
    iv = dk[0:16]
    key = dk[16:32]
    return iv, key


def decrypt_rijndael(key, iv, enc_data):
    rijn = AES.new(key, AES.MODE_CBC, IV=iv)
    return unpad(rijn.decrypt(enc_data), AES.block_size)


def nanocore_guid(pedata):
    pedata = pedata.decode('utf-8', 'ignore')
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    guid = re.search(uuid_pattern, pedata).group()
    return uuid.UUID(guid).bytes_le


def encrypted_key(pedata):
    pe = pefile.PE(data=pedata)

    for section in pe.sections:
        if b'.rsrc' in section.Name:
            break

    with io.BytesIO(pedata) as f:
        offset = 0x58  # resource section header
        f.seek(section.PointerToRawData + offset)
        data_len = int.from_bytes(f.read(4), 'little')
        enc_key = f.read(data_len)

    return enc_key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=True,
                        help='NanoCore executable file')
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print('Error: File is not found.')
        return

    with open(args.file, 'rb') as f:
        pedata = f.read()

    guid = nanocore_guid(pedata)
    enc_key = encrypted_key(pedata)

    rijndael_iv, rijndael_key = pbkdf2(guid, guid, iterations=8)
    des_key = decrypt_rijndael(rijndael_key, rijndael_iv, enc_key)

    print(f'PBKDF2 password and salt: {guid.hex()}')
    print(f'Encrypted key: {enc_key.hex()}')
    print(f'Rijndael key: {rijndael_key.hex()}')
    print(f'Rijndael iv: {rijndael_iv.hex()}')
    print(f'NanoCore DES key and iv: {des_key.hex()}')


if __name__ == '__main__':
    main()
