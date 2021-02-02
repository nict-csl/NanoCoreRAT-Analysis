#!/usr/bin/env python3
import argparse
import os
import re
import hashlib
import pprint
import json
import pefile
from NanoCoreAnalyzer import NanoCore, NanoCoreType, NanoCoreJSONEncoder


def decode_data(key, data):
    nanocore = NanoCore(des_key_iv=key)
    data_len = len(data).to_bytes(4, 'little')
    result = nanocore.decode(data_len + data)
    return result


def check_contents(data):
    jpg_pattern = b'\xff\xd8.*JFIF.*'
    if re.match(jpg_pattern, data):
        return 'jpg', data
    elif re.match(jpg_pattern, data[8:]):  # Surveillance EX plugin
        return 'jpg', data[8:]

    pe_pattern = b'MZ.*'
    if re.match(pe_pattern, data):
        pe = pefile.PE(data=data)
        if pe.FILE_HEADER.Characteristics & 0x2000:
            return 'dll', data
        return 'exe', data

    return 'bin', data  # TODO: uncategorized


def dump_contents(dump_dir, output_dir, decoded_data):
    params = decoded_data['params']
    for param in params:
        if param['type'] == NanoCoreType.BYTEARRAY:
            category, content = check_contents(param['value'])
            md5 = hashlib.md5(content).hexdigest()
            filename = f'{md5}.{category}'
            output = os.path.join(dump_dir, output_dir, category, filename)

            os.makedirs(os.path.dirname(output), exist_ok=True)
            with open(output, 'wb') as f:
                f.write(content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=True,
                        help='NanoCore configuration file (catalog.dat, settings.bin, strage.dat)')
    parser.add_argument('-k', '--key', type=str, default='722018788c294897',
                        help='NanoCore DES key (optional)')
    parser.add_argument('-D', '--dump_dir', type=str,
                        help='Dump the bytearray data (optional)')
    args = parser.parse_args()

    if args.file and not os.path.isfile(args.file):
        print('Error: File is not found.')
        return

    with open(args.file, 'rb') as f:
        data = f.read()

    key = bytes.fromhex(args.key)

    result = decode_data(key, data)
    filename = os.path.basename(args.file)

    if args.dump_dir and result is not None:
        dump_contents(args.dump_dir, filename, result)

    print(json.dumps(result, indent=4, cls=NanoCoreJSONEncoder))


if __name__ == '__main__':
    main()
