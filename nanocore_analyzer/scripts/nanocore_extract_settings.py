#!/usr/bin/env python3
import argparse
import os
import io
import pprint
import pefile
import json
from NanoCoreAnalyzer import NanoCore, NanoCoreType, NanoCoreJSONEncoder


def get_nanocore_settings(file, key):
    with open(file, 'rb') as f:
        pedata = f.read()

    pe = pefile.PE(data=pedata)
    for section in pe.sections:
        if b'.rsrc' in section.Name:
            break

    with io.BytesIO(pedata) as f:
        offset = 0x58  # resource section header
        f.seek(section.PointerToRawData + offset)
        data_len = int.from_bytes(f.read(4), 'little')
        guid = f.read(data_len)
        config = f.read()

    nanocore = NanoCore(des_key_iv=key)
    return nanocore.decode(config)


def show_compact_log(result):
    params = iter(result['params'])
    for param in params:
        # show settings
        if NanoCoreType.STRING == param['type']:
            print(param['value'], end=', ')
            param = next(params)
            if NanoCoreType.BYTEARRAY == param['type']:
                print('Binary data ({} bytes)'.format(len(param['value'])))
            else:
                print(param['value'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=True,
                        help='NanoCore executable file')
    parser.add_argument('-k', '--key', type=str, default='722018788c294897',
                        help='NanoCore DES key (optional)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output (optional)')
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print('Error: File is not found.')
        return

    key = bytes.fromhex(args.key)
    settings = get_nanocore_settings(args.file, key)
    if args.verbose:
        print(json.dumps(settings, indent=4, cls=NanoCoreJSONEncoder))
    else:
        show_compact_log(settings)


if __name__ == '__main__':
    main()
