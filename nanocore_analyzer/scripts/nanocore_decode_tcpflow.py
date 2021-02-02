#!/usr/bin/env python3
import argparse
import os
import re
import itertools
import hashlib
import xml.etree.ElementTree as ET
import json
import pefile
from NanoCoreAnalyzer import NanoCore, NanoCoreType, NanoCoreJSONEncoder


def decode_tcpflow(file, key):
    with open(file, 'rb') as f:
        tcpflow = f.read()

    nanocore = NanoCore(des_key_iv=key)
    filename = os.path.basename(file)

    results = []
    offset = 0
    while len(tcpflow) > offset:
        result = {'filename': filename}
        data_len = int.from_bytes(tcpflow[offset:offset + 4], 'little') + 4
        decoded_data = nanocore.decode(tcpflow[offset:offset + data_len])
        if decoded_data is None:
            decoded_data = {'Error': 'decode error'}

        result.update(decoded_data)
        results.append(result)
        offset += data_len
    return results


def get_tcpflow_files(dir):
    files = []
    xmlpath = os.path.join(dir, 'report.xml')
    tree = ET.parse(xmlpath)
    root = tree.getroot()
    for configuration in root.iter('configuration'):
        for fileobject in configuration.iter('fileobject'):
            for filename in fileobject.iter('filename'):
                filename = os.path.basename(filename.text)
                path = os.path.join(dir, filename)
                files.append(path)
    return files


def filter_files(files, filter_ip, filter_port):
    if filter_ip == filter_port == None:
        return files

    ip = port = '.*'
    if filter_ip:
        ip = '.'.join([x.zfill(3) for x in filter_ip.split('.')])

    if filter_port:
        port = str(filter_port).zfill(5)

    filename_patterns = [
        re.compile(f'{ip}.*.{port}.*'),
        re.compile(f'.*-{ip}.{port}.*'),
        re.compile(f'{ip}.{port}-.*'),
        re.compile(f'.*.{port}-{ip}.*'),
    ]

    target_files = []
    for file, pattern in itertools.product(files, filename_patterns):
        filename = os.path.basename(file)
        if file not in target_files and re.match(pattern, filename):
            target_files.append(file)
    return target_files


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


def dump_contents(output_dir, tcpflow_name, decoded_data):
    params = decoded_data['params']
    for param in params:
        if param['type'] == NanoCoreType.BYTEARRAY:
            category, value = check_contents(param['value'])
            md5 = hashlib.md5(value).hexdigest()
            filename = f'{md5}.{category}'
            output = os.path.join(output_dir, tcpflow_name, category, filename)

            os.makedirs(os.path.dirname(output), exist_ok=True)
            with open(output, 'wb') as f:
                f.write(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str,
                        help='tcpflow file')
    parser.add_argument('-d', '--dir', type=str,
                        help='directory with tcpflow files')
    parser.add_argument('-D', '--dump-dir', type=str,
                        help='Dump the binary data (optional)')
    parser.add_argument('-k', '--key', type=str, default='722018788c294897',
                        help='NanoCore DES key (optional)')
    parser.add_argument('--oneline', action='store_true',
                        help='Show the decoded logs line by line (optional)')
    parser.add_argument('--filter-ip', type=str,
                        help='Decode only data containing a specific IP address (optional)')
    parser.add_argument('--filter-port', type=str,
                        help='Decode only data containing a specific port (optional)')
    args = parser.parse_args()

    if (args.file and not os.path.isfile(args.file)) or (args.dir and not os.path.isdir(args.dir)):
        print('Error: No such file or directory.')
        return

    if args.file:
        files = [args.file]
    elif args.dir:
        files = get_tcpflow_files(args.dir)
    else:
        parser.print_usage()
        return

    key = bytes.fromhex(args.key)

    files = filter_files(files, args.filter_ip, args.filter_port)
    results = []
    for file in files:
        results += decode_tcpflow(file, key)

    for result in results:
        if args.dump_dir and result is not None:
            dump_contents(args.dump_dir, result['filename'], result)

        if args.oneline:
            print(json.dumps(result, cls=NanoCoreJSONEncoder))

    if not args.oneline:
        print(json.dumps(results, indent=4, cls=NanoCoreJSONEncoder))


if __name__ == '__main__':
    main()
