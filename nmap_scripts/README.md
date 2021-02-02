# nmap_scripts - nanocore.nse

``nanocore.nse`` is a custom NSE script for detecting NanoCore C2 servers.  
Tested on Ubuntu 20.04LTS

## Requirements

- Nmap 3.80
- Lua 5.3.3
- LuaRocks 3.5.0
- luaossl-20200709-0

## Installation

1. Install Nmap and Lua
    ```bash
    $ sudo apt install nmap lua5.3
    ```

1. Install LuaRocks
    ```bash
    $ sudo apt install liblua5.3-dev unzip
    $ wget https://luarocks.org/releases/luarocks-3.5.0.tar.gz
    $ tar zxpf luarocks-3.5.0.tar.gz
    $ cd luarocks-3.5.0
    $ ./configure
    $ make
    $ sudo make install
    ```

1. Install luaossl
    ```bash
    $ sudo apt install libssl-dev
    $ sudo luarocks install luaossl
    ```

## Usage

```bash
$ nmap <ip_address> -p- --script nmap/nanocore.nse

<snip>

PORT     STATE SERVICE
54984/tcp open  unknown
| nanocore:
|   send_payload:
|     guid_bytes_le: \xb3\x88\x91\x29\x2d\x92\x2a\xd4\xee\xd5\x47\xf1\x44\x51\x2e\xed
|     identity: 7AFklzEZjC\Ey0mU
|     group: Default
|     version: 1.2.2.0
|   result:
|     all: \x20\x00\x00\x00\xbd\xa2\xc2\x87\x53\x02\xe0\xfd\x94\x94\x83\x6d\x6e\xf8\x68\x70\xfa\x42\x95\xc6\x02\x3a\x67\x65\x7f\xf2\x26\x4b\x19\x55\x25\xda\x08\x00\x00\x00\xc1\xc3\xd0\x32\x43\x59\xa1\x78
|     length: 32
|_    body: \x00\x01\x00\x00\x02\x10\x00\x00\x00\xbd\xc8\x94\x5f\x1d\x79\x9c\x84\x54\x08\x52\x2e\x37\x2d\x1d\xbd
```