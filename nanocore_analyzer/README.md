# nanocore_analyzer

## Installation

In the nanocore_analyzer directory run:

```bash
$ pip install .
```

We recommend installing nanocore_analyzer in a virtualenv, which looks as follows:

```bash
$ python3 -m virtualenv -p python3 venv
$ . venv/bin/activate
(venv)$ pip install .
```

## Usage

### nanocore_extract_keys.py

This is a script that extracts the key that NanoCore uses to encrypt the data transmitted.

```bash
$ nanocore_extract_keys.py -f NanoCoreClient.exe
PBKDF2 password and salt: fafe3a92949c4e429d9ebeb16905ce23
Encrypted key: f3cd8ce9ea0ca9a6526b15c994496c04
Rijndael key: 05a84a08393b752e57a5dd49631a45b7
Rijndael iv: 8673fecf3674a70f6e46756e4bda3965
NanoCore DES key and iv: 722018788c294897
```

### nanocore_extract_settings.py

This is a script that extracts configuration data of NanoCore RAT.

```bash
$ nanocore_extract_settings.py -f NanoCoreClient.exe
SurveillanceEx Plugin, Binary data (100352 bytes)
BuildTime, 2020-11-10 17:11:27.859525
Version, 1.2.2.0
Mutex, c8ee054a-b2fb-4bf2-8a5d-e3f1101de1da
DefaultGroup, Default
PrimaryConnectionHost, 192.168.0.200       
BackupConnectionHost, 127.0.0.1
ConnectionPort, 54984
RunOnStartup, False
RequestElevation, False
BypassUserAccountControl, False
ClearZoneIdentifier, True
ClearAccessControl, False
SetCriticalProcess, False
PreventSystemSleep, True
ActivateAwayMode, False
EnableDebugMode, False
RunDelay, 0
ConnectDelay, 4000
RestartDelay, 5000
TimeoutInterval, 5000
KeepAliveTimeout, 30000
MutexTimeout, 5000
LanTimeout, 2500
WanTimeout, 8000
BufferSize, 65535
MaxPacketSize, 10485760
GCThreshold, 10485760
UseCustomDnsServer, True
PrimaryDnsServer, 8.8.8.8
BackupDnsServer, 8.8.4.4
```

### nanocore_decode_tcpflow.py

This is a script that decodes data transmitted as part of TCP connections of NanoCore RAT.

Before using this script, you need to run tcpflow.

```bash
$ tcpflow -r NanoCore.pcap -o flows/
```

Decode the NanoCore data contained in the tcpflow file.

```bash
$ nanocore_decode_tcpflow.py -f flows/192.168.000.100.01031-192.168.000.200.54984 | less
[
    {
        "filename": "192.168.000.100.01031-192.168.000.200.54984",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "compressed_mode": false,
        "flags": [
            0,
            0
        ],
        "params": [
            {
                "type": "GUID",
                "value": "7abd86e7-cf8a-44dd-8829-2045c27d59e2"
            },
            {
                "type": "STRING",
                "value": "TEST-PC\\user"
            },
            {
                "type": "STRING",
                "value": "Default"
            },
            {
                "type": "STRING",
                "value": "1.2.2.0"
            }
        ]
    },
    <snip>
```

If -D/--dump_dir option is specified, binary data (such as image files and DLLs) contained in the decoded data are dumped.

```bash
$ nanocore_decode_tcpflow.py -f flows/192.168.000.100.01033-192.168.000.200.54984 -D dump/ | less
$ ls -R dump/
dump/:
192.168.000.100.01033-192.168.000.200.54984

dump/192.168.000.100.01033-192.168.000.200.54984:
jpg

dump/192.168.000.100.01033-192.168.000.200.54984/jpg:
2636f15fc776b00cc3014107ebb07081.jpg
ca89182e6665c19795a6aa240413c958.jpg
d6f57a3c06079e46529cfcbf9c7c1ff5.jpg
```

### nanocore_decode_file.py

This is a script that decodes the configuration file generated after a NanoCore infection.

When infected with the NanoCore RAT, the following files are generated.

- ``C:\Users\<UserName>\AppData\Roaming\<GUID>\catalog.dat``
- ``C:\Users\<UserName>\AppData\Roaming\<GUID>\settings.bin``
- ``C:\Users\<UserName>\AppData\Roaming\<GUID>\strage.dat``

This script decodes these files.

- catalog.dat

    ```bash
    $ nanocore_decode_file.py -f catalog.dat 
    {
        "uuid": "00000000-0000-0000-0000-000000000000",
        "compressed_mode": false,
        "flags": [
            0,
            0
        ],
        "params": [
            {
                "type": "GUID",
                "value": "d4466edc-d84f-f2d0-8dce-eb4345fd8569"
            },
            {
                "type": "GUID",
                "value": "8e554d9c-a2bd-1b48-e703-c5704de5a7d8"
            },
            {
                "type": "GUID",
                "value": "d0aba983-d188-e5d9-03fa-ea3df4ea994d"
            },
            {
                "type": "GUID",
                "value": "94caa1be-766d-6a44-a7be-3d14688fc136"
            },
            {
                "type": "GUID",
                "value": "46dba22e-b7d5-7204-7d2c-b8de9e767095"
            },
            {
                "type": "GUID",
                "value": "bb1cf52d-d82c-72d9-c259-5c1cb3155589"
            },
            {
                "type": "GUID",
                "value": "a42871f1-7588-a24a-6543-93866f7d582d"
            },
            {
                "type": "GUID",
                "value": "00592cb9-e09a-3d31-3c36-119998044e3d"
            },
            {
                "type": "GUID",
                "value": "5ff5348d-4be5-ff14-57a4-ee5f523ee6b3"
            },
            {
                "type": "GUID",
                "value": "2441ccc7-e521-6225-4a86-bbbd0ea9b98f"
            },
            {
                "type": "GUID",
                "value": "c0ef879c-365c-dde4-7b37-20a8972cbbfb"
            },
            {
                "type": "GUID",
                "value": "83d05a36-970f-6690-ed4b-27b89b03c077"
            }
        ]
    }
    ```

- settings.bin

    ```bash
    $ nanocore_decode_file.py -f settings.bin 
    {
        "uuid": "00000000-0000-0000-0000-000000000000",
        "compressed_mode": false,
        "flags": [
            0,
            0
        ],
        "params": [
            {
                "type": "STRING",
                "value": "KeyboardLogging"
            },
            {
                "type": "BOOL",
                "value": true
            },
            {
                "type": "STRING",
                "value": "DNSLogging"
            },
            {
                "type": "BOOL",
                "value": false
            }
        ]
    }
    ```


- strage.dat

    ```bash
    $ nanocore_decode_file.py -f strage.dat -D dump/ > /dev/null
    $ ls dump/strage.dat/dll
    189d32136482ced3d7f9743aa312ad50.dll  39c8185da53fbe588136525f1654d8f3.dll  7283fa19fa6af23c6469976b67c00156.dll  b7fc2e10abaeb174f02fe10f533ec741.dll  de880274dcd7ec3ebf4e61e843662be3.dll
    2c72cad8dff49c583d870fc6282980dd.dll  5f811de9c87dff3815974880168f9f54.dll  78f7c326ea2dbd0eb08de790d6e4bd19.dll  bdc8945f1d799c845408522e372d1dbd.dll
    36cf6fc7f7d048755ddeace5a0a102ed.dll  603f7ddc535d2d99f9aae77274e4cffb.dll  9c8242440c47a4f1ce2e47df3c3ddd28.dll  d9ac251618ec2f76a8fa0f6fb526fb31.dll
    ```