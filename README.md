# NanoCoreRAT-Analysis

This repository publishes analysis tools for NanoCore RAT.

## nanocore_analyzer

These are the scripts that were created during the NanoCore analysis.

- ``nanocore_extract_keys.py``:  
  This is a script that extracts the key that NanoCore uses to encrypt the data transmitted.

- ``nanocore_extract_settings.py``:  
  This is a script that extracts configuration data of NanoCore RAT.
  
- ``nanocore_decode_tcpflow.py``:  
  This is a script that decodes data transmitted as part of TCP connections of NanoCore RAT.

- ``nanocore_decode_file.py``:  
  This is a script that decodes the configuration file generated after a NanoCore infection.

Please see [here](./nanocore_analyzer/README.md) for more details.

## nmap_scripts

``nanocore.nse``: This is a custom NSE script for detecting NanoCore C2 servers. 

Please see [here](./nmap_scripts/README.md) for more details.