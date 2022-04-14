import zlib
import uuid
import datetime
import io
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from NanoCoreAnalyzer.types import NanoCoreType


class NanoCore:
    def __init__(self, des_key_iv=b'\x72\x20\x18\x78\x8c\x29\x48\x97'):
        self.des_key = des_key_iv
        self.des_iv = des_key_iv

    def __des_encrypt(self, data):
        cipher = DES.new(key=self.des_key, iv=self.des_iv, mode=DES.MODE_CBC)
        return cipher.encrypt(pad(data, DES.block_size))

    def __des_decrypt(self, data):
        cipher = DES.new(key=self.des_key, iv=self.des_iv, mode=DES.MODE_CBC)
        dec_data = cipher.decrypt(data)
        if len(dec_data) == 0:
            return b''
        return unpad(dec_data, DES.block_size)

    def __bool_to_byte(self, bool):
        return b'\x01' if bool else b'\x00'

    def __bool_from_byte(self, byte):
        return byte == b'\x01'

    def __serialize_datetime(self, dt):
        unixtime = dt.timestamp()
        base_ticks = 0x489f7ff5f7b58000  # 1970/01/01 00:00:00
        return int(unixtime * 10000000) + base_ticks

    def __deserialize_datetime(self, ticks):
        base_ticks = 0x489f7ff5f7b58000  # 1970/01/01 00:00:00
        unixtime = (ticks - base_ticks) / 10000000
        try:
            return datetime.datetime.fromtimestamp(unixtime)
        except ValueError:
            return ticks

    def encode(self, guid, compressed_mode, flag1, flag2, params):
        payload_body = b''
        payload_body += flag1.to_bytes(1, 'little')
        payload_body += flag2.to_bytes(1, 'little')

        empty_uuid = uuid.UUID(bytes=b'\x00' * 16)
        if empty_uuid == guid:
            payload_body += self.__bool_to_byte(False)
        else:
            payload_body += self.__bool_to_byte(True)
            payload_body += guid.bytes_le

        for data in params:
            nanocore_type = data['type']
            payload_body += nanocore_type.value.to_bytes(1, 'little')

            value = data['value']
            if nanocore_type == NanoCoreType.BOOL:
                payload_body += self.__bool_to_byte(value)
            elif nanocore_type == NanoCoreType.BYTE:
                payload_body += value
            elif nanocore_type == NanoCoreType.BYTEARRAY:
                payload_body += len(value).to_bytes(4, 'little')
                payload_body += value
            elif nanocore_type == NanoCoreType.INT or nanocore_type == NanoCoreType.UINT:
                payload_body += value.to_bytes(4, 'little')
            elif nanocore_type == NanoCoreType.LONG or nanocore_type == NanoCoreType.ULONG:
                payload_body += value.to_bytes(8, 'little')
            elif nanocore_type == NanoCoreType.SHORT or nanocore_type == NanoCoreType.USHORT:
                payload_body += value.to_bytes(2, 'little')
            elif nanocore_type == NanoCoreType.STRING or nanocore_type == NanoCoreType.VERSION:
                payload_body += len(value).to_bytes(1, 'little')
                payload_body += value.encode()
            elif nanocore_type == NanoCoreType.DATETIME:
                ticks = self.__serialize_datetime(value)
                payload_body += ticks.to_bytes(8, 'little')
            elif nanocore_type == NanoCoreType.GUID:
                payload_body += value.bytes_le
            else:  # TODO: Other Types
                pass

        if compressed_mode and len(payload_body) >= 860:
            deflate_data = zlib.compress(payload_body)[2:-4]
            payload_body_len = len(payload_body).to_bytes(4, 'little')
            payload_body = b'\x01' + payload_body_len + deflate_data
        else:
            payload_body = b'\x00' + payload_body

        encrypt_body = self.__des_encrypt(payload_body)
        return len(encrypt_body).to_bytes(4, 'little') + encrypt_body


    def decode(self, payload):
        payload_len = int.from_bytes(payload[:4], 'little')
        try:
            payload_body = self.__des_decrypt(payload[4:payload_len + 4])
        except ValueError:
            return None

        f = io.BytesIO(payload_body)
        compressed_mode = self.__bool_from_byte(f.read(1))
        if compressed_mode:
            # data length after raw inflate.
            data_len = int.from_bytes(f.read(4), 'little')
            deflate_data = f.read()
            inflate_data = zlib.decompress(deflate_data, wbits=-15)
            payload_len = len(inflate_data)
            f.close()
            f = io.BytesIO(inflate_data)

        flag1 = int.from_bytes(f.read(1), 'little')
        flag2 = int.from_bytes(f.read(1), 'little')
        guid = uuid.UUID(bytes=b'\x00' * 16)
        params = []

        check_guid = self.__bool_from_byte(f.read(1))
        if check_guid:
            guid_bytes = f.read(16)
            guid = uuid.UUID(bytes_le=guid_bytes)

        position = f.tell()
        while payload_len > position:
            type_num = int.from_bytes(f.read(1), 'little')
            try:
                nanocore_type = NanoCoreType(type_num)
                if nanocore_type == NanoCoreType.BOOL:
                    value = self.__bool_from_byte(f.read(1))
                elif nanocore_type == NanoCoreType.BYTE:
                    value = f.read(1)
                elif nanocore_type == NanoCoreType.BYTEARRAY:
                    data_len = int.from_bytes(f.read(4), 'little')
                    value = f.read(data_len)
                elif nanocore_type == NanoCoreType.INT or nanocore_type == NanoCoreType.UINT:
                    value = int.from_bytes(f.read(4), 'little')
                elif nanocore_type == NanoCoreType.LONG or nanocore_type == NanoCoreType.ULONG:
                    value = int.from_bytes(f.read(8), 'little')
                elif nanocore_type == NanoCoreType.SHORT or nanocore_type == NanoCoreType.USHORT:
                    value = int.from_bytes(f.read(2), 'little')
                elif nanocore_type == NanoCoreType.FLOAT:
                    value = float(int.from_bytes(f.read(4), 'little'))
                elif nanocore_type == NanoCoreType.STRING or nanocore_type == NanoCoreType.VERSION:
                    data_len = int.from_bytes(f.read(1), 'little')
                    value = f.read(data_len).decode()
                elif nanocore_type == NanoCoreType.DATETIME:
                    ticks = int.from_bytes(f.read(8), 'little')
                    value = self.__deserialize_datetime(ticks)
                elif nanocore_type == NanoCoreType.GUID:
                    value = uuid.UUID(bytes_le=f.read(16))
                else:  # TODO: Other Types
                    nanocore_type = NanoCoreType.UNKNOWN
                    value = f.read()

                if position == f.tell():
                    break
                position = f.tell()
                params.append({'type': nanocore_type, 'value': value})

            except ValueError:
                return None
        f.close()
        return {'uuid': guid, 'compressed_mode': compressed_mode, 'flags': [flag1, flag2], 'params': params}
