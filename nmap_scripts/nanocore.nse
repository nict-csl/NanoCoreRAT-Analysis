local shortport = require "shortport"
local stdnse = require "stdnse"
local openssl_cipher = require "openssl.cipher"

math.randomseed(os.time())
local random = math.random

description = [[
Detects the running of NanoCore C2 server.
required: luaossl
]]

---
-- @output
-- 54984/tcp open  unknown
-- | nanocore:
-- |   send_payload:
-- |     guid_bytes_le: \xb3\x88\x91\x29\x2d\x92\x2a\xd4\xee\xd5\x47\xf1\x44\x51\x2e\xed
-- |     identity: 7AFklzEZjC\Ey0mU
-- |     group: Default
-- |     version: 1.2.2.0
-- |   result:
-- |     all: \x20\x00\x00\x00\xbd\xa2\xc2\x87\x53\x02\xe0\xfd\x94\x94\x83\x6d\x6e\xf8\x68\x70\xfa\x42\x95\xc6\x02\x3a\x67\x65\x7f\xf2\x26\x4b\x19\x55\x25\xda\x08\x00\x00\x00\xc1\xc3\xd0\x32\x43\x59\xa1\x78
-- |     length: 32
-- |_    body: \x00\x01\x00\x00\x02\x10\x00\x00\x00\xbd\xc8\x94\x5f\x1d\x79\x9c\x84\x54\x08\x52\x2e\x37\x2d\x1d\xbd


author = "Takashi Matsumoto <tmatsumoto@nict.go.jp>"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"malware"}


-- Check All Ports
portrule = shortport.port_range("T:1-65535")

function pkcs7_padding(payload)
    pad_num = 8 - (string.len(payload) % 8)
    for i = 0, pad_num - 1, 1 do
        payload = payload .. "\x07"
    end
    return payload
end

function pkcs7_unpadding(payload)
    pad = string.match(payload, "\x07*$")
    pad_len = string.len(pad)
    return string.sub(payload, 1, (pad_len + 1) * -1)
end

function des_encrypt(key, iv, plaintext)
    cipher = openssl_cipher.new("DES-CBC")
    cipher:encrypt(key, iv, false)
    return cipher:final(pkcs7_padding(plaintext))
end

function des_decrypt(key, iv, ciphertext)
    cipher = openssl_cipher.new("DES-CBC")
    cipher:decrypt(key, iv, false)
    return pkcs7_unpadding(cipher:final(ciphertext))
end

function uuid4()
    -- UUID4: RRRRRRRR-RRRR-4RRR-rRRR-RRRRRRRRRRRR
    local uuid = ""
    for i = 0, 15, 1 do
        num = random(0, 0xff)
        if (i == 7) then
            num = num & 0x0f | 0x40 
        elseif (i == 8) then
            num = num & 0x3f | 0x80 
        end
        uuid = uuid .. string.char(num)
    end
    return uuid
end

function random_string(n)
    local str_table = {}
    local base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    base:gsub(".", function(c) table.insert(str_table, c) end)

    table_len = string.len(base)

    local str = ""
    for i = 0, n - 1, 1 do
        str = str .. str_table[random(1, table_len)]
    end
    return str
end

function fromInt32(num)
    local bytes = ""
    for i = 0, 3, 1 do
        bytes = bytes .. string.char(num & 0xff)
        num = num >> 8
    end
    return bytes
end

function toInt32(bytes)
    local int32 = 0
    for i = 1, 4, 1 do
        c = string.sub(bytes, i, i)
        int32 = int32 + (string.byte(c) << (8 * (i - 1)))
    end
    return int32
end

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('\\x%02x', string.byte(c))
    end))
end

function nanocore_payload(guid, identity, group, version)
    local des_key = "\x72\x20\x18\x78\x8c\x29\x48\x97"
    local des_iv = des_key

    local payload = "\x00\x00\x00\x00"
    .. "\x12" .. guid
    .. "\x0c" .. string.char(string.len(identity)) .. identity
    .. "\x0c" .. string.char(string.len(group)) .. group
    .. "\x0c" .. string.char(string.len(version)) .. version

    local enc_payload = des_encrypt(des_key, des_iv, payload)
    local payload_len = fromInt32(string.len(enc_payload))
    return payload_len .. enc_payload
end

function decrypt_result(result)
    if (string.len(result) < 4) then
        return nil, 0
    end

    local len = toInt32(string.sub(result, 1, 4))
    local body = string.sub(result, 5, len + 4)

    if (string.len(body) == len) then
        local des_key = "\x72\x20\x18\x78\x8c\x29\x48\x97"
        local des_iv = des_key
        return des_decrypt(des_key, des_iv, body), len
    end
    return nil, 0
end

action = function(host, port)
    local socket = nmap.new_socket()
    local result
    local status = true

    local err_catch = function()
        socket:close()
    end

    local try = nmap.new_try(err_catch)

    socket:set_timeout(3000)
    try(socket:connect(host.ip, port.number, port.protocol))

    local guid = uuid4()
    local host = random_string(10)
    local user = random_string(5)
    local identity = host .. "\\" .. user
    local group = "Default"
    local version = "1.2.2.0"
    local payload = nanocore_payload(guid, identity, group, version)
    try(socket:send(payload))

    status, result = socket:receive_lines(1)

    local dec_result
    local len
    stdnse.debug = string.tohex(result)
    dec_result, len = decrypt_result(result)

    if (status and dec_result ~= nil) then
        local output = stdnse.output_table()

        output.send_payload = stdnse.output_table()
        output.send_payload.guid_bytes_le = string.tohex(guid)
        output.send_payload.identity = identity
        output.send_payload.group = group
        output.send_payload.version = version

        output.result = stdnse.output_table()
        output.result.all = string.tohex(result)
        output.result.length = len
        output.result.body = string.tohex(dec_result)
        return output
    end
end