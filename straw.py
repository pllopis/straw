"""
Straw, the simple tool to suck the config out of your Slurm beverage!
"""
import sys
import os
import socket

from dataclasses import dataclass
from pymunge import MungeContext, UID_ANY, GID_ANY
from K12 import KangarooTwelve
from struct import pack, unpack, calcsize

SLURM_PROTOCOL_VERSION = {
        '22.05': (38 << 8) | 0,
        '21.08': (37 << 8) | 0,
        '20.11': (36 << 8) | 0,
        'min': (36 << 8) | 0,
        }

HASH_K12 = 2
HASH_K12_LEN = 32
PLUGIN_AUTH_MUNGE = 0x0065
PLUGIN_AUTH_JWT = 0x0066
REQUEST_CONFIG = 0x07df
RESPONSE_CONFIG = REQUEST_CONFIG+1

protocol_version = None

@dataclass
class Header:
    protocol_version:  int = 0
    flags:             int = 0
    msg_type:          int = REQUEST_CONFIG
    body_length:       int = 4
    forward_cnt:       int = 0
    ret_cnt:           int = 0
    address_ss_family: int = 0

    def pack(self):
        if self.protocol_version >= SLURM_PROTOCOL_VERSION['22.05']:
            header = pack('!HHHIHHH',
                          self.protocol_version,
                          self.flags,
                          self.msg_type,
                          self.body_length,
                          self.forward_cnt,
                          self.ret_cnt,
                          self.address_ss_family)
        elif self.protocol_version >= SLURM_PROTOCOL_VERSION['20.11']:
             header = pack('!HHHHIHHH',
                          self.protocol_version,
                          self.flags,
                          0,
                          self.msg_type,
                          self.body_length,
                          self.forward_cnt,
                          self.ret_cnt,
                          self.address_ss_family)
        return header

    def unpack(self, header, protocol_version):
        self.protocol_version, = unpack('!H', header[:2])
        if self.protocol_version != protocol_version:
            sys.exit(f'Protocol version response from server ({self.protocol_version}) is different to the protocol version requested ({protocol_version}).')
        if protocol_version >= SLURM_PROTOCOL_VERSION['22.05']:
            _, _, self.msg_type, self.body_length, _, _, _ = unpack('!HHHIHHH', header)
        elif protocol_version >= SLURM_PROTOCOL_VERSION['20.11']:
            _, _, _, self.msg_type, self.body_length, _, _, _ = unpack('!HHHHIHHH', header)
        return self


@dataclass
class Auth:
    """
    To use with munge, use parameters by default. Munge cred will be generated automatically.
    To use with JWT, use Auth(cred=jwt_token, plugin_id=PLUGIN_AUTH_JWT).
    """
    cred: str = None
    plugin_id: int = PLUGIN_AUTH_MUNGE

    def _get_munge_cred(self, body):
        custom_string = pack('!H', REQUEST_CONFIG)
        print('custom str:')
        hexdump(custom_string)
        print('hash input:')
        hexdump(body)
        slurm_hash = pack('B32s', HASH_K12, bytes(KangarooTwelve(body, custom_string, HASH_K12_LEN)))
        print('raw hash:')
        hexdump(slurm_hash)
        with MungeContext() as ctx:
            ctx.uid_restriction = UID_ANY
            ctx.gid_restriction = GID_ANY
            cred = ctx.encode(slurm_hash)
        return cred

    def pack(self, body):
        if self.plugin_id == PLUGIN_AUTH_MUNGE:
            self.cred = self._get_munge_cred(body)
            return pack('!II', self.plugin_id, len(self.cred)+1) + self.cred + b'\x00'
        elif self.plugin_id == PLUGIN_AUTH_JWT:
            # packstr(token) + packstr(NULL)
            return pack('!II', self.plugin_id, len(self.cred)+1) + bytes(self.cred, 'utf-8') + b'\x00' + b'\x00\x00\x00\x00'


@dataclass
class Body:
    req_flags: int = 0x001

    def pack(self):
        return pack('!I', self.req_flags)

def hexdump(data):
    # Make sure the input data is a bytestring
    if not isinstance(data, bytes):
        raise TypeError("hexdump() argument must be a bytestring")

    # Initialize variables
    addr = 0
    lines = []

    # Loop over the data in blocks of 16 bytes
    for i in range(0, len(data), 16):
        # Get the current block of data
        block = data[i:i+16]
        
        # Compute the hexadecimal representation of the block
        hexstr = " ".join(f"{b:02x}" for b in block)
        
        # Compute the ASCII representation of the block, using '.' for non-printable characters
        asciistr = "".join(chr(b) if 32 <= b < 127 else "." for b in block)
        
        # Add the address, hexadecimal representation, and ASCII representation to the list of lines
        lines.append(f"{addr:08x}  {hexstr:47}  {asciistr}")
        
        # Increment the address
        addr += 16

    # Return the list of lines as a string, separated by newlines
    print("\n".join(lines))

def send_recv(server, payload):
    payload_msg = pack('!I', len(payload)) + payload
    s = socket.create_connection((server, 6817))
    s.sendall(payload_msg)
    with s, s.makefile(mode='rb') as sfile:
        recv_len = sfile.read(4)
        print('recvd ', len(recv_len), 'bytes')
        resp_len = int(unpack('!I', recv_len)[0])
        print('Read a message of length', resp_len)
        response = bytes(sfile.read(resp_len))
    return response

def parse_msg(msg):
    h = Header().unpack(msg[:16], protocol_version)
    # Check auth
    if h.msg_type != RESPONSE_CONFIG:
        sys.exit(f'Response type ({h.msg_type}) not what we expected ({RESPONSE_CONFIG}). Make sure you run as slurm user or root')
    print(f'Got a response body of length {h.body_length}:')
    return b''

def save_config(response):
    pass

def fetch_config(server):
    print('Protocol version:', protocol_version)
    h = Header(protocol_version=protocol_version)
    print(repr(h))
    header = Header(protocol_version=protocol_version).pack()
    body = Body().pack()
    try:
        token = os.environ['SLURM_JWT']
    except:
        sys.exit('SLURM_JWT undefined')
    #auth = Auth().pack(body)
    auth = Auth(cred=token, plugin_id=PLUGIN_AUTH_JWT).pack(body)
    print(f'Header ({len(header)}):')
    hexdump(header)
    print(f'Auth: ({len(auth)})')
    hexdump(auth)
    print(f'Body: ({len(body)})')
    hexdump(body)
    payload = header + auth + body
    payload_msg = pack('!I', len(payload)) + payload
    print(f'Full message: ({len(payload_msg)})')
    hexdump(payload_msg)
    response_msg = send_recv(server, payload)
    hexdump(response_msg)
    response = parse_msg(response_msg)
    print('Response raw:')
    hexdump(response)
    save_config(response)

def main():
    global protocol_version
    protocol_version = SLURM_PROTOCOL_VERSION[sys.argv[2]]
    fetch_config(sys.argv[1])

if __name__ == '__main__':
    main()
