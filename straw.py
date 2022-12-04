"""
Straw, the simple tool to suck the config out of your Slurm beverage!
"""
import sys
import os
import socket
import argparse
import re
import logging

from dataclasses import dataclass
from pymunge import MungeContext, UID_ANY, GID_ANY
from K12 import KangarooTwelve
from struct import pack, unpack, calcsize

SLURM_PROTOCOL_VERSION = {
        '22.05': (38 << 8) | 0,
        '21.08': (37 << 8) | 0,
        '20.11': (36 << 8) | 0,
        }

HASH_K12 = 2
HASH_K12_LEN = 32
PLUGIN_AUTH_MUNGE = 0x0065
PLUGIN_AUTH_JWT = 0x0066
REQUEST_CONFIG = 0x07df
RESPONSE_CONFIG = REQUEST_CONFIG+1

protocol_version = None

def list_protocol_versions():
    for ver in SLURM_PROTOCOL_VERSION.keys():
        print(ver)

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


@dataclass
class Auth:
    """
    To use with munge, use Auth(plugin_id=PLUGIN_AUTH_MUNGE). Munge cred will be generated automatically.
    To use with JWT, use Auth(cred=jwt_token, plugin_id=PLUGIN_AUTH_JWT).
    """
    plugin_id: int = None
    cred: str = None

    def _get_munge_cred(self, body):
        custom_string = pack('!H', REQUEST_CONFIG)
        logging.debug('custom str:')
        logging.debug(hexdump(custom_string))
        logging.debug('hash input:')
        logging.debug(hexdump(body))
        slurm_hash = pack('B32s', HASH_K12, bytes(KangarooTwelve(body, custom_string, HASH_K12_LEN)))
        logging.debug('raw hash:')
        logging.debug(hexdump(slurm_hash))
        with MungeContext() as ctx:
            ctx.uid_restriction = UID_ANY
            ctx.gid_restriction = GID_ANY
            cred = ctx.encode(slurm_hash)
        return cred

    def pack(self, body):
        if self.plugin_id == PLUGIN_AUTH_MUNGE:
            try:
                self.cred = self._get_munge_cred(body)
            except Exception as err:
                sys.exit(f'Failed to generate munge credential:\n{err}')
            return pack('!II', self.plugin_id, len(self.cred)+1) + self.cred + b'\x00'
        elif self.plugin_id == PLUGIN_AUTH_JWT:
            # packstr(token) + packstr(NULL)
            return pack('!II', self.plugin_id, len(self.cred)+1) + bytes(self.cred, 'utf-8') + b'\x00' + b'\x00\x00\x00\x00'


@dataclass
class Body:
    req_flags: int = 0x001

    def pack(self):
        return pack('!I', self.req_flags)


@dataclass
class SlurmMessage:
    data: bytes

    header: Header = Header()
    auth: Auth = Header()
    body: Body = Body()

    _unpack_offset: int = 0

    def unpack(self, fmt):
        """
        Akin to struct.unpack, but keep track of which bytes we've unpacked from self.data (in self._unpack_offset).
        """
        unpack_sz = calcsize(fmt)
        res = unpack(fmt, self.data[self._unpack_offset:self._unpack_offset+unpack_sz])
        self._unpack_offset += unpack_sz
        return res

    def unpackstr(self):
        """
        Unpacks a string <uint32_t><str><\0>, where len of str is given by the first uint32_t size.
        Keep track of the offset in self.data
        """
        str_len, = self.unpack('!I')
        if (str_len > 0):
            # str_len accounts for trailing '\0'
            s = self.data[self._unpack_offset:self._unpack_offset+str_len-1]
            self._unpack_offset += str_len
            return s
        else:
            return None

    def unpack_header(self):
        self.header.protocol_version, = self.unpack('!H')
        if self.header.protocol_version != protocol_version:
            sys.exit(f'Protocol version response from server ({self.header.protocol_version}) is different to the protocol version requested ({protocol_version}).')
        if protocol_version >= SLURM_PROTOCOL_VERSION['22.05']:
            _, self.header.msg_type, self.header.body_length, _, _, _ = self.unpack('!HHIHHH')
        elif protocol_version >= SLURM_PROTOCOL_VERSION['20.11']:
            _, _, self.header.msg_type, self.header.body_length, _, _, _ = self.unpack('!HHHIHHH')

    def unpack_auth(self):
        self.auth.plugin_id, = self.unpack('!I')
        if self.auth.plugin_id == PLUGIN_AUTH_MUNGE:
            self.auth.cred = self.unpackstr()
            logging.debug(f'Munge cred: {self.auth.cred}')
        if self.auth.plugin_id == PLUGIN_AUTH_JWT:
            token = self.unpackstr()
            user = self.unpackstr()


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
    return "\n".join(lines)

class StrawConnectionError(Exception):
    pass

def send_recv(server, payload):
    def parse_server(server):
        """"Parse server[:port]"""
        vals = server.split(':')
        if len(vals) > 1:
            return vals[0], vals[1]
        else:
            return vals[0], 6817

    payload_msg = pack('!I', len(payload)) + payload

    host, port = parse_server(server)
    logging.info(f'Trying {host}:{port}...')
    try:
        s = socket.create_connection((host, port))
        s.sendall(payload_msg)
    except Exception as ex:
        logging.error(ex)
        raise StrawConnectionError()

    with s, s.makefile(mode='rb') as sfile:
        recv_len = sfile.read(4)
        logging.debug(f'recvd {len(recv_len)} bytes')
        resp_len = int(unpack('!I', recv_len)[0])
        logging.debug(f'Read a message of length {resp_len}')
        response = bytes(sfile.read(resp_len))
    return response

def parse_msg(data):
    msg = SlurmMessage(data=data)
    msg.unpack_header()
    msg.unpack_auth()
    #h = Header().unpack(msg[:16], protocol_version)
    #a = Auth(data=msg[16:]).parse()
    if msg.header.msg_type != RESPONSE_CONFIG:
        sys.exit(f'Response type ({msg.header.msg_type}) not what we expected ({RESPONSE_CONFIG}). Make sure you run as slurm user or root')
    logging.debug(f'Got a response body of length {msg.header.body_length}:')
    return b''

def save_config(response):
    pass

def fetch_config(servers, auth):
    logging.debug(f'Using protocol version: {protocol_version}')
    h = Header(protocol_version=protocol_version)
    logging.debug(repr(h))
    header = Header(protocol_version=protocol_version).pack()
    body = Body().pack()
    logging.info(f'Using authentication method: {auth}')
    if auth == 'jwt':
        try:
            token = os.environ['SLURM_JWT']
        except:
            sys.exit('Auth method jwt requested but SLURM_JWT undefined')
        auth = Auth(cred=token, plugin_id=PLUGIN_AUTH_JWT).pack(body)
    else:
        auth = Auth(plugin_id=PLUGIN_AUTH_MUNGE).pack(body)
    logging.debug(f'Header ({len(header)}):')
    logging.debug(hexdump(header))
    logging.debug(f'Auth: ({len(auth)})')
    logging.debug(hexdump(auth))
    logging.debug(f'Body: ({len(body)})')
    logging.debug(hexdump(body))
    payload = header + auth + body
    payload_msg = pack('!I', len(payload)) + payload
    logging.debug(f'Full message: ({len(payload_msg)})')
    logging.debug(hexdump(payload_msg))
    response_msg = None
    for server in servers:
        try:
            response_msg = send_recv(server, payload)
        except StrawConnectionError as err:
            logging.info(err)
            logging.error('Connection error. Retrying with next server.')
        else:
            # Only bother retrying further servers for connection errors
            break

    if not response_msg:
        sys.exit('Unable to connect and no more servers to try')

    logging.debug(hexdump(response_msg))
    response = parse_msg(response_msg)
    logging.debug('Response raw:')
    logging.debug(hexdump(response))
    save_config(response)

def parse_args():
    def major_version_match(arg):
        if not re.fullmatch(r'[0-9]{2,}\.[0-9]+', arg):
            raise ValueError('Slurm major version must be specified (e.g. 22.05)')
        return arg

    # First parser just for listing protocol versions
    list_parser = argparse.ArgumentParser(add_help=False)
    list_parser.add_argument('-l', '--list', action='store_true')
    list_versions = False
    try:
        args, _ = list_parser.parse_known_args()
        if args.list:
            list_versions = True
    except:
        pass

    if list_versions:
        list_protocol_versions()
        sys.exit(0)

    # Main parser
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('server', type=str, nargs='+',
                        help='slurmctld server in server[:port] notation')
    parser.add_argument('version', type=major_version_match,
                        help='Slurm major version that corresponds to that of the slurmctld server (e.g. 22.05)')
    parser.add_argument('--auth', choices=['munge', 'jwt'], default='jwt',
                        help='Authentication method')
    parser.add_argument('-v', '--verbose', action='count',
                        help='Increase output verbosity. Rrepetitions allowed.')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('-l', '--list', action='store_true',
                             help='List available protocol versions')
    return parser.parse_args()

def main():
    args = parse_args()

    if not args.verbose:
        # default logging level
        loglevel = logging.ERROR
    elif args.verbose >= 2:
        loglevel = logging.DEBUG
    elif args.verbose >= 1:
        loglevel = logging.INFO
    logging.getLogger().setLevel(loglevel)
    logging.basicConfig(format='%(message)s', datefmt='%m/%d/%Y %H:%M:%S %Z')

    logging.debug(repr(args))

    global protocol_version
    protocol_version = SLURM_PROTOCOL_VERSION[args.version]
    fetch_config(args.server, args.auth)

if __name__ == '__main__':
    main()
