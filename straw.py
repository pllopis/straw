"""
Straw, the simple tool to suck the config out of your Slurm beverage!
"""
import sys
import os
import socket
import argparse
import re
import logging

from dataclasses import dataclass, field
from vendor.K12 import KangarooTwelve
from struct import pack, unpack, calcsize
try:
    from pymunge import MungeContext, UID_ANY, GID_ANY
except ImportError:
    has_munge = False
else:
    has_munge = True

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
RESPONSE_SLURM_RC = 8001
NO_VAL = 0xfffffffe

protocol_version = None

def list_protocol_versions():
    for ver in SLURM_PROTOCOL_VERSION.keys():
        print(ver)

@dataclass
class Header:
    # default values for packing the request_config msg
    protocol_version:  int = 0
    flags:             int = 0
    msg_type:          int = REQUEST_CONFIG
    body_length:       int = 4
    forward_cnt:       int = 0
    ret_cnt:           int = 0
    address_ss_family: int = 0


@dataclass
class Auth:
    """
    To use with munge, use Auth(plugin_id=PLUGIN_AUTH_MUNGE). Munge cred will be generated automatically.
    To use with JWT, use Auth(cred=jwt_token, plugin_id=PLUGIN_AUTH_JWT).
    """
    plugin_id: int = None
    cred: str = None

class Body:
    pass

@dataclass
class RequestConfigBody(Body):
    req_flags: int = 0x001

    def pack(self):
        return pack('!I', self.req_flags)

@dataclass
class ResponseConfigBody(Body):
    config_files: list[tuple] = field(default_factory=list) # filename, content
    spool_dir: str = None

    def pack(self):
        raise NotImplementedError('Responses are only unpacked, not packed')


@dataclass
class SlurmMessage:
    """
    A Slurm message consists of `header`, `auth`, and `body` payloads, in that order.
    When packing a message, because they depend on each other (e.g. auth may need to create a hash of the body),
    first the separate instances are created. Then, they can be pack()ed.
    When unpacking a message, the binary `data` will be "walked", starting at offset 0,
    unpacking header, auth, and body, also in that order.
    """
    data: bytes = None

    header: Header = Header()
    auth: Auth = Header()
    body: Body = None

    _unpack_offset: int = 0

    def _unpack(self, fmt):
        """
        Akin to struct.unpack, but keep track of which bytes we've unpacked from self.data (in self._unpack_offset).
        """
        unpack_sz = calcsize(fmt)
        res = unpack(fmt, self.data[self._unpack_offset:self._unpack_offset+unpack_sz])
        self._unpack_offset += unpack_sz
        return res

    def _unpackstr(self):
        """
        Unpacks a string <uint32_t><str><\0>, where len of str is given by the first uint32_t size.
        Keep track of the offset in self.data
        """
        str_len, = self._unpack('!I')
        if (str_len > 0):
            # str_len accounts for trailing '\0'
            s = self.data[self._unpack_offset:self._unpack_offset+str_len-1]
            self._unpack_offset += str_len
            return s
        else:
            return None

    def unpack_header(self):
        self.header.protocol_version, = self._unpack('!H')
        if self.header.protocol_version != protocol_version:
            sys.exit(f'Protocol version response from server ({self.header.protocol_version}) is different to the protocol version requested ({protocol_version}).')
        if protocol_version >= SLURM_PROTOCOL_VERSION['22.05']:
            _, self.header.msg_type, self.header.body_length, _, _, _ = self._unpack('!HHIHHH')
        elif protocol_version >= SLURM_PROTOCOL_VERSION['20.11']:
            _, _, self.header.msg_type, self.header.body_length, _, _, _ = self._unpack('!HHHIHHH')

    def unpack_auth(self):
        self.auth.plugin_id, = self._unpack('!I')
        if self.auth.plugin_id == PLUGIN_AUTH_MUNGE:
            self.auth.cred = self._unpackstr()
            logging.debug(f'Munge cred: {self.auth.cred}')
        if self.auth.plugin_id == PLUGIN_AUTH_JWT:
            token = self._unpackstr()
            user = self._unpackstr()

    def _unpack_list(self):
        lst = []
        config_file_count, = self._unpack('!I')
        if config_file_count != NO_VAL:
            for i in range(0, config_file_count):
                file_exists, = self._unpack('B')
                filename = self._unpackstr()
                if filename:
                    filename = filename.decode('utf-8')
                content = self._unpackstr()
                if content:
                    content = content.decode('utf-8')
                logging.debug(f'filename: {filename}, exists: {bool(file_exists)}')
                if file_exists:
                    lst.append((filename, content))
        return lst

    def unpack_body(self):
        if self.header.msg_type == RESPONSE_SLURM_RC:
            # Uh oh, error!
            rc, = self._unpack('!I')
            if rc == 2010:
                logging.error('Maybe you did not run as Slurm user or root (required for munge auth)?')
            sys.exit(f'We got a reply with errno: {rc}')
        elif self.header.msg_type == RESPONSE_CONFIG:
            if self.header.protocol_version >= SLURM_PROTOCOL_VERSION['21.08']:
                self.body = ResponseConfigBody()
                logging.debug(f'Got a response body of length {self.header.body_length}:')
                self.body.config_files = self._unpack_list()
                self.body.spool_dir = self._unpackstr().decode('utf-8')
            elif self.header.protocol_version >= SLURM_PROTOCOL_VERSION['20.11']:
                raise NotImplementedError('Fetching config from Slurm 21.08 > version >= 20.11 not yet implemented')
            else:
                raise Exception(f'Server replied with unsupported protocol version: {self.header.protocol_version}')
        

    def unpack(self):
        self._unpack_offset = 0
        self.unpack_header()
        self.unpack_auth()
        self.unpack_body()

    def _get_munge_cred(self):
        custom_string = pack('!H', REQUEST_CONFIG)
        body = self.body.pack()
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
            self.auth.cred = ctx.encode(slurm_hash)
        return self.auth.cred

    def pack(self):
        self.data = self.pack_header() + \
                    self.pack_auth() +   \
                    self.pack_body()
        logging.debug(f'Full message: ({len(self.data)})')
        logging.debug(hexdump(self.data))
        return self.data

    def pack_header(self):
        if self.header.protocol_version >= SLURM_PROTOCOL_VERSION['22.05']:
            header = pack('!HHHIHHH',
                          self.header.protocol_version,
                          self.header.flags,
                          self.header.msg_type,
                          self.header.body_length,
                          self.header.forward_cnt,
                          self.header.ret_cnt,
                          self.header.address_ss_family)
        elif self.header.protocol_version >= SLURM_PROTOCOL_VERSION['20.11']:
             header = pack('!HHHHIHHH',
                          self.header.protocol_version,
                          self.header.flags,
                          0,
                          self.header.msg_type,
                          self.header.body_length,
                          self.header.forward_cnt,
                          self.header.ret_cnt,
                          self.header.address_ss_family)
        logging.debug(f'Header ({len(header)}):')
        logging.debug(hexdump(header))
        return header

    def pack_auth(self):
        if self.auth.plugin_id == PLUGIN_AUTH_MUNGE:
            try:
                self.auth.cred = self._get_munge_cred()
            except Exception as err:
                sys.exit(f'Failed to generate munge credential:\n{err}')
            auth = pack('!II', self.auth.plugin_id, len(self.auth.cred)+1) + self.auth.cred + b'\x00'
        elif self.auth.plugin_id == PLUGIN_AUTH_JWT:
            # packstr(token) + packstr(NULL)
            auth = pack('!II', self.auth.plugin_id, len(self.auth.cred)+1) + bytes(self.auth.cred, 'utf-8') + b'\x00' + b'\x00\x00\x00\x00'
        logging.debug(f'Auth: ({len(auth)})')
        logging.debug(hexdump(auth))
        return auth

    def pack_body(self):
        body = self.body.pack()
        logging.debug(f'Body: ({len(body)})')
        logging.debug(hexdump(body))
        return body

    def RequestConfigMsg(self, protocol_version, auth_method):
        self.header = Header(protocol_version=protocol_version)
        self.body = RequestConfigBody()
        logging.info(f'Using authentication method: {auth_method}')
        if auth_method == 'jwt':
            try:
                token = os.environ['SLURM_JWT']
            except:
                sys.exit('Auth method jwt requested but SLURM_JWT undefined')
            self.auth = Auth(cred=token, plugin_id=PLUGIN_AUTH_JWT)
        else:
            if not has_munge:
                sys.exit('Auth method munge requested, but pymunge not available')
            self.auth = Auth(plugin_id=PLUGIN_AUTH_MUNGE)
        payload = self.pack()
        return payload



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
    msg.unpack()
    return msg

def save_config(msg, output_dir):
    for file in msg.body.config_files:
        filepath = f'{output_dir}/{file[0]}'
        content = str(file[1])
        try:
            with open(filepath, 'w') as f:
                f.write(content)
        except Exception as err:
            logging.error(f'Unable to write {filepath}: {err}')

def fetch_config(servers, auth, output_dir='./'):
    logging.debug(f'Using protocol version: {protocol_version}')
    payload = SlurmMessage().RequestConfigMsg(protocol_version=protocol_version, auth_method=auth)
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
    slurm_msg = parse_msg(response_msg)
    if slurm_msg.body.spool_dir:
        logging.info(f'SlurmdSpoolDir={slurm_msg.body.spool_dir}')
    save_config(slurm_msg, output_dir)

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
    parser.add_argument('-o', '--output-dir', default='./',
                        help='Existing output directory where config files will be saved')
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
    fetch_config(args.server, args.auth, args.output_dir)

if __name__ == '__main__':
    main()
