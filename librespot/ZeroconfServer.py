import zeroconf
from time import sleep
from random import randint, choice
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs, parse_qsl
# import pyDH
from .crypto import DiffieHellman
from base64 import b64encode, b64decode
import threading
import json
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
from collections import namedtuple as _nt
from io import BytesIO
# from proto import Keyexchange
import os
import socket
# from .core import Session

VERSION = '0.1.0'
'''
https://github.com/librespot-org/librespot/wiki/Authentication
https://github.com/librespot-org/librespot-java/blob/dev/lib/src/main/java/xyz/gianlu/librespot/ZeroconfServer.java#L279
'''

spotify_aps = [
    ('gew1-accesspoint-e-p7l8.ap.spotify.com', 4070),
    ('gew1-accesspoint-c-dxgt.ap.spotify.com', 443),
    ('gew1-accesspoint-e-bhhz.ap.spotify.com', 80),
    ('gew1-accesspoint-e-h5bk.ap.spotify.com', 4070),
    ('gew1-accesspoint-e-7nwb.ap.spotify.com', 443),
    ('gew1-accesspoint-e-k6dg.ap.spotify.com', 80),
    ('guc3-accesspoint-e-rccz.ap.spotify.com', 4070),
    ('guc3-accesspoint-e-ps5d.ap.spotify.com', 443),
    ('guc3-accesspoint-e-0qs4.ap.spotify.com', 80)]

spotify_dealers = [
    ('gew-dealer.spotify.com', 443),
    ('guc-dealer.spotify.com', 443),
    ('gae-dealer.spotify.com', 443)]

spotify_spclients = [
    ('spclient=[gew-spclient.spotify.com', 443),
    ('gae-spclient.spotify.com', 443),
    ('guc-spclient.spotify.com', 443)]


class SpotifyDiscover:
    class SpotifyHTTPAuth(BaseHTTPRequestHandler):

        _nt_auth = _nt('SpotifyAuth', 'type username token')

        default_getinfo_fields = {"status": 101,
                                  "statusString": "ERROR-OK",
                                  "spotifyError": 0,
                                  "version": "2.1.0",
                                  "libraryVersion": VERSION,
                                  "accountReq": "PREMIUM",
                                  "brandDisplayName": "librespot-org",
                                  "modelDisplayName": "librespot-python",
                                  "voiceSupport": "NO",
                                  "availability": "",
                                  "productID": 0,
                                  "tokenType": "default",
                                  "groupStatus": "NONE",
                                  "resolverVersion": "0",
                                  "scope": "streaming:client-authorization-universal",
                                  "activeUser": ""}

        name = 'default'
        device_id = 'c46d3aa800c725d4e2e2f1e05ca03cc007151c29'
        deviceType = 'SPEAKER'
        # private_key = None
        dh = DiffieHellman()


        def parse_auth_blob(self, blob):
            b = BytesIO(blob)
            b.seek(1)
            username_len = int.from_bytes(b.read(1), 'little')
            username = b.read(username_len).decode()
            b.seek(1, 1)
            auth_type = int.from_bytes(b.read(1), 'little')
            b.seek(1, 1)
            auth_token_len = int.from_bytes(b.read(1), 'little')
            b.seek(1, 1)
            auth_token = b.read(auth_token_len).decode()
            return self._nt_auth(auth_type, username, auth_token)


        def do_GET(self):
            action = parse_qs(urlparse(self.path).query).get('action')
            if action:
                action = action[0]

            if action == 'getInfo':
                info = self.default_getinfo_fields
                info['name'] = self.name
                info['deviceID'] = self.device_id
                info['remoteName'] = self.name
                info['publicKey'] = b64encode(self.dh.public_key.to_bytes(96, 'big')).decode('ascii')
                info['deviceType'] = self.deviceType
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(info).encode('ascii'))
            else:
                self.send_response(404)
                self.end_headers()


        def do_POST(self):
            self.content_length = int(self.headers['Content-Length'])
            if not self.content_length:
                self.send_response(400)
                self.end_headers()
            post_data = self.rfile.read(self.content_length)
            self.post_data = dict(parse_qsl(post_data.decode('ascii')))
            username = self.post_data['userName']
            blob = b64decode(self.post_data['blob'])
            iv = blob[:0x10]
            expect_mac = blob[-0x14:]
            encrypted = blob[0x10:-0x14]
            shared_key = self.dh.compute_shared_key(b64decode(self.post_data['clientKey']))
            base_key = hashlib.sha1(shared_key.to_bytes(96, 'big')).digest()[:0x10]
            checksum_key = hmac.digest(base_key, b'checksum', hashlib.sha1)
            encryption_key = hmac.digest(base_key, b'encryption', hashlib.sha1)[:0x10]
            mac = hmac.digest(checksum_key, encrypted, hashlib.sha1)
            assert mac == expect_mac, 'Checksum incorrect, key exchange failed!'

            ptext = AES.new(encryption_key, AES.MODE_CTR, initial_value=iv, nonce=b'').decrypt(encrypted)
            data = b64decode(ptext.decode('ascii'))

            base_key = hashlib.pbkdf2_hmac('SHA1', hashlib.sha1(self.device_id.encode()).digest(),
                                           username.encode(), 0x100, 20)
            key = hashlib.sha1(base_key).digest() + int.to_bytes(20, 4, 'big')
            decrypted_blob = bytearray(AES.new(key, AES.MODE_ECB).decrypt(data))

            for i in range(len(decrypted_blob) - 16):
                decrypted_blob[len(decrypted_blob) - i - 1] ^= decrypted_blob[len(decrypted_blob) - i - 0x11]

            auth = self.parse_auth_blob(decrypted_blob)
            assert auth.username == username
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(json.dumps(dict())))
            self.end_headers()
            self.wfile.write(json.dumps(dict()).encode())
            # todo Setup session based on current successful auth
            # self.session = Session()


    def __init__(self, name, port=None):
        self.name = name
        self.SpotifyHTTPAuth.name = name
        self.port = port if port else randint(1024, 65535)
        self.http_server = None
        self.http_thread = None
        self.zeroconf = None
        self.http_req_handler = None
        self.setup_http_auth_server()
        self.setup_zeroconf()
        print(f'Serving HTTP on port {self.port} and using Zeroconf to redirect auth requests to it...')


    def setup_zeroconf(self, interface=None):
        # TODO Get the actual interface addresses
        svc = zeroconf.ServiceInfo('_spotify-connect._tcp.local.', f'{self.name}._spotify-connect._tcp.local.',
                                   self.port,
                                   properties={'CPATH': '/', 'VERSION': '1.0', 'Stack': 'SP'},
                                   parsed_addresses=['10.0.0.80'])
        self.zeroconf = zeroconf.Zeroconf()
        self.zeroconf.register_service(svc)


    def start_http_server(self):
        self.http_server = HTTPServer(('0.0.0.0', self.port), self.SpotifyHTTPAuth)
        self.http_server.serve_forever()


    def setup_http_auth_server(self):
        self.http_thread = threading.Thread(target=self.start_http_server)
        self.http_thread.start()


if __name__ == '__main__':
    sp_discovery = SpotifyDiscover('PyTest Speaker', port=1338)

    while True:
        sleep(1)
