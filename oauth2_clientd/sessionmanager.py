#!/usr/bin/python3

import os
import os.path
import threading
import http.server
import socket
import select
import sys
import urllib.parse
import json
import secrets
import hashlib
import base64
import getpass
import stat
import logging

from typing import cast, Any, Dict, Optional, Tuple, Type, Union

from atomicwrites import atomic_write

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from requests_oauthlib import OAuth2Session # type: ignore

from .helpers import b64decode, b64encode_str, encode_dict

log = logging.getLogger(__name__)

class NoTokenError(RuntimeError):
    """The token is not available"""

class NoPrivateKeyError(RuntimeError):
    """Cannot unlock private key"""

try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn
    class ThreadingHTTPServer(ThreadingMixIn, http.server.HTTPServer): # type: ignore
        daemon_threads = True

class _RedirectURIHandler(http.server.BaseHTTPRequestHandler):
    def log_request(self, code: Union[int, str] = '-',
                    size: Union[int, str] = '-') -> None:
        if log.level >= logging.DEBUG:
            super().log_request(code, size)

    def do_HEAD(self) -> None:
        # pylint: disable=invalid-name
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def _write_already_provided(self) -> None:
        self.wfile.write(b'The authorization redirect has already been provided ' +
                         b'and this server will shut down shortly.')

    def _write_redirect_completed(self) -> None:
        self.wfile.write(b'Authorization redirect completed. You may '
                         b'close this window.')

    def _write_invalid_request(self) -> None:
        self.wfile.write(b'The requested URI does not represent an authorization redirect.')

    # pylint: disable=invalid-name
    def do_GET(self) -> None:
        self.do_HEAD()
        self.wfile.write(b'<html><head><title>Authorizaton result</title></head>')
        self.wfile.write(b'<body><p>')

        path = 'http://localhost' + self.path
        server = cast(_ThreadingHTTPServerWithContext, self.server)
        if server.context.validate_authurl(path):
            with server.context.authurl_lock:
                if server.context.authurl:
                    self._write_already_provided()
                else:
                    server.context.authurl = path
                    self._write_redirect_completed()
        else:
            self._write_invalid_request()
        self.wfile.write(b'</p></body></html>')

class _TokenSocketHandler(http.server.BaseHTTPRequestHandler):
    def log_request(self, code: Union[int, str] = '-',
                    size: Union[int, str] = '-') -> None:
        if log.level >= logging.INFO:
            super().log_request(code, size)

    # pylint: disable=invalid-name
    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    # pylint: disable=invalid-name
    def do_GET(self) -> None:
        self.do_HEAD()
        server = cast(_ThreadingHTTPServerWithContext, self.server)
        with server.context.token_lock:
            if (not server.context.token or
                    not 'access_token' in server.context.token):
                raise NoTokenError("Cannot retreive access token")
            response = server.context.token['access_token']

        self.wfile.write(bytes(response, 'utf-8'))

class _ThreadingHTTPServerWithContext(ThreadingHTTPServer):
    def __init__(self, address: Tuple[str, int],
                 handler: Type[http.server.BaseHTTPRequestHandler],
                 context: 'OAuth2ClientManager') -> None:
        super().__init__(address, handler)
        self.context = context

class _UnixSocketThreadingHTTPServer(_ThreadingHTTPServerWithContext):
    address_family = socket.AF_UNIX
    def __init__(self, filename: str,
                 handler: Type[http.server.BaseHTTPRequestHandler],
                 context: 'OAuth2ClientManager') -> None:
        super().__init__((filename, 0), handler, context)

    def server_bind(self) -> None:
        self.socket.bind(self.server_address[0])

    def get_request(self) -> Tuple[Any, Tuple[str, int]]:
        req, _ = super().get_request()
        return req, self.server_address

def crypto_padding() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)

class OAuth2ClientManager:
    def __init__(self, registration: Dict[str, str], client: Dict[str, str]) -> None:
        self._registration = registration
        self.client = client
        self.session_file_path: Optional[str] = None
        self.public_key: Optional[rsa.RSAPublicKey] = None
        self.saved_session: Dict[str, Any] = {}
        self.session: OAuth2Session = None

        self.token: Optional[Dict[str, Any]] = None
        self.token_lock = threading.Lock()
        self.token_changed = threading.Condition(self.token_lock)

        self.authurl: Optional[str] = None
        self.authurl_lock = threading.Lock()

        self._server: Optional[_ThreadingHTTPServerWithContext] = None
        self._server_thread: Optional[threading.Thread] = None

        self._file_thread: Optional[threading.Thread] = None
        self._file_thread_exit = threading.Event()

    @property
    def access_token_expiry(self) -> float:
        if not self.token:
            raise NoTokenError("No valid token found.")
        if not 'expires_at' in self.token:
            raise ValueError("Token is missing expiration")
        with self.token_lock:
            expiry = self.token['expires_at']
        return expiry

    def _init_saved_session(self) -> None:
        password_bytes = None
        while password_bytes is None:
            try:
                pw1 = getpass.getpass("Enter password for new private key (min 10 chars): ")
                if len(pw1) < 10:
                    print("Password too short.  Must be longer than 10 characters.",
                          file=sys.stderr)
                    continue
                pw2 = getpass.getpass("Repeat: ")
            except (KeyboardInterrupt, EOFError) as ex:
                raise NoPrivateKeyError("Cannot create private key without password.") from ex

            if pw1 == pw2:
                password_bytes = bytes(pw1.encode())
            else:
                print("Passwords don't match.  Try again.")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                               backend=default_backend())
        self.public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.BestAvailableEncryption(password_bytes))
        public_key_pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)

        self.saved_session = {
            'private_key' : private_key_pem.decode('utf-8'),
            'public_key' : public_key_pem.decode('utf-8'),
        }

    @classmethod
    def from_saved_session(cls, path: str) -> 'OAuth2ClientManager':
        with open(path, 'rb') as session_file:
            saved_session = json.loads(session_file.read())

        private_key_pem_bytes = bytes(saved_session['private_key'], 'utf-8')
        public_key_pem_bytes = bytes(saved_session['public_key'], 'utf-8')

        private_key = None
        while private_key is None:
            try:
                password = getpass.getpass("Enter password for private key: ")
            except (KeyboardInterrupt, EOFError) as ex:
                raise NoPrivateKeyError("Cannot unlock private key without password.") from ex

            if not password:
                continue

            password_bytes = bytes(password.encode())
            try:
                private_key = serialization.load_pem_private_key(private_key_pem_bytes,
                                                                 password=password_bytes,
                                                                 backend=default_backend())
            except ValueError as ex: # Usually bad password
                print(ex)

        key = private_key.decrypt(b64decode(saved_session['cryptoparams']['key']),
                                  crypto_padding())
        del private_key

        nonce = b64decode(saved_session['cryptoparams']['nonce'])

        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(b64decode(saved_session['data'])) + decryptor.finalize()
        session = json.loads(b64decode(data))

        obj = cls(session['registration'], session['client'])
        obj.session_file_path = path
        obj.saved_session = saved_session
        obj.public_key = serialization.load_pem_public_key(public_key_pem_bytes,
                                                           backend=default_backend())

        obj.token = session['tokendata']
        obj.session = OAuth2Session(session['client'], token=obj.token)

        return obj

    def _encrypt(self, data: bytes) -> Tuple[bytes, Dict[str, str]]:
        if not self.public_key:
            raise RuntimeError("No public key available")
        key = os.urandom(32)
        nonce = os.urandom(16)

        params: Dict[str, str] = {
            'algo' : 'AES',
            'mode' : 'CTR',
            'key' : b64encode_str(self.public_key.encrypt(key, crypto_padding())),
            'nonce' : b64encode_str(nonce),
        }

        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return encrypted_data, params

    def save_session(self, path: Optional[str] = None, overwrite: bool = True) -> None:
        if path is None and self.session_file_path:
            path = self.session_file_path
        elif self.session_file_path is None and path:
            self.session_file_path = path
        else:
            raise ValueError("No path specified and no default available.")

        data_dict = {
            'client' : self.client,
            'registration' : self._registration,
            'tokendata' : self.token,
        }

        data, params = self._encrypt(encode_dict(data_dict))
        self.saved_session['data'] = b64encode_str(data)
        self.saved_session['cryptoparams'] = params

        if path is None:
            raise RuntimeError("No session file named for write.")

        jsondata = json.dumps(self.saved_session, sort_keys=True, indent=4)
        del self.saved_session['data']
        del self.saved_session['cryptoparams']
        with atomic_write(path, overwrite=overwrite) as session_file:
            print(jsondata, file=session_file)

    def _start_server(self) -> None:
        if self._server_thread:
            raise RuntimeError("Server thread already running.")
        if not self._server:
            raise RuntimeError("HTTP server not set up yet.")

        self._server.context = self
        self._server_thread = threading.Thread(target=self._server.serve_forever, name='SocketThread')
        self._server_thread.start()

    def _setup_redirect_listener(self, port: int = 0) -> None:
        self._server = _ThreadingHTTPServerWithContext(('127.0.0.1', port), _RedirectURIHandler, self)

    def _get_redirect_listener_port(self) -> int:
        if not self._server:
            raise RuntimeError("No server configured.")
        return self._server.server_address[1]

    def _stop_server(self) -> None:
        if self._server:
            log.debug("Telling HTTP server to shutdown")
            self._server.shutdown()
            self._server = None

        if self._server_thread:
            log.debug("Waiting for HTTP server to shutdown")
            self._server_thread.join()
            self._server_thread = None
            log.debug("HTTP server has shutdown")

    @staticmethod
    def _generate_pkce_context() -> Tuple[str, Dict[str, str]]:
        verifier = secrets.token_urlsafe(90)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest)[:-1].decode('utf-8')

        pkce_challenge = {
            'code_challenge_method' : 'S256',
            'code_challenge' : challenge,
        }
        return (verifier, pkce_challenge)

    @staticmethod
    def _print_authurl_prompt() -> None:
        print('Please enter the full callback URL: ', end='', flush=True)

    def _inform_user_of_listener(self) -> None:
        if not self._server:
            return

        port = self._get_redirect_listener_port()
        listening = f"\nA listener has been started at localhost:{port}.  When you follow the link, the authorization response will be received automatically."
        listening += f"\nIf using this system remotely, you may wish to forward the port to this host by creating a new SSH session with the following options: '-L {port}:localhost:{port}' prior to following the link.\n"
        print(listening)

    @staticmethod
    def validate_authurl(url: str) -> bool:
        """Validate that a url could potentially be an authurl by testing for the 'code' query variable"""
        querystring = urllib.parse.urlparse(url).query
        qvars = urllib.parse.parse_qs(querystring)
        return 'code' in qvars

    # This handles racing with the http listener
    def _wait_for_authurl_on_stdin(self) -> None:
        self._print_authurl_prompt()
        while True:
            (readers, _, _) = select.select([sys.stdin], [], [], 0.5)
            with self.authurl_lock:
                if not self.authurl and readers:
                    try:
                        url = sys.stdin.readline()
                        if self.validate_authurl(url):
                            self.authurl = url
                        else:
                            print("Error: No authcode provided.")
                            self._print_authurl_prompt()
                            continue
                    except KeyboardInterrupt:
                        break
                elif self.authurl:
                    print("(not necessary any longer)\nResponse provided by browser session.\n")
                if self.authurl:
                    break


    @classmethod
    def from_new_authorization(cls, registration: Dict[str, str], client: Dict[str, str],
                               port: int = 0) -> 'OAuth2ClientManager':
        obj = cls(registration, client)
        obj._init_saved_session()
        obj._new_authorization(port)

        return obj

    def _new_authorization(self, port: int = 0) -> None:
        redirect_uri = self._registration['redirect_uri']
        if 'http://localhost' in redirect_uri:
            self._setup_redirect_listener(port)
            port = self._get_redirect_listener_port()

            redirect_uri = f'http://localhost:{port}'

        self.session = OAuth2Session(self.client['client_id'], redirect_uri=redirect_uri,
                                     scope=self._registration['scope'])

        verifier, pkce_challenge = self._generate_pkce_context()


        authorization_url, _ = self.session.authorization_url(self._registration['authorize_endpoint'],
                                                              **pkce_challenge)

        print(f'Please go to {authorization_url} and authorize access.')
        if self._server:
            self._start_server()
            self._inform_user_of_listener()
        self._wait_for_authurl_on_stdin()
        if self._server:
            self._stop_server()

        if not self.authurl:
            raise RuntimeError("Stopped waiting for authurl but none found.")

        # oauthlib expects redirects to be https -- no need for localhost
        if 'http://localhost' in self.authurl:
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

        # o365 requires the 'offline_access' scope in the request to issue
        # refresh tokens but strips it in the response. oauthlib views that
        # as a changed scope event that is handled as an error unless relaxed.
        os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
        self.token = self.session.fetch_token(self._registration['token_endpoint'],
                                              authorization_response=self.authurl,
                                              include_client_id=True,
                                              **self.client, code_verifier=verifier)

    def refresh_token(self) -> None:
        log.info("Starting token refresh")
        new_token = self.session.refresh_token(self._registration['token_endpoint'], **self.client)
        log.info("Token refreshed")

        with self.token_changed:
            self.token = new_token
            self.token_changed.notify()

    def get_access_token(self) -> str:
        if not self.token or 'access_token' not in self.token:
            raise NoTokenError("No access token available")
        with self.token_lock:
            access_token = self.token['access_token']
        return access_token

    def write_access_token(self, filename: str) -> None:
        if not self.token or 'access_token' not in self.token:
            raise NoTokenError("No access token available.")
        try:
            with atomic_write(filename, overwrite=True) as access_file:
                print(self.token['access_token'], file=access_file)
        except OSError as ex:
            log.warning(f"Failed to write access token to file '{filename}': {ex.strerror}")

    def _file_writer(self, filename: str) -> None:
        if not self.token or 'access_token' not in self.token:
            raise NoTokenError("No access token available.")
        my_token: Optional[str] = None
        while True:
            needs_write = False
            with self.token_changed:
                if my_token == self.token['access_token']:
                    self.token_changed.wait()
                else:
                    my_token = self.token['access_token']
                    needs_write = True

            if not my_token:
                raise NoTokenError("Access token changed but is unavailable.")

            if needs_write:
                log.info(f"Writing out new access token to {filename}")
                self.write_access_token(filename)
            if self._file_thread_exit.is_set():
                log.debug("_file_writer: Exiting")
                break

    def start_file_writer(self, filename: str) -> None:
        self._file_thread = threading.Thread(target=self._file_writer, args=((filename),), name='FileWriterThread')
        self._file_thread.start()

    def stop_file_writer(self) -> None:
        if self._file_thread:
            log.debug("Telling file thread to exit")
            self._file_thread_exit.set()
            with self.token_changed:
                self.token_changed.notify()
            log.debug("Waiting for file thread to exit")
            self._file_thread.join()
            log.debug("File thread has exited")

    def start_socket_listener(self, filename: str) -> None:
        if self._server or self._server_thread:
            raise RuntimeError("Server already running")

        log.debug(f"Starting HTTP listener on {filename}")

        if os.path.exists(filename):
            sock_stat = os.stat(filename)
            if stat.S_ISSOCK(sock_stat.st_mode):
                os.unlink(filename)
            else:
                raise OSError("{filename} already exists but is not a socket.  Will not replace.")
        self._server = _UnixSocketThreadingHTTPServer(filename, _TokenSocketHandler, self)
        self._server.context = self
        os.chmod(filename, 0o600)

        self._start_server()

    def stop_socket_listener(self) -> None:
        self._stop_server()
