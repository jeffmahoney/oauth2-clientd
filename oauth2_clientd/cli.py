#!/usr/bin/python3

import os
import os.path
import argparse
import stat
import sys
import time
import signal
import shutil
import getpass
import contextlib
import subprocess
import logging

from typing import Any, Dict, Optional, Sequence, TextIO

import daemon # type: ignore
import daemon.pidfile # type: ignore
from lockfile import AlreadyLocked # type: ignore
from oauthlib.oauth2.rfc6749.errors import OAuth2Error # type: ignore

from .sessionmanager import OAuth2ClientManager
from .sessionmanager import NoTokenError, NoPrivateKeyError

log = logging.getLogger(__name__)
DATE_FORMAT='%Y-%m-%d %H:%M:%S'
LOG_FORMAT = "%(asctime)s.%(msecs)03d %(threadName)s[%(process)d] %(levelname)s %(message)s"

try:
    from contextlib import nullcontext
except ImportError:
    # pylint: disable=invalid-name
    class nullcontext(contextlib.AbstractContextManager): # type: ignore
        def __init__(self, enter_result=None):
            self.enter_result = enter_result

        def __enter__(self):
            return self.enter_result

        def __exit__(self, *excinfo):
            pass

registrations: Dict[str, Dict[str, Sequence[str]]] = {
    'google': {
        'authorize_endpoint': 'https://accounts.google.com/o/oauth2/auth',
        'devicecode_endpoint': 'https://oauth2.googleapis.com/device/code',
        'token_endpoint': 'https://accounts.google.com/o/oauth2/token',
        'redirect_uri': 'http://localhost',
        'imap_endpoint': 'imap.gmail.com',
        'pop_endpoint': 'pop.gmail.com',
        'smtp_endpoint': 'smtp.gmail.com',
        'sasl_method': 'OAUTHBEARER',
        'scope': 'https://mail.google.com/',
    },
    'microsoft': {
        'authorize_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        'devicecode_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
        'token_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        #'redirect_uri': 'https://login.microsoftonline.com/common/oauth2/nativeclient',
        'redirect_uri' : 'http://localhost',
        'imap_endpoint': 'outlook.office365.com',
        'pop_endpoint': 'outlook.office365.com',
        'smtp_endpoint': 'smtp.office365.com',
        'sasl_method': 'XOAUTH2',
        'scope': ('offline_access https://outlook.office.com/IMAP.AccessAsUser.All',
                  'https://outlook.office.com/POP.AccessAsUser.All',
                  'https://outlook.office.com/SMTP.Send'),
    },
    'suse-o365': {
        'inherits' : 'microsoft',
        'client_id' : '3ce62cca-417a-462c-bbe5-03d1888daf53',
        'tenant' : 'mysuse.onmicrosoft.com',
        'client_secret' : ''
    }
}
DEFAULT_PROVIDER = 'suse-o365'

def shutdown_listeners_and_exit(oaclient: OAuth2ClientManager) -> None:
    log.warning("Shutting down")
    oaclient.stop_file_writer()
    oaclient.stop_socket_listener()
    sys.exit(0)

class SignalHandler:
    def __init__(self, client: OAuth2ClientManager) -> None:
        self.client = client

    def __call__(self, signum: int, trace: Any) -> None:
        shutdown_listeners_and_exit(self.client)

def token_needs_refreshing(token: Dict[str, Any], threshold: int) -> bool:
    return token['expires_at'] + threshold > time.time()

def wait_for_refresh_timeout(oaclient: OAuth2ClientManager, thresh: int) -> None:
    if not oaclient.token:
        raise NoTokenError("No token to refresh")

    timeout = oaclient.access_token_expiry - thresh - time.time()

    if timeout > 0:
        log.info(f"Waiting {int(timeout)}s to refresh token.")
        time.sleep(timeout)
    else:
        log.info("Token has expired.")

def run_update_hook(update_hook: str, access_token: str) -> None:
    try:
        log.info(f"Running update hook {update_hook} for new access token.")
        cmd = subprocess.run([update_hook], input=access_token, text=True, timeout=5)
    except subprocess.TimeoutExpired as ex:
        log.warning(f"Update hook {update_hook} timed out after {ex.timeout}s.")
    except subprocess.CalledProcessError as ex:
        ret = ex.returncode
        if ret > 0:
            log.warning(f"Update hook {update_hook} failed.  Exited with status={ret}.")
        else:
            log.warning(f"Update hook {update_hook} terminated by signal {-ret}.")

def main_loop(oaclient: OAuth2ClientManager, sockname: Optional[str],
              filename: Optional[str], threshold: int = 300,
              update_hook: Optional[str] = None) -> None:

    if not oaclient.token:
        raise NoTokenError("No token to monitor")

    if token_needs_refreshing(oaclient.token, threshold):
        oaclient.refresh_token()

    oaclient.save_session()

    if sockname:
        oaclient.start_socket_listener(sockname)

    if filename:
        oaclient.start_file_writer(filename)

    # Assume the access token has been changed since the last startup
    if update_hook:
        run_update_hook(update_hook, oaclient.token['access_token'])

    try:
        while True:
            wait_for_refresh_timeout(oaclient, threshold)
            log.debug("Wait for refresh complete")
            oaclient.refresh_token()
            oaclient.save_session()

            if update_hook:
                run_update_hook(update_hook, oaclient.token['access_token'])
            elif log.level >= logging.DEBUG and not filename and not sockname:
                print("\nBEGIN ACCESS TOKEN")
                if oaclient.token and 'access_token' in oaclient.token:
                    print(oaclient.token['access_token'])
                else:
                    raise NoTokenError("Token was supposed to be refreshed but is missing")
    except KeyboardInterrupt:
        shutdown_listeners_and_exit(oaclient)

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase verbosity')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='enable debug output')
    parser.add_argument('-a', '--authorize', action='store_true',
                        help='generate a new refresh token on startup using the default clientid and secret for the provider')
    parser.add_argument('-c', '--clientid', type=str, default=None,
                        help='specify client id to use for authorization if different than the default (or if there is no default).')
    parser.add_argument('-p', '--port', type=int, default=0,
                        help='specify port for http server (useful for tunneling to remote host)')
    parser.add_argument('-D', '--daemonize', type=str, dest='logfile',
                        help='detach and daemonize after user interaction is complete, logging to file')
    parser.add_argument('-f', '--file', type=str, default=None,
                        help='write access token to <file> (periodically, prior to expiration, if in daemon mode)')
    parser.add_argument('-i', '--pidfile', type=str, default=None, dest='pidfile',
                        help='write daemon pid to <pidfile>')
    parser.add_argument('-s', '--socket', type=str, default=None,
                        help='create a UNIX socket at <socket> with an http listener to provide access token on request')
    parser.add_argument('-P', '--provider', type=str, default=DEFAULT_PROVIDER,
                        choices=registrations.keys(),
                        help=f'provider to request tokens (default={DEFAULT_PROVIDER})')
    parser.add_argument('-q', '--quiet', action='store_true', help='limit unnecessary output')
    parser.add_argument('-t', '--threshold', type=int, default=300,
                        help='threshold before expiration to attempt to refresh tokens. (default=300s)')
    parser.add_argument('-u', '--update-hook', type=str, default=None,
                        help='path to command to call when token is updated (will receive access token on stdin)')
    parser.add_argument('--force', action='store_true', help='overwrite sessionfile if it exists')
    parser.add_argument('sessionfile', help='path to store encrypted session and refresh token')
    args = parser.parse_args()
    return args

def resolve_registration(provider, loops=None):
    reg = registrations[provider]
    if 'inherits' in reg:
        if loops is None:
            loops = [provider]
        elif provider in loops:
            raise ValueError(f"Provider '{provider}' is already in the dependency chain")
        else:
            loops.append(provider)
        inherited = resolve_registration(reg['inherits'], loops)
        reg = { **inherited, **reg }

    return reg

class FatalError(RuntimeError):
    pass

def main() -> None:
    args = parse_arguments()

    loglevel = logging.WARNING
    if args.debug:
        loglevel = logging.DEBUG
    elif args.verbose:
        loglevel = logging.INFO

    logging.basicConfig(stream=sys.stderr, level=loglevel)

    if args.update_hook:
        try:
            st = os.stat(args.update_hook)
        except IOError as ex:
            raise FatalError(f"Could not stat update hook {args.update_hook}: {ex.strerror}") from ex

        if not stat.S_ISREG(st.st_mode):
            raise FatalError(f"Update hook {args.update_hook} is not a regular file.")

        if st.st_mode & stat.S_IXUSR == 0:
            raise FatalError(f"Update hook {args.update_hook} is not executable.")

    if args.pidfile:
        pidfile_path = os.path.realpath(args.pidfile)
        oa2cd_pidfile = daemon.pidfile.TimeoutPIDLockFile(pidfile_path)
        # If we know the pidfile is there, we can skip asking the user
        # for the password and exit early.  This is racy and for convenience
        # only.  It's checked properly before we start the main loop.
        if oa2cd_pidfile.is_locked():
            pid = oa2cd_pidfile.read_pid()
            raise FatalError(f"PID file {pidfile_path} is already locked by PID {pid}.")
    else:
        oa2cd_pidfile = nullcontext()

    try:
        if args.authorize:
            registration = resolve_registration(args.provider)
            if args.clientid:
                clientid = args.clientid
            elif 'client_id' in registration:
                clientid = registration['client_id']
            else:
                raise FatalError(f"Provider {args.provider} has no default client id set.\nPlease provide one with --clientid.")

            client_data = {
                'client_id' : clientid,
            }

            if os.path.exists(args.sessionfile) and not args.force:
                raise FatalError(f"{args.sessionfile} already exists.")

            # A missing client_secret will cause a password prompt.
            # If the client_secret key is present, even with an empty
            # string or None, we'll use that.
            if 'client_secret' in registration and not args.clientid:
                client_data['client_secret'] = registration['client_secret']
            else:
                try:
                    secret = getpass.getpass(f"Secret for clientid {clientid} (leave empty if there is no secret): ")
                    if secret:
                        client_data['client_secret'] = secret
                except (EOFError, KeyboardInterrupt):
                    raise FatalError("\nFailed to obtain client secret.")

            if 'tenant' in registration:
                client_data['tenant'] = registration['tenant']
            try:
                oaclient = OAuth2ClientManager.from_new_authorization(registration, client_data,
                                                               args.port)
            except OAuth2Error as ex:
                log.error(f"Failed to obtain authorization: {str(ex)}.")
                if args.debug:
                    raise ex from ex
                sys.exit(1)
            oaclient.save_session(args.sessionfile, overwrite=args.force)
        else:
            try:
                # NB: If we make a request before daemonizing, we'll have to
                # re-establish the session afterwards as the sockets backing
                # the connection pool will have been closed.
                oaclient = OAuth2ClientManager.from_saved_session(args.sessionfile)
                if not oaclient.token:
                    raise NoTokenError("Session didn't contain valid session.")
            except (FileNotFoundError, PermissionError) as ex:
                raise FatalError(f"Couldn't open session file: {str(ex)}") from ex
    except NoPrivateKeyError as ex:
        raise FatalError(f"\n{str(ex)}") from ex

    daemonize = False
    if args.logfile:
        daemonize = True

    if not args.file and not args.socket:
        columns = shutil.get_terminal_size((80, 25))[0]
        if not args.quiet:
            raise FatalError("No file or socket was specified")

        if (oaclient.token and
                token_needs_refreshing(oaclient.token, args.threshold)):
            oaclient.refresh_token()

        if oaclient.token and 'access_token' in oaclient.token:
            if not args.quiet:
                raise FatalError("No file, socket, or update hook was specified")
            if oaclient.token and 'access_token' in oaclient.token:
                if not args.quiet:
                    print("Current access token follows:", file=sys.stderr)
                    print(columns * '-', file=sys.stderr)
                print(oaclient.token['access_token'])
                if not args.quiet:
                    print(columns * '-', file=sys.stderr)
            else:
                log.error("No valid access token found.")
            sys.exit(0)
        else:
            daemonize = False

    logfile: Optional[TextIO] = None
    if daemonize:
        try:
            # We open it here just to get an error for the user before
            # we daemonize.
            logfile = open(args.logfile, 'w+') # pylint: disable=consider-using-with
        except (OSError, IOError) as ex:
            raise FatalError(f"Failed to open logfile {logfile}: {ex.args[1]}.") from ex

        context = daemon.DaemonContext(files_preserve=[logfile],
                                       working_directory=os.getcwd(),
                                       pidfile=oa2cd_pidfile,
                                       stdout=sys.stdout,
                                       stderr=sys.stderr)
        context.signal_map = {
            signal.SIGTERM: SignalHandler,
            signal.SIGHUP: 'terminate',
        }
    else:
        context = oa2cd_pidfile

    try:
        with context:
            if logfile:
                sys.stderr.close()
                sys.stdout.close()
                sys.stderr = logfile
                sys.stdout = logfile

            # Now that we're starting up for real, some timestamps and other
            # information may be useful for logging.
            logging.basicConfig(stream=sys.stderr, level=log.level,
                                datefmt=DATE_FORMAT, format=LOG_FORMAT,
                                force=True)
            main_loop(oaclient, args.socket, args.file, args.threshold, args.update_hook)
    except AlreadyLocked as ex:
        raise FatalError(f"{ex} by PID {oa2cd_pidfile.read_pid()}") from ex
