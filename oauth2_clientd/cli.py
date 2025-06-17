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
from configparser import ConfigParser
try:
    import importlib.resources as pkg_resources
except ImportError:
    import importlib_resources as pkg_resources # type: ignore

from typing import Any, Dict, List, Optional, TextIO, Union

import daemon # type: ignore
import daemon.pidfile # type: ignore
from lockfile import AlreadyLocked # type: ignore
from oauthlib.oauth2.rfc6749.errors import OAuth2Error # type: ignore

from .sessionmanager import OAuth2ClientManager
from .sessionmanager import NoTokenError, NoPrivateKeyError

log = logging.getLogger()
DATE_FORMAT='%Y-%m-%d %H:%M:%S'
LOG_FORMAT = "%(asctime)s.%(msecs)03d %(threadName)s[%(process)d] %(levelname)s %(message)s"

DEFAULT_CONFIG_PATHS = [
    '/etc/oauth2-clientd.conf',
    os.path.expanduser('~/.config/oauth2-clientd/oauth2-clientd.conf')
]

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

# CLOCK_BOOTTIME was added in Python 3.7, so we'll use CLOCK_REALTIME on
# earlier releases.
def get_boottime() -> int:
    try:
        return int(time.clock_gettime(time.CLOCK_BOOTTIME))
    except AttributeError:
        return int(time.clock_gettime(time.CLOCK_REALTIME))

# This is a workaround. All implementations of sleep() in Python use
# CLOCK_MONOTONIC, which has the advantage of never going backward but it
# also stops while the system is suspended.  If the system is suspended for
# longer than the specified threshold, we'll miss the renewal window.
# This workaround uses the CLOCK_BOOTTIME clock, which does _not_
# stop while the system is suspended, but since there is no direct way to
# access clock_nanosleep directly from Python, we'll have to settle for
# a loop with short timeouts to check if we've passed the deadline.
# [There is the monotonic_time third-party module but it uses dlopen to
#  access clock_nanosleep and that's even worse of a hack IMO.]
def wallclock_sleep(timeout: int, step: int = 60) -> None:
    deadline = get_boottime() + timeout

    while timeout > 0:
        step = min(step, timeout)
        time.sleep(step)

        timeout = deadline - get_boottime()

def wait_for_refresh_timeout(oaclient: OAuth2ClientManager, thresh: int) -> None:
    if not oaclient.token:
        raise NoTokenError("No token to refresh")

    timeout = int(oaclient.access_token_expiry - thresh - time.time())

    if timeout > 0:
        log.info(f"Waiting {int(timeout)}s to refresh token.")
        wallclock_sleep(timeout)

    if time.time() > oaclient.access_token_expiry:
        log.info("Token has expired.")

def run_update_hook(update_hook: str, access_token: str) -> None:
    try:
        log.info(f"Running update hook {update_hook} for new access token.")
        subprocess.run([update_hook], input=access_token, text=True, timeout=5, check=True)
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

def parse_arguments(config: ConfigParser) -> argparse.Namespace:
    provider_help : Dict[str, Union[Optional[str], List[str]]]

    try:
        default_provider = config['DEFAULT']['provider']
        provider_help = {
            'default' : default_provider,
            'help' : f'provider to request tokens (default={default_provider})',
        }
    except KeyError:
        provider_help = {
            'default' : None,
            'help' : 'provider to request tokens',
        }

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true',
                        help='display this message and exit')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase verbosity')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='enable debug output')
    parser.add_argument('-C', '--config', type=str, action='append',
                        help='specify config file -- can be invoked more than once; empty path or /dev/null will clear options loaded from previously read/default files')

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
    parser.add_argument('-P', '--provider', type=str, **provider_help) # type: ignore
    parser.add_argument('-l', '--list-providers', action='store_true',
                        help='print available providers and exit.')
    parser.add_argument('--dump-config', action='store_true',
                        help='display loaded configuration and exit')
    parser.add_argument('-q', '--quiet', action='store_true', help='limit unnecessary output')
    parser.add_argument('-t', '--threshold', type=int, default=300,
                        help='threshold before expiration to attempt to refresh tokens. (default=300s)')
    parser.add_argument('-u', '--update-hook', type=str, default=None,
                        help='path to command to call when token is updated (will receive access token on stdin)')
    parser.add_argument('--force', action='store_true', help='overwrite sessionfile if it exists')

    # Options that don't require a session file and shouldn't fail should the argument
    # be absent.
    (args, _) = parser.parse_known_args()
    if (args.list_providers or args.dump_config) and not args.help:
        return args

    parser.add_argument('sessionfile', help='path to store encrypted session and refresh token')

    if args.help:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    return args

def resolve_registration(config: ConfigParser, provider: str, loops: Optional[List[str]] = None) -> Dict[str, str]:
    reg = dict(config[provider])
    if 'inherits' in reg:
        if loops is None:
            loops = [provider]
        elif provider in loops:
            raise FatalError(f"Config error: Provider '{provider}' is already in the dependency chain")
        else:
            loops.append(provider)
        if reg['inherits'] not in config:
            raise FatalError(f"Config error: Provider '{provider}' inherits from provider '{reg['inherits']}' which does not exist.")
        inherited = resolve_registration(config, reg['inherits'], loops)
        reg = { **inherited, **reg }

    return reg

_REQUIRED_KEYS = [ 'authorize_endpoint', 'token_endpoint',
                   'sasl_method', 'scope', 'redirect_uri' ]

def validate_registration(provider: str, registration: Dict[str, str]):
    for key in _REQUIRED_KEYS:
        if not key in registration:
            raise FatalError(f"Definition for provider '{provider}' is missing option '{key}'.")

class FatalError(RuntimeError):
    pass

def read_config(config: ConfigParser, path: str, verbose: bool) -> None:
    try:
        msg = f"Reading config from '{path}'"
        with open(path, encoding='utf8', errors="surrogateescape") as config_file:
            config.read_file(config_file)
            msg += "."
    except OSError as ex:
        msg += f" failed: {ex.strerror}. [ignoring]"
    finally:
        if verbose:
            print(msg, file=sys.stderr)

def dump_config(config: ConfigParser, stream: TextIO):
    print("Loaded configuration: ", file=stream)
    config.write(stream)

def dump_providers(config: ConfigParser, stream: TextIO):
    print(f"Available providers: {', '.join(config.sections())}", file=stream)

def update_logging(verbose: bool, debug: bool) -> None:
    loglevel = logging.WARNING
    if debug:
        loglevel = logging.DEBUG
    elif verbose:
        loglevel = logging.INFO

    log.setLevel(loglevel)

def early_verbose(args: List[str]) -> bool:
    return ('-v' in args or '--verbose' in args or
            '-d' in args or '--debug' in args)

def main() -> None:
    config = ConfigParser()

    stderr_log_handler = logging.StreamHandler(stream=sys.stderr)
    log.addHandler(stderr_log_handler)
    update_logging(False, False)

    # We read the configs prior to parsing the command line but we'll still want
    # to be able to report opening configs
    verbose = early_verbose(sys.argv)

    msg = "Reading 'builtin-providers.conf' from package data"
    try:
        text = pkg_resources.open_text('oauth2_clientd.data', 'builtin-providers.conf')
        config.read_file(text)
        if verbose:
            print(msg + ".", file=sys.stderr)
    except FileNotFoundError:
        print(msg + " failed.  Defaults may be unavailable.", file=sys.stderr)

    for path in DEFAULT_CONFIG_PATHS:
        read_config(config, path, verbose)

    args = parse_arguments(config)

    update_logging(args.verbose, args.debug)

    # If -C was used, we'll need to add those into the mix
    if args.config:
        for configfile in args.config:
            if configfile in ('', '/dev/null'):
                config = ConfigParser()
                if args.debug:
                    print("Resetting configuration.", file=sys.stderr)
                continue
            read_config(config, configfile, verbose)

    if args.dump_config:
        dump_config(config, sys.stdout)
        sys.exit(0)

    if args.list_providers:
        dump_providers(config, sys.stdout)
        sys.exit(0)

    if args.provider:
        provider = args.provider
    else:
        try:
            provider = config['DEFAULT']['provider']
        except KeyError as ex:
            raise FatalError('No default provider configured.') from ex

    if not provider in config:
        if args.debug:
            dump_config(config, sys.stderr)
        elif args.verbose:
            dump_providers(config, sys.stderr)

        raise FatalError(f"No provider '{provider}' configured.")

    if args.update_hook:
        try:
            hook_st = os.stat(args.update_hook)
        except IOError as ex:
            raise FatalError(f"Could not stat update hook {args.update_hook}: {ex.strerror}") from ex

        if not stat.S_ISREG(hook_st.st_mode):
            raise FatalError(f"Update hook {args.update_hook} is not a regular file.")

        if hook_st.st_mode & stat.S_IXUSR == 0:
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
            registration = resolve_registration(config, provider)
            validate_registration(provider, registration)
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
                except (EOFError, KeyboardInterrupt) as ex:
                    raise FatalError("\nFailed to obtain client secret.") from ex

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
            # pylint: disable=consider-using-with
            logfile = open(args.logfile, 'w+', encoding='utf8', errors="surrogateescape")
            logfile_handler = logging.StreamHandler(stream=logfile)
            log.addHandler(logfile_handler)
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
                log.removeHandler(stderr_log_handler)
            else:
                logfile_handler = stderr_log_handler

            # Now that we're starting up for real, some timestamps and other
            # information may be useful for logging.
            logfile_formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)
            logfile_handler.setFormatter(logfile_formatter)

            main_loop(oaclient, args.socket, args.file, args.threshold, args.update_hook)
    except AlreadyLocked as ex:
        raise FatalError(f"{ex} by PID {oa2cd_pidfile.read_pid()}") from ex
