# oauth2-clientd

oauth2-clientd is a script to manage OAUTH2 tokens for terminal or
headless Mail User Agents (MUAs) like fetchmail or mutt.

It can obtain a refresh token, securely store it, periodically update it,
and return access tokens on-demand via either a plaintext file or UNIX socket.

## Installation

You will need the following dependencies:

    $ pip3 install --user oauthlib requests-oauthlib python-daemon


Then to install:

    $ python3 setup.py install --user


## Getting started

To get started, you'll need to generate a refresh token.

    $ oauth2-clientd -a <clientid> [-P <provider>] /path/to/sessionfile


If the sessionfile exists, it will be not overwritten without --force.

If left unspecified, the default provider is Microsoft Office 365.

You'll be prompted for two things:
- The secret for the clientid, if any.
- The password for the private key (with confirmation)

Then you'll be presented with a URL to follow in your browser to authenticate
to your provider.

If the provider is configured to redirect to localhost, an HTTP listener
will be started on a random port.  Otherwise, you'll need to copy-and-paste
the authorization URL the provider sends as a response.  If your MUA is
running on a remote system, you can specify the port to use for the listener
with `-p <port>` to allow an SSH tunnel to be used to forward the response
to the script.

Once the refresh token is obtained, oauth2-clientd will wait until
interrupted, refreshing the refresh token 5 minutes before it expires.

## Output

By default, oauth2-clientd will refresh the token and output an access
token on stdout.  Your MUA will probably either use a command to fetch a
new access token or expect the access token to be written to a plaintext
file on disk.

oauth2-clientd exports tokens in two ways:

The following options can be used to start up an HTTP listener on the specified
UNIX socket.  If the socket exists it will be removed and replaced.

    $ oauth2-clientd -s /path/to/socket /path/to/authfile


Your MUA can be configured to retreive the access token with a simple command:

    $ curl --unix-socket /path/to/socket http://localhost


If your client requires a plaintext file, the following command will write out
such a file each time the token is refreshed:

    $ oauth2-clientd -f /path/to/file /path/to/authfile


Both options can be used at the same time but each can only be specified once.

## Background

The script can be daemonized using the -D option which takes the path
to a logfile as an argument.

    $ oauth2-clientd [other options] -D /path/to/logfile /path/to/authfile


## Security

The tokens are kept secure on disk using AES encryption.  Each time the
tokens are written, a new key is generated, and encrypted with the RSA
public key generated during the authorize step.  The password for the private
key is used during startup to unlock the saved tokens and is unused after
that.  The refresh token is kept in memory but never written to disk in
unencrypted form.  The access token is available in plaintext but should
be configured with a short expiration time.

## Client IDs

A client ID and optional secret is required for oauth2-clientd to
successfully authenticate via OAUTH2.

### Office 365

For corporate Office 365, your administrator will have to add a client ID
to your organization's Active Directory instance.

### Outlook.com personal accounts

Outlook.com personal accounts are not supported yet and need more research.

### Gmail and Google Workspace

For personal Gmail accounts, you'll need to register this application
as a valid application in the Google Cloud Platform [Console](https://console.cloud.google.com/apis/credentials).  The same applies to Workspace domains
but your account must have administrative privileges to do it.

If you haven't used this service prior to configuring these Client IDs, you'll
have to accept the terms of service and create a new project (or use an
existing one).

Once the project is created, select it and go to the APIs [pane](https://console.cloud.google.com/apis).

There, you'll need to configure the "OAuth Consent Screen" first.

You'll need to choose a user type. `External` will work for the purposes
of setting up the client IDs for this use.  Next you'll enter a workflow:

- (1) OAuth Consent Screen
  - App Information
    -  App name: `<oauth2-clientd>` -- This is for your own reference
    -  User support email: `<this will be a pull down of your registered email addresses or groups>`
    -  App logo: (optional)

  - App domain (optional)
  - Authorized domains (optional)
  - Developer contact information `<same email address as above>`

- (2) Scopes
  - Click on _Add or remove scopes_
  - Manually add scopes
    - `https://mail.google.com`

- (3) Test Users
  - Click on _Add users_
  - Add your gmail address


Next select the _Credentials_ pane.

Click _+ CREATE CREDENTIALS_ and select _OAuth Client ID_.  The
application type will be _Web Application._  Once you select it, a number
of other fields will appear.  The _Name_ field is for you to be able to
identify the client ID later and can be whatever you like.  Click
_+ Add URI_ under the _Authorized redirect URIs_ heading and add
`http://localhost` before clicking _Create_.  Once you've created it,
it will display the client ID and secret.  These will be available via
the Credentials console for you to reference in the future.

Once you have the client ID and secret, you can establish your tokens using

    $ oauth2-clientd -P google -c <clientid> -a /path/to/sessionfile

and then following the instructions under [Getting Started][#Getting-Started].
