# File Formats

## Access Token

The access token written to the output file or published via the UNIX socket is unmodified from the token received from the provider (i.e. unencrypted).  The format of the token itself is defined by the provider.  [RFC 6749](https://tools.ietf.org/html/rfc6749#page-10) describes the access token as "a string presenting an authorization issued to the client.  The string is usually opaque to the client."

## Session File

The session file is stored in JSON format using utf-8 encoding.  It consists of four top-level variables:
* `cryptoparams`
	* The cryptographic parameters required to access the information contained in the `data` field.
	* `algo` - The algorithm used to encrypt the data, currently only `"AES"` is supported.
	* `mode` - The cipher mode used to encrypt the data, currently only `"CTR"` is supported.
	* `key` - The key used to encrypt the data, itself encrypted using the RSA public key below then encoded as base64.
	* Different algorithms and modes will use different fields to describe their additional input. AES-CTR requires:
		* `nonce` - The nonce used to initialize the cipher encoded as base64.
* `data`- The session dictionary serialized as a JSON document, encrypted using the parameters above and encoded as base64.
	* `client`- The client information used when establishing the refresh token.
		* `client_id` - The client ID presented to the server
		* `client_secret` - The client secret presented to the server (optional)
	* `registration` - The registration dictionary used when establishing the refresh token. It contains the URIs and other fields required to contact the OAUTH2 server.
	* `tokendata` - The token dictionary provided by oauthlib. The fields match the fields defined in [RFC 6749](https://tools.ietf.org/html/rfc6749).
* `private_key` - The RSA private key used to decrypt the cryptographic key described in `cryptoparams` encoded as base64.
* `public_key` - The RSA public key used to encrypt the cryptographic key described in `cryptoparams` encoded as base64.
