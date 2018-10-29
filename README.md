# HTTP Signature for Insomnia REST Client
This is a plugin for the [Insomnia REST Client](https://insomnia.rest/)

IETF Draft: https://tools.ietf.org/html/draft-cavage-http-signatures-10

## How to use
1. Set authentication type to Bearer Token
2. Set Prefix value to Signature
3. Set Token value to HTTP Signature template
4. Set Key ID value
5. Set Private Key value without headers (`-----BEGIN RSA PRIVATE KEY-----`,`-----END RSA PRIVATE KEY-----`) and new lines

![Screenshot](https://raw.githubusercontent.com/adnsio/insomnia-plugin-http-signature/master/screenshot.png)
