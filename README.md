# gencert
Generates a self-signed CA and then uses it to
sign a new certificate. The files produced are:
`ca-key.pem` - CA's private key
`cacert.pem` - CA's certificate
`cert.pem` - certificate corresponding to `key.pem` signed with the CA above
`key.pem` - generated private key

This sample ode is based on the snippet https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
published with a permissive (Public Domain) License.

