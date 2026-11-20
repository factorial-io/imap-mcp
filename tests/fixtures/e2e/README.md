# End-to-end test fixtures

Test-only key material for `tests/e2e.rs`. Never use these anywhere else.

- `ca.pem` — test CA; the server under test trusts it via `SSL_CERT_FILE`.
  Its private key was discarded after signing.
- `imap.pem`, `imap.key` — certificate (localhost, 127.0.0.1) and PKCS#8 key
  for the scripted IMAP server, issued by the test CA, valid for 100 years.
- `oidc-signing.pem` — PKCS#1 RSA key the mock OIDC provider signs ID tokens
  with.

Regenerate with:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.pem -days 36500 -subj "/CN=imap-mcp e2e test CA"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout imap.key.tmp -out imap.csr -subj "/CN=localhost"
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" > ext.cnf
openssl x509 -req -in imap.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out imap.pem -days 36500 -extfile ext.cnf
openssl pkcs8 -topk8 -nocrypt -in imap.key.tmp -out imap.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k.pem
openssl rsa -in k.pem -traditional -out oidc-signing.pem
rm -f ca.key ca.srl imap.key.tmp imap.csr ext.cnf k.pem
```
