# JWT Playground
Various tests regarding signing and verifying JWT tokens.

```shell
# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

Links:
* [Generate a keypair using OpenSSL](https://en.wikibooks.org/wiki/Cryptography/Generate_a_keypair_using_OpenSSL)
