# Signed Keys

This Go library generates, signs, validates and encodes keys, such as api keys for example. This allows such keys to be 
pre-validated in a fast and cheap way. An exemplary use case could be high throughput API endpoints that might not
easily be rate-limited, but you still want to prevent bad actors from overloading your database by spamming requests
with random api keys.

```
go get github.com/pinax-network/signedkeys
```

## Example usage

```
package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/pinax-network/signedkeys"
)

var keyGen *signedkeys.Generator

func init() {
	// initializes a new key generator using
	keyGen = signedkeys.NewGenerator(
		signedkeys.WithRand(signedkeys.Secure()), // a secure random generator for the key generation from crypto/rand (this is the default)
		signedkeys.WithKeyLength(12), // a key length of 12 bytes
		signedkeys.WithSigner(signedkeys.HmacSigner(sha1.New, []byte("my_secret"), 8)), // a signer that adds an 8-byte hmac signature using sha1 hashes and "my_secret" as secret
		signedkeys.WithVerifier(signedkeys.HmacVerifier(sha1.New, []byte("my_secret"), 8)), // the appropriate hmac validator with the same settings as the signer
		signedkeys.WithEncoding(signedkeys.HexEncoding()), // hexadecimal encoding for the resulting key + signature
	)
}

func main() {

	// generates a new key
	key, err := keyGen.GenerateKey()
	if err != nil {
		panic(err)
	}
	fmt.Printf("generated key: %s\n", key)

	// use the key generator to validate the keys signature
	valid := keyGen.VerifySignature(key)
	fmt.Printf("is valid: %t\n", valid)
}
```
