package signedkeys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"hash"
)

// Signer receives a key and returns a signature for it.
type Signer func(src []byte) ([]byte, error)

// NoopSigner returns a signer that just returns an empty byte array (no signature).
func NoopSigner() Signer {
	return func(_ []byte) ([]byte, error) {
		return []byte{}, nil
	}
}

// HmacSigner returns a signer that creates a hmac signature using the given hash function and signing key. If
// prefixLength is set to a value greater than 0, the signature will be capped. This can be used to shorten the overall
// key length, but reduces the security of the signing. Note that the prefixLength set must be the same as set in
// HmacVerifier.
func HmacSigner(h func() hash.Hash, signingKey []byte, prefixLength int) Signer {
	return func(src []byte) ([]byte, error) {
		hmacSigner := hmac.New(h, signingKey)
		hmacSigner.Write(src)
		res := hmacSigner.Sum(nil)
		if prefixLength > 0 && prefixLength < len(res) {
			res = res[:prefixLength]
		}

		return res, nil
	}
}

// Ed25519Signer returns a signer that signs a key with an ed25519.PrivateKey. It will not be hashed.
func Ed25519Signer(privateKey ed25519.PrivateKey) Signer {
	return func(src []byte) ([]byte, error) {
		return privateKey.Sign(rand.Reader, src, crypto.Hash(0))
	}
}
