package signedkeys

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
	"hash"
)

// Verifier returns true if the signature is valid for the given key or false otherwise.
type Verifier func(key []byte, signature []byte) bool

// NoopVerifier returns a noop verifier which will always return true, no matter the key and signature given.
func NoopVerifier() Verifier {
	return func(_ []byte, _ []byte) bool {
		return true
	}
}

// HmacVerifier verifies the given signature using the hmac hashing. It accepts a hash method like sha1.New, the signing
// key to be used and a prefix length which is used to cap the signature at the first x bytes (this reduces the overall
// length of the keys). If no signature capping is wished, prefixLength can just be set to -1. Note that the prefixLength
// must match the one set in the HmacSigner or the validation will fail.
func HmacVerifier(h func() hash.Hash, signingKey []byte, prefixLength int) Verifier {
	return func(key []byte, signature []byte) bool {
		hmacSigner := hmac.New(h, signingKey)
		hmacSigner.Write(key)
		resSig := hmacSigner.Sum(nil)
		if prefixLength <= 0 || prefixLength >= len(resSig) {
			return subtle.ConstantTimeCompare(resSig, signature) == 1
		}

		return subtle.ConstantTimeCompare(resSig[:prefixLength], signature) == 1
	}
}

// Ed25519Verifier verifies a key's signature using an ed25519.PublicKey.
// Note this method will panic if the public key is not ed25519.PublicKeySize bytes long, rather than on every
// verification as ed25519.Verify would.
func Ed25519Verifier(publicKey ed25519.PublicKey) Verifier {
	if len(publicKey) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("ed25519 public key must be %d bytes long, got %d", ed25519.PublicKeySize, len(publicKey)))
	}

	return func(key []byte, signature []byte) bool {
		return ed25519.Verify(publicKey, key, signature)
	}
}
