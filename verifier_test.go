package signedkeys

import (
	"crypto/ed25519"
	"testing"
)

func TestEd25519Verifier_InvalidPublicKey(t *testing.T) {

	// a public key of the wrong length must be refused when the verifier is created, not on every verification
	for _, publicKey := range []ed25519.PublicKey{nil, []byte("short"), make([]byte, ed25519.PublicKeySize+1)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Ed25519Verifier(%d byte key) did not panic", len(publicKey))
				}
			}()
			Ed25519Verifier(publicKey)
		}()
	}
}
