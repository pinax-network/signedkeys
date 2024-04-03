package signedkeys

import "crypto/rand"

// Rand returns a random byte array in the given length.
type Rand func(int) ([]byte, error)

// Secure returns a Rand that generates a securely random byte array using crypto/rand.
func Secure() Rand {
	return func(length int) ([]byte, error) {
		res := make([]byte, length)
		if _, err := rand.Read(res); err != nil {
			return res, err
		}
		return res, nil
	}
}
