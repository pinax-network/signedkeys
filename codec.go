package signedkeys

import (
	"encoding/base64"
	"encoding/hex"
)

type Encoder func([]byte) []byte
type Decoder func([]byte) ([]byte, error)

// NoopEncoding is just a default noop encoder that returns the original byte array produced by the Generator.
func NoopEncoding() (Encoder, Decoder) {
	return func(src []byte) []byte {
			return src
		}, func(src []byte) ([]byte, error) {
			return src, nil
		}
}

// HexEncoding encodes the generated key into a hexadecimal byte array. The result can just be cast into a string to
// get a hex string.
func HexEncoding() (Encoder, Decoder) {
	return func(src []byte) []byte {
			res := make([]byte, hex.EncodedLen(len(src)))
			hex.Encode(res, src)
			return res
		}, func(src []byte) ([]byte, error) {
			res := make([]byte, len(src))
			n, err := hex.Decode(res, src)
			return res[:n], err
		}
}

// Base64Encoding encodes the generated key into a base64 byte array with standard encoding settings (using base64.StdEncoding).
// The result can just be cast into a string to get a valid base64 string.
func Base64Encoding() (Encoder, Decoder) {
	return func(src []byte) []byte {
			res := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
			base64.StdEncoding.Encode(res, src)
			return res
		}, func(src []byte) ([]byte, error) {
			res := make([]byte, len(src))
			n, err := base64.StdEncoding.Decode(res, src)
			return res[:n], err
		}
}
