package signedkeys

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDecoder_GenerateSecureKey(t *testing.T) {

	// test the generator with the default setting doesn't error
	gen := NewGenerator()
	key, err := gen.GenerateKey()
	assert.NoError(t, err)
	assert.Equal(t, DefaultKeyLength, len(key))

	// from here on, we inject a mock rand to ensure we can test the actual results
	testKeyRand := func(length int) ([]byte, error) {
		return []byte("testkeylength_16"), nil
	}

	// test with mock rand
	gen = NewGenerator(WithRand(testKeyRand))
	key, err = gen.GenerateKey()
	assert.NoError(t, err)
	assert.Equal(t, DefaultKeyLength, len(key))
	assert.Equal(t, "testkeylength_16", string(key))

	// test the hex encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithEncoding(HexEncoding()),
	)
	key, err = gen.GenerateKey()
	assert.NoError(t, err)
	assert.Equal(t, "746573746b65796c656e6774685f3136", string(key))

	// test the base64 encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithEncoding(Base64Encoding()),
	)
	key, err = gen.GenerateKey()
	assert.NoError(t, err)
	assert.Equal(t, "dGVzdGtleWxlbmd0aF8xNg==", string(key))

	// test with hmac signature and hex encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(HmacSigner(sha256.New, []byte("test_signing_key"), -1)),
		WithVerifier(HmacVerifier(sha256.New, []byte("test_signing_key"), -1)),
		WithEncoding(HexEncoding()),
	)
	key, err = gen.GenerateKey()
	assert.NoError(t, err)
	// key is 746573746b65796c656e6774685f3136
	// hmac is 42876f7915ca22838f7718a18c072652a15d42f783afd2a46553c6d7e58a73fa
	assert.Equal(t, "746573746b65796c656e6774685f313642876f7915ca22838f7718a18c072652a15d42f783afd2a46553c6d7e58a73fa", string(key))

	valid := gen.VerifySignature(key)
	assert.Equal(t, true, valid)

	// test with hmac signature with prefix length and hex encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(HmacSigner(sha256.New, []byte("test_signing_key"), 12)),
		WithVerifier(HmacVerifier(sha256.New, []byte("test_signing_key"), 12)),
		WithEncoding(HexEncoding()),
	)
	key, err = gen.GenerateKey()
	assert.NoError(t, err)
	// key is 746573746b65796c656e6774685f3136
	// hmac is 42876f7915ca22838f7718a18c072652a15d42f783afd2a46553c6d7e58a73fa (capped at the first 12 bytes)
	assert.Equal(t, "746573746b65796c656e6774685f313642876f7915ca22838f7718a1", string(key))

	valid = gen.VerifySignature(key)
	assert.Equal(t, true, valid)

	// ensure we don't accept a shorter prefix
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(HmacSigner(sha256.New, []byte("test_signing_key"), 12)),
		WithVerifier(HmacVerifier(sha256.New, []byte("test_signing_key"), 10)),
		WithEncoding(HexEncoding()),
	)
	key, err = gen.GenerateKey()
	assert.NoError(t, err)
	// key is 746573746b65796c656e6774685f3136
	// hmac is 42876f7915ca22838f7718a18c072652a15d42f783afd2a46553c6d7e58a73fa (capped at the first 12 bytes)
	assert.Equal(t, "746573746b65796c656e6774685f313642876f7915ca22838f7718a1", string(key))

	valid = gen.VerifySignature(key)
	assert.Equal(t, false, valid)

	// test with hmac signature and base64 encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(HmacSigner(sha1.New, []byte("test_signing_key"), -1)),
		WithVerifier(HmacVerifier(sha1.New, []byte("test_signing_key"), -1)),
		WithEncoding(Base64Encoding()),
	)
	key, err = gen.GenerateKey()
	assert.NoError(t, err)

	assert.Equal(t, "dGVzdGtleWxlbmd0aF8xNpsqgAhQp5G9cGJ4jfMYTEY9y68r", string(key))

	valid = gen.VerifySignature(key)
	assert.Equal(t, true, valid)

	// test with ed25519 signature and hex encoding
	pubKey, err := hex.DecodeString("74b31ae07c26fd23d7008cbb38264c9e43e6325573c260f2331adca4eccba55f")
	assert.NoError(t, err)

	privKey, err := hex.DecodeString("c1ec13413449e3a715694433da83247e895d5cdecab8d787be4c9d3a2fa50c1d74b31ae07c26fd23d7008cbb38264c9e43e6325573c260f2331adca4eccba55f")
	assert.NoError(t, err)

	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(Ed25519Signer(privKey)),
		WithVerifier(Ed25519Verifier(pubKey)),
		WithEncoding(HexEncoding()),
	)
	key, err = gen.GenerateKey()
	assert.NoError(t, err)
	// key is 746573746b65796c656e6774685f3136
	// hmac is 59d676a27dfa5496097f0476f7646946f6dde9a03fcb5c94c19b66913587b02a0f898eb92ffe1707dad5597ded66e6d1877b8d11b1fb34f15dfb656ffdc7c808
	assert.Equal(t, "746573746b65796c656e6774685f313659d676a27dfa5496097f0476f7646946f6dde9a03fcb5c94c19b66913587b02a0f898eb92ffe1707dad5597ded66e6d1877b8d11b1fb34f15dfb656ffdc7c808", string(key))

	valid = gen.VerifySignature(key)
	assert.Equal(t, true, valid)

	// test with ed25519 signature and base64 encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(Ed25519Signer(privKey)),
		WithVerifier(Ed25519Verifier(pubKey)),
		WithEncoding(Base64Encoding()),
	)
	key, err = gen.GenerateKey()
	assert.NoError(t, err)
	assert.Equal(t, "dGVzdGtleWxlbmd0aF8xNlnWdqJ9+lSWCX8EdvdkaUb23emgP8tclMGbZpE1h7AqD4mOuS/+Fwfa1Vl97Wbm0Yd7jRGx+zTxXftlb/3HyAg=", string(key))

	valid = gen.VerifySignature(key)
	assert.Equal(t, true, valid)
}
