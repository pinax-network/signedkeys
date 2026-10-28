package signedkeys

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDecoder_GenerateSecureKey(t *testing.T) {

	// test the generator with the default setting doesn't error
	gen := NewGenerator()
	key := generateKey(t, gen)
	if len(key) != DefaultKeyLength {
		t.Errorf("key length = %d, want %d", len(key), DefaultKeyLength)
	}

	// from here on, we inject a mock rand to ensure we can test the actual results
	testKeyRand := func(length int) ([]byte, error) {
		return []byte("testkeylength_16"), nil
	}

	// test with mock rand
	gen = NewGenerator(WithRand(testKeyRand))
	key = generateKey(t, gen)
	if len(key) != DefaultKeyLength {
		t.Errorf("key length = %d, want %d", len(key), DefaultKeyLength)
	}
	assertKey(t, key, "testkeylength_16")

	// test the hex encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithEncoding(HexEncoding()),
	)
	key = generateKey(t, gen)
	assertKey(t, key, "746573746b65796c656e6774685f3136")

	// test the base64 encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithEncoding(Base64Encoding()),
	)
	key = generateKey(t, gen)
	assertKey(t, key, "dGVzdGtleWxlbmd0aF8xNg==")

	// test with hmac signature and hex encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(HmacSigner(sha256.New, []byte("test_signing_key"), -1)),
		WithVerifier(HmacVerifier(sha256.New, []byte("test_signing_key"), -1)),
		WithEncoding(HexEncoding()),
	)
	key = generateKey(t, gen)
	// key is 746573746b65796c656e6774685f3136
	// hmac is 42876f7915ca22838f7718a18c072652a15d42f783afd2a46553c6d7e58a73fa
	assertKey(t, key, "746573746b65796c656e6774685f313642876f7915ca22838f7718a18c072652a15d42f783afd2a46553c6d7e58a73fa")
	assertSignature(t, gen, key, true)

	// test with hmac signature with prefix length and hex encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(HmacSigner(sha256.New, []byte("test_signing_key"), 12)),
		WithVerifier(HmacVerifier(sha256.New, []byte("test_signing_key"), 12)),
		WithEncoding(HexEncoding()),
	)
	key = generateKey(t, gen)
	// key is 746573746b65796c656e6774685f3136
	// hmac is 42876f7915ca22838f7718a18c072652a15d42f783afd2a46553c6d7e58a73fa (capped at the first 12 bytes)
	assertKey(t, key, "746573746b65796c656e6774685f313642876f7915ca22838f7718a1")
	assertSignature(t, gen, key, true)

	// ensure we don't accept a shorter prefix
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(HmacSigner(sha256.New, []byte("test_signing_key"), 12)),
		WithVerifier(HmacVerifier(sha256.New, []byte("test_signing_key"), 10)),
		WithEncoding(HexEncoding()),
	)
	key = generateKey(t, gen)
	// key is 746573746b65796c656e6774685f3136
	// hmac is 42876f7915ca22838f7718a18c072652a15d42f783afd2a46553c6d7e58a73fa (capped at the first 12 bytes)
	assertKey(t, key, "746573746b65796c656e6774685f313642876f7915ca22838f7718a1")
	assertSignature(t, gen, key, false)

	// test with hmac signature and base64 encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(HmacSigner(sha1.New, []byte("test_signing_key"), -1)),
		WithVerifier(HmacVerifier(sha1.New, []byte("test_signing_key"), -1)),
		WithEncoding(Base64Encoding()),
	)
	key = generateKey(t, gen)
	assertKey(t, key, "dGVzdGtleWxlbmd0aF8xNpsqgAhQp5G9cGJ4jfMYTEY9y68r")
	assertSignature(t, gen, key, true)

	// test with ed25519 signature and hex encoding
	pubKey, err := hex.DecodeString("74b31ae07c26fd23d7008cbb38264c9e43e6325573c260f2331adca4eccba55f")
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}

	privKey, err := hex.DecodeString("c1ec13413449e3a715694433da83247e895d5cdecab8d787be4c9d3a2fa50c1d74b31ae07c26fd23d7008cbb38264c9e43e6325573c260f2331adca4eccba55f")
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(Ed25519Signer(privKey)),
		WithVerifier(Ed25519Verifier(pubKey)),
		WithEncoding(HexEncoding()),
	)
	key = generateKey(t, gen)
	// key is 746573746b65796c656e6774685f3136
	// hmac is 59d676a27dfa5496097f0476f7646946f6dde9a03fcb5c94c19b66913587b02a0f898eb92ffe1707dad5597ded66e6d1877b8d11b1fb34f15dfb656ffdc7c808
	assertKey(t, key, "746573746b65796c656e6774685f313659d676a27dfa5496097f0476f7646946f6dde9a03fcb5c94c19b66913587b02a0f898eb92ffe1707dad5597ded66e6d1877b8d11b1fb34f15dfb656ffdc7c808")
	assertSignature(t, gen, key, true)

	// test with ed25519 signature and base64 encoding
	gen = NewGenerator(
		WithRand(testKeyRand),
		WithSigner(Ed25519Signer(privKey)),
		WithVerifier(Ed25519Verifier(pubKey)),
		WithEncoding(Base64Encoding()),
	)
	key = generateKey(t, gen)
	assertKey(t, key, "dGVzdGtleWxlbmd0aF8xNlnWdqJ9+lSWCX8EdvdkaUb23emgP8tclMGbZpE1h7AqD4mOuS/+Fwfa1Vl97Wbm0Yd7jRGx+zTxXftlb/3HyAg=")
	assertSignature(t, gen, key, true)
}

func TestGenerator_GenerateKeyRandLength(t *testing.T) {

	// a random generator returning the wrong number of bytes must fail the generation, as the key could never be verified
	for _, length := range []int{0, DefaultKeyLength - 1, DefaultKeyLength + 1} {
		gen := NewGenerator(
			WithRand(func(int) ([]byte, error) { return make([]byte, length), nil }),
			WithSigner(HmacSigner(sha1.New, []byte("test_signing_key"), 8)),
			WithVerifier(HmacVerifier(sha1.New, []byte("test_signing_key"), 8)),
		)
		if key, err := gen.GenerateKey(); err == nil {
			t.Errorf("GenerateKey() with a %d byte random generator returned %q, want an error", length, key)
		}
	}
}

func TestGenerator_VerifySignatureShortKey(t *testing.T) {

	// keys that decode to fewer than keyLength bytes must be rejected instead of panicking
	hexGen := NewGenerator(
		WithVerifier(HmacVerifier(sha1.New, []byte("test_signing_key"), 8)),
		WithEncoding(HexEncoding()),
	)
	for _, key := range []string{"", "ab", "abcd", "00112233445566", "0011223344556677", "00112233445566778899aabbccddee"} {
		assertSignature(t, hexGen, []byte(key), false)
	}

	base64Gen := NewGenerator(
		WithVerifier(HmacVerifier(sha1.New, []byte("test_signing_key"), 8)),
		WithEncoding(Base64Encoding()),
	)
	for _, key := range []string{"", "YQ==", "dGVzdGtleQ=="} {
		assertSignature(t, base64Gen, []byte(key), false)
	}

	noopGen := NewGenerator(WithVerifier(HmacVerifier(sha1.New, []byte("test_signing_key"), 8)))
	for _, key := range []string{"", "short"} {
		assertSignature(t, noopGen, []byte(key), false)
	}
}

func generateKey(t *testing.T, gen *Generator) []byte {
	t.Helper()

	key, err := gen.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	return key
}

func assertKey(t *testing.T, key []byte, want string) {
	t.Helper()

	if string(key) != want {
		t.Errorf("key = %q, want %q", key, want)
	}
}

// assertSignature checks the result of VerifySignature and reports a panic as a failure of its own,
// so that one panicking key does not abort the remaining checks.
func assertSignature(t *testing.T, gen *Generator, key []byte, want bool) {
	t.Helper()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("VerifySignature(%q) panicked: %v", key, recovered)
		}
	}()

	if got := gen.VerifySignature(key); got != want {
		t.Errorf("VerifySignature(%q) = %t, want %t", key, got, want)
	}
}
