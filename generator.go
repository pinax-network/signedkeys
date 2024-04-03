package signedkeys

const (
	// DefaultKeyLength specifies the default length for generated keys
	DefaultKeyLength = 16
)

type Generator struct {
	keyLength int
	rand      Rand
	encoder   Encoder
	decoder   Decoder
	signer    Signer
	verifier  Verifier
}

// NewGenerator returns a new key generator. If no options are specified, it will return a generator using the
// DefaultKeyLength, Secure random generator, NoopSigner, NoopVerifier and NoopEncoding.
func NewGenerator(options ...Option) *Generator {

	encoder, decoder := NoopEncoding()
	res := &Generator{
		keyLength: DefaultKeyLength,
		rand:      Secure(),
		encoder:   encoder,
		decoder:   decoder,
		signer:    NoopSigner(),
	}

	for _, o := range options {
		o(res)
	}

	return res
}

// GenerateKey generates a random key. It will contain a signature if WithSigner has been set and is going to be encoded
// based on the WithEncoding option.
func (g *Generator) GenerateKey() ([]byte, error) {

	res, err := g.rand(g.keyLength)
	if err != nil {
		return res, err
	}

	signature, err := g.signer(res)
	if err != nil {
		return res, err
	}

	return g.encoder(append(res, signature...)), nil
}

// VerifySignature returns true if the signature embedded in the key is valid. It uses the Verifier that has been
// set using the WithVerifier option.
func (g *Generator) VerifySignature(key []byte) bool {

	decodedKey, err := g.decoder(key)
	if err != nil {
		return false
	}

	return g.verifier(decodedKey[:g.keyLength], decodedKey[g.keyLength:])
}
