package signedkeys

type Option func(*Generator)

// WithKeyLength overrides the DefaultKeyLength used to define the byte length of a generated key.
// Note this method will panic if it receives a keyLength of zero or smaller.
func WithKeyLength(keyLength int) Option {
	if keyLength <= 0 {
		panic("default key length must be greater than zero")
	}

	return func(g *Generator) {
		g.keyLength = keyLength
	}
}

// WithRand allows setting a custom random generator.
func WithRand(rand Rand) Option {
	return func(g *Generator) {
		g.rand = rand
	}
}

// WithEncoding sets the given Encoder and Decoder to be used to handle key codings.
func WithEncoding(encoder Encoder, decoder Decoder) Option {
	return func(g *Generator) {
		g.encoder = encoder
		g.decoder = decoder
	}
}

// WithSigner sets a key signer.
func WithSigner(signer Signer) Option {
	return func(g *Generator) {
		g.signer = signer
	}
}

// WithVerifier sets a key verifier
func WithVerifier(verifier Verifier) Option {
	return func(g *Generator) {
		g.verifier = verifier
	}
}
