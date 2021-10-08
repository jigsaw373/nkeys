// Copyright 2018 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nkeys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/ed25519"
)

// kp is the internal struct for a kepypair using seed.
type kp struct {
	seed []byte
}

// CreatePair will create a KeyPair based on the rand entropy and a type/prefix byte. rand can be nil.
func CreatePair(prefix PrefixByte) (KeyPair, error) {
	var rawSeed [256]byte

	_, err := io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		return nil, err
	}

	seed, err := EncodeSeed(prefix, rawSeed[:])
	if err != nil {
		return nil, err
	}
	return &kp{seed}, nil
}

// rawSeed will return the raw, decoded 64 byte seed.
func (pair *kp) rawSeed() ([]byte, error) {
	_, raw, err := DecodeSeed(pair.seed)
	return raw, err
}

func (pair *kp) keys() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	raw, err := pair.rawSeed()
	if err != nil {
		return ecdsa.PublicKey{}, ecdsa.PrivateKey{}, err
	}
	keyCurve := secp256k1.S256()
	privatekey, err := ecdsa.GenerateKey(keyCurve, bytes.NewReader(raw))
	if err != nil {
		return ecdsa.PublicKey{}, ecdsa.PrivateKey{}, err
	}
	return privatekey.PublicKey, *privatekey, nil
}

// Wipe will randomize the contents of the seed key
func (pair *kp) Wipe() {
	io.ReadFull(rand.Reader, pair.seed)
	pair.seed = nil
}

// Seed will return the encoded seed.
func (pair *kp) Seed() ([]byte, error) {
	return pair.seed, nil
}

// PublicKey will return the encoded public key associated with the KeyPair.
// All KeyPairs have a public key.
func (pair *kp) PublicKey() (string, error) {
	public, raw, err := DecodeSeed(pair.seed)
	if err != nil {
		return "", err
	}
	keyCurve := secp256k1.S256()
	priv, err := ecdsa.GenerateKey(keyCurve, bytes.NewReader(raw))
	pub := priv.PublicKey
	if err != nil {
		return "", err
	}
	mPub := elliptic.Marshal(keyCurve, pub.X, pub.Y)
	pk, err := Encode(public, mPub)
	if err != nil {
		return "", err
	}
	return string(pk), nil
}

// PrivateKey will return the encoded private key for KeyPair.
func (pair *kp) PrivateKey() ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return Encode(PrefixBytePrivate, priv.D.Bytes())
}

// Sign will sign the input with KeyPair's private key.
func (pair *kp) Sign(input []byte) ([]byte, error) {
	_, priv, err := pair.keys()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, input), nil
}

// Verify will verify the input against a signature utilizing the public key.
func (pair *kp) Verify(input []byte, sig []byte) error {
	pub, _, err := pair.keys()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, input, sig) {
		return ErrInvalidSignature
	}
	return nil
}
