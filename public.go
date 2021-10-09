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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type PublicKey []byte

// A KeyPair from a public key capable of verifying only.
type pub struct {
	pre PrefixByte
	pub PublicKey
}

// PublicKey will return the encoded public key associated with the KeyPair.
// All KeyPairs have a public key.
func (p *pub) PublicKey() (string, error) {
	pk, err := Encode(p.pre, p.pub)
	if err != nil {
		return "", err
	}
	return string(pk), nil
}

// Seed will return an error since this is not available for public key only KeyPairs.
func (p *pub) Seed() ([]byte, error) {
	return nil, ErrPublicKeyOnly
}

// PrivateKey will return an error since this is not available for public key only KeyPairs.
func (p *pub) PrivateKey() ([]byte, error) {
	return nil, ErrPublicKeyOnly
}

// Sign will return an error since this is not available for public key only KeyPairs.
func (p *pub) Sign(input []byte) ([]byte, error) {
	return nil, ErrCannotSign
}

// Verify will verify the input against a signature utilizing the public key.
func (p *pub) Verify(input []byte, sig []byte) error {
	x, y := elliptic.Unmarshal(secp256k1.S256(), p.pub)
	publicKey := ecdsa.PublicKey{secp256k1.S256(), x, y}
	h := md5.New()
	io.WriteString(h, string(input))
	signhash := h.Sum(nil)

	r := big.NewInt(0)
	r.SetBytes(sig[:32])
	s := big.NewInt(0)
	s.SetBytes(sig[32:])

	if !ecdsa.Verify(&publicKey, signhash, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// Wipe will randomize the public key and erase the pre byte.
func (p *pub) Wipe() {
	p.pre = '0'
	io.ReadFull(rand.Reader, p.pub)
}
