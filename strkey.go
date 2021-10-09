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
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
)

// PrefixByte is a lead byte representing the type.
type PrefixByte byte

const (
	PrefixByteSeed PrefixByte = 'S'

	PrefixBytePrivate PrefixByte = 'P'

	PrefixByteServer PrefixByte = 'N'

	PrefixByteCluster PrefixByte = 'C'

	PrefixByteOperator PrefixByte = 'O'

	PrefixByteAccount PrefixByte = 'A'

	PrefixByteUser PrefixByte = 'U'

	PrefixByteUnknown PrefixByte = 'X'

	SeedLength = 256
)

// Set our encoding to not include padding '=='
var b32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// Encode will encode a raw key or seed with the prefix and crc16 and then base32 encoded.
func Encode(prefix PrefixByte, src []byte) ([]byte, error) {
	if err := checkValidPrefixByte(prefix); err != nil {
		return nil, err
	}

	var raw bytes.Buffer

	// write prefix byte
	if err := raw.WriteByte(byte(prefix)); err != nil {
		return nil, err
	}

	// write payload
	if _, err := raw.Write(src); err != nil {
		return nil, err
	}

	// Calculate and write crc16 checksum
	err := binary.Write(&raw, binary.LittleEndian, crc16(raw.Bytes()))
	if err != nil {
		return nil, err
	}

	data := raw.Bytes()
	// change to hex
	buf := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(buf, data)
	return buf[:], nil
}

func EncodeSeed(public PrefixByte, src []byte) ([]byte, error) {

	if err := checkValidPublicPrefixByte(public); err != nil {
		return nil, err
	}

	if len(src) != SeedLength {
		return nil, ErrInvalidSeedLen
	}

	var raw bytes.Buffer

	raw.WriteByte(byte(PrefixByteSeed))
	raw.WriteByte(byte(public))

	// write payload
	if _, err := raw.Write(src); err != nil {
		return nil, err
	}

	// Calculate and write crc16 checksum
	err := binary.Write(&raw, binary.LittleEndian, crc16(raw.Bytes()))
	if err != nil {
		return nil, err
	}

	data := raw.Bytes()
	buf := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(buf, data)
	return buf, nil
}

// IsValidEncoding will tell you if the encoding is a valid key.
func IsValidEncoding(src []byte) bool {
	_, err := decode(src)
	return err == nil
}

// decode will decode the hex and check crc16 and the prefix for validity.
func decode(src []byte) ([]byte, error) {
	raw := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(raw, src)
	if err != nil {
		return nil, err
	}
	raw = raw[:n]

	if len(raw) < 4 {
		return nil, ErrInvalidEncoding
	}

	var crc uint16
	checksum := bytes.NewReader(raw[len(raw)-2:])
	if err := binary.Read(checksum, binary.LittleEndian, &crc); err != nil {
		return nil, err
	}

	// ensure checksum is valid
	if err := validate(raw[0:len(raw)-2], crc); err != nil {
		return nil, err
	}

	return raw[:len(raw)-2], nil
}

// Decode will decode the base32 string and check crc16 and enforce the prefix is what is expected.
func Decode(expectedPrefix PrefixByte, src []byte) ([]byte, error) {
	if err := checkValidPrefixByte(expectedPrefix); err != nil {
		return nil, err
	}
	raw, err := decode(src)
	if err != nil {
		return nil, err
	}
	if prefix := PrefixByte(raw[0]); prefix != expectedPrefix {
		return nil, ErrInvalidPrefixByte
	}
	return raw[1:], nil
}

// DecodeSeed will decode the hex string and check crc16 and enforce the prefix is a seed
// and the subsequent type is a valid type.
func DecodeSeed(src []byte) (PrefixByte, []byte, error) {
	raw, err := decode(src)
	if err != nil {
		return PrefixByteSeed, nil, err
	}
	b1 := raw[0]
	b2 := raw[1]

	if PrefixByte(b1) != PrefixByteSeed {
		return PrefixByteSeed, nil, ErrInvalidSeed
	}
	if checkValidPublicPrefixByte(PrefixByte(b2)) != nil {
		return PrefixByteSeed, nil, ErrInvalidSeed
	}
	return PrefixByte(b2), raw[2:], nil
}

// Prefix returns PrefixBytes of its input
func Prefix(src string) PrefixByte {
	b, err := decode([]byte(src))
	if err != nil {
		return PrefixByteUnknown
	}
	prefix := PrefixByte(b[0])
	err = checkValidPrefixByte(prefix)
	if err == nil {
		return prefix
	}
	// Might be a seed.
	b1 := b[0] & 248
	if PrefixByte(b1) == PrefixByteSeed {
		return PrefixByteSeed
	}
	return PrefixByteUnknown
}

// IsValidPublicKey will decode and verify that the string is a valid encoded public key.
func IsValidPublicKey(src string) bool {
	b, err := decode([]byte(src))
	if err != nil {
		return false
	}
	if prefix := PrefixByte(b[0]); checkValidPublicPrefixByte(prefix) != nil {
		return false
	}
	return true
}

// IsValidPublicUserKey will decode and verify the string is a valid encoded Public User Key.
func IsValidPublicUserKey(src string) bool {
	_, err := Decode(PrefixByteUser, []byte(src))
	return err == nil
}

// IsValidPublicAccountKey will decode and verify the string is a valid encoded Public Account Key.
func IsValidPublicAccountKey(src string) bool {
	_, err := Decode(PrefixByteAccount, []byte(src))
	return err == nil
}

// IsValidPublicServerKey will decode and verify the string is a valid encoded Public Server Key.
func IsValidPublicServerKey(src string) bool {
	_, err := Decode(PrefixByteServer, []byte(src))
	return err == nil
}

// IsValidPublicClusterKey will decode and verify the string is a valid encoded Public Cluster Key.
func IsValidPublicClusterKey(src string) bool {
	_, err := Decode(PrefixByteCluster, []byte(src))
	return err == nil
}

// IsValidPublicOperatorKey will decode and verify the string is a valid encoded Public Operator Key.
func IsValidPublicOperatorKey(src string) bool {
	_, err := Decode(PrefixByteOperator, []byte(src))
	return err == nil
}

// checkValidPrefixByte returns an error if the provided value
// is not one of the defined valid prefix byte constants.
func checkValidPrefixByte(prefix PrefixByte) error {
	switch prefix {
	case PrefixByteOperator, PrefixByteServer, PrefixByteCluster,
		PrefixByteAccount, PrefixByteUser, PrefixByteSeed, PrefixBytePrivate:
		return nil
	}
	return ErrInvalidPrefixByte
}

// checkValidPublicPrefixByte returns an error if the provided value
// is not one of the public defined valid prefix byte constants.
func checkValidPublicPrefixByte(prefix PrefixByte) error {
	switch prefix {
	case PrefixByteServer, PrefixByteCluster, PrefixByteOperator, PrefixByteAccount, PrefixByteUser:
		return nil
	}
	return ErrInvalidPrefixByte
}

func (p PrefixByte) String() string {
	switch p {
	case PrefixByteOperator:
		return "operator"
	case PrefixByteServer:
		return "server"
	case PrefixByteCluster:
		return "cluster"
	case PrefixByteAccount:
		return "account"
	case PrefixByteUser:
		return "user"
	case PrefixByteSeed:
		return "seed"
	case PrefixBytePrivate:
		return "private"
	}
	return "unknown"
}

// CompatibleKeyPair returns an error if the KeyPair doesn't match expected PrefixByte(s)
func CompatibleKeyPair(kp KeyPair, expected ...PrefixByte) error {
	pk, err := kp.PublicKey()
	if err != nil {
		return err
	}
	pkType := Prefix(pk)
	for _, k := range expected {
		if pkType == k {
			return nil
		}
	}

	return ErrIncompatibleKey
}
