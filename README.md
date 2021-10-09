# NKEYS

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![ReportCard](http://goreportcard.com/badge/nats-io/nkeys)](http://goreportcard.com/report/nats-io/nkeys)
[![Build Status](https://travis-ci.com/nats-io/nkeys.svg?branch=master)](http://travis-ci.com/nats-io/nkeys)
[![GoDoc](http://godoc.org/github.com/nats-io/nkeys?status.svg)](http://godoc.org/github.com/nats-io/nkeys)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/nkeys/badge.svg?branch=master&service=github)](https://coveralls.io/github/nats-io/nkeys?branch=master)

A public-key signature system based on [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)for the NATS ecosystem.

## About

The NATS ecosystem is now using [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1) to generate keys and perform authentication and authorization for entities such as Accounts, Users, Servers and Clusters.

the formulation that was used in the original NKEYS still remains. but keys are now encoded by hex encoding and the length of encoded strings are now different. off course the method of calculating the prefix bytes of keys is now different. 

by migrating from Ed25519 to Secp256k1, all of the traditional functions are still remain with their old arguments and return values so that as a user point of view, no change has to be done in client code.

the main libraries added in this migration, are : "crypto/ecdsa" and "crypto/elliptic", also the [crypto/secp256k1](github.com/ethereum/go-ethereum/crypto/secp256k1) is used to reterieve the curv variable for ECDSA.



## Installation

Use the `go` command:

	$ go get github.com/nats-io/nkeys

## nk - Command Line Utility

Located under the nk [directory](https://github.com/nats-io/nkeys/tree/master/nk).

## Basic API Usage
```go

// Create a new User KeyPair
user, _ := nkeys.CreateUser()

// Sign some data with a full key pair user.
data := []byte("Hello World")
sig, _ := user.Sign(data)

// Verify the signature.
err = user.Verify(data, sig)

// Access the seed, the only thing that needs to be stored and kept safe.
// seed = "5355f2c11f75e1e582c12e0077c77a80c51a7daed05dde32c181248d564696e94b859b744f17e68f5d7cf268d60abbc2788ab98fccf135c2e1bc4f37b99918b0d8b92e29f76d1db84e51155526500dc323d75165a5332602660b3149293a5fd3a841daea77d152a0eed37c46c58cd15cca14b08011734a49a50b4589daeb37f9d50c711d72ba830cba228bec6a662ff585db2efec55f738196999e3d5f46a10bd0949c09e4d6c115b77c37fe7f209f3e9c3315fbfce30497b7d3ecdc04581c6be3423a68fce0433b79bbfc46fbe0c7c0f2c15a758ad38288e43e9ee7731fbeb62e4c1305bf389d880cbed997a64c51d7fb5d1fbb557ece91f9195e5c5fd6e21d34489cde"
seed, _ := user.Seed()

// Access the public key which can be shared.
// publicKey = "55d38288e43e9e55f2c11f75e1e582c12e0077c77a80c51a7d..."
publicKey, _ := user.PublicKey()

// Create a full User who can sign and verify from a private seed.
user, _ = nkeys.FromSeed(seed)

// Create a User who can only verify signatures via a public key.
user, _ = nkeys.FromPublicKey(publicKey)

// Create a User KeyPair with our own random data.
var rawSeed [32]byte
_, err := io.ReadFull(rand.Reader, rawSeed[:])  // Or some other random source.
user2, _ := nkeys.FromRawSeed(PrefixByteUser, rawSeed)

```

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.

