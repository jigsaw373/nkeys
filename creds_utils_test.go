package nkeys

import (
	"bytes"
	"testing"
)

func Test_ParseDecoratedJWTBad(t *testing.T) {
	v, err := ParseDecoratedJWT([]byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if v != "foo" {
		t.Fatal("unexpected input was not returned")
	}
}

func Test_ParseDecoratedSeedBad(t *testing.T) {
	if _, err := ParseDecoratedNKey([]byte("foo")); err == nil {
		t.Fatal("Expected error")
	} else if err.Error() != "no nkey seed found" {
		t.Fatal(err)
	}
}

const (
	credsSeed      = `5355f2c11f75e1e582c12e0077c77a80c51a7daed05dde32c181248d564696e94b859b744f17e68f5d7cf268d60abbc2788ab98fccf135c2e1bc4f37b99918b0d8b92e29f76d1db84e51155526500dc323d75165a5332602660b3149293a5fd3a841daea77d152a0eed37c46c58cd15cca14b08011734a49a50b4589daeb37f9d50c711d72ba830cba228bec6a662ff585db2efec55f738196999e3d5f46a10bd0949c09e4d6c115b77c37fe7f209f3e9c3315fbfce30497b7d3ecdc04581c6be3423a68fce0433b79bbfc46fbe0c7c0f2c15a758ad38288e43e9ee7731fbeb62e4c1305bf389d880cbed997a64c51d7fb5d1fbb557ece91f9195e5c5fd6e21d34489cde`
	credsJwt       = `eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJHVDROVU5NRUY3Wk1XQ1JCWFZWVURLUVQ2WllQWjc3VzRKUlFYRDNMMjRIS1VKRUNRSDdRIiwiaWF0IjoxNTkwNzgxNTkzLCJpc3MiOiJBQURXTFRISUNWNFNVQUdGNkVLTlZFVzVCQlA3WVJESUJHV0dHSFo1SkJET1FZQTdHVUZNNkFRVSIsIm5hbWUiOiJPUEVSQVRPUiIsInN1YiI6IlVERTZXVEdMVFRQQ1JKUkpDS0JKUkdWTlpUTElWUjdMRUVFTFI0Q1lXV1dCS0pTN1hZSUtYRFVVIiwibmF0cyI6eyJwdWIiOnt9LCJzdWIiOnt9LCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.c_XQT04wEoVVNDRjPHeKwe17BOrSpQTcftwIbB7KoNEIz6peZCJDc4-J3emVepHofUOWy7IAo9TlLwYhuGHWAQ`
	decoratedCreds = `-----BEGIN NATS USER JWT-----
eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJHVDROVU5NRUY3Wk1XQ1JCWFZWVURLUVQ2WllQWjc3VzRKUlFYRDNMMjRIS1VKRUNRSDdRIiwiaWF0IjoxNTkwNzgxNTkzLCJpc3MiOiJBQURXTFRISUNWNFNVQUdGNkVLTlZFVzVCQlA3WVJESUJHV0dHSFo1SkJET1FZQTdHVUZNNkFRVSIsIm5hbWUiOiJPUEVSQVRPUiIsInN1YiI6IlVERTZXVEdMVFRQQ1JKUkpDS0JKUkdWTlpUTElWUjdMRUVFTFI0Q1lXV1dCS0pTN1hZSUtYRFVVIiwibmF0cyI6eyJwdWIiOnt9LCJzdWIiOnt9LCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.c_XQT04wEoVVNDRjPHeKwe17BOrSpQTcftwIbB7KoNEIz6peZCJDc4-J3emVepHofUOWy7IAo9TlLwYhuGHWAQ
------END NATS USER JWT------

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
5355f2c11f75e1e582c12e0077c77a80c51a7daed05dde32c181248d564696e94b859b744f17e68f5d7cf268d60abbc2788ab98fccf135c2e1bc4f37b99918b0d8b92e29f76d1db84e51155526500dc323d75165a5332602660b3149293a5fd3a841daea77d152a0eed37c46c58cd15cca14b08011734a49a50b4589daeb37f9d50c711d72ba830cba228bec6a662ff585db2efec55f738196999e3d5f46a10bd0949c09e4d6c115b77c37fe7f209f3e9c3315fbfce30497b7d3ecdc04581c6be3423a68fce0433b79bbfc46fbe0c7c0f2c15a758ad38288e43e9ee7731fbeb62e4c1305bf389d880cbed997a64c51d7fb5d1fbb557ece91f9195e5c5fd6e21d34489cde
------END USER NKEY SEED------

*************************************************************
`
)

func Test_ParseDecoratedSeedAndJWT(t *testing.T) {
	// test with and without \r\n
	for _, creds := range [][]byte{[]byte(decoratedCreds),
		bytes.ReplaceAll([]byte(decoratedCreds), []byte{'\n'}, []byte{'\r', '\n'})} {
		kp, err := ParseDecoratedUserNKey(creds)
		if err != nil {
			t.Fatal(err)
		}
		pu, err := kp.Seed()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pu, []byte(credsSeed)) {
			t.Fatal("seeds don't match")
		}

		kp, err = ParseDecoratedNKey(creds)
		if err != nil {
			t.Fatal(err)
		}
		pu, err = kp.Seed()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pu, []byte(credsSeed)) {
			t.Fatal("seeds don't match")
		}

		jwt, err := ParseDecoratedJWT(creds)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte(jwt), []byte(credsJwt)) {
			t.Fatal("jwt don't match")
		}
	}
}
