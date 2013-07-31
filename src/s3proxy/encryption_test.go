package main

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"
)

func byteArrayEquals(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	equals := true

	for i := range a {
		if a[i] != b[i] {
			equals = false
			break
		}
	}

	return equals
}

func TestEncryption(t *testing.T) {
	bucketInfo := &BucketInfo{
		Config: &BucketConfig{
			EncryptionKey: "0123456789ABCDEF",
		},
	}

	bucketInfoWrongKey := &BucketInfo{
		Config: &BucketConfig{
			EncryptionKey: "WRONG_KEY_OH_NO!",
		},
	}

	payload := "The privilege of absurdity; to which no living creature is subject but man only."

	const NEncryptionRounds = 3
	encryptedPayloads := make([][]byte, NEncryptionRounds)

	// We use a random IV, so we should get different encrypted payloads for
	// each round
	for i := 0; i < NEncryptionRounds; i++ {
		// Encrypt
		encReader, _, err := SetupWriteEncryption(strings.NewReader(payload), bucketInfo)

		if err != nil {
			t.Fatalf("Error while setting up encryption: %s", err)
		}

		encryptedPayloads[i], err = ioutil.ReadAll(encReader)

		if err != nil {
			t.Fatalf("Error while encrypting data: %s", err)
		}

		encReader.Close()

		if i > 0 && byteArrayEquals(encryptedPayloads[i-1], encryptedPayloads[i]) {
			t.Fatalf("Two identical encrypted payloads for two different encryption rounds")
		}

		// Decrypt with correct key
		decReader, _, err := SetupReadEncryption(bytes.NewReader(encryptedPayloads[i]), bucketInfo)

		if err != nil {
			t.Fatalf("Error while setting up decryption: %s", err)
		}

		decryptedPayload, err := ioutil.ReadAll(decReader)

		if err != nil {
			t.Fatalf("Error while decrypting data: %s", err)
		}

		decReader.Close()

		if string(decryptedPayload) != payload {
			t.Fatalf("Decrypted payload does not match original (decrypted: '%s' original: '%s')", string(decryptedPayload), payload)
		}

		// Decrypt with incorrect key
		decReader, _, err = SetupReadEncryption(bytes.NewReader(encryptedPayloads[i]), bucketInfoWrongKey)

		if err != nil {
			t.Fatalf("Error while setting up decryption: %s", err)
		}

		decryptedPayload, err = ioutil.ReadAll(decReader)

		if err != nil {
			t.Fatalf("Error while decrypting data: %s", err)
		}

		decReader.Close()

		if string(decryptedPayload) == payload {
			t.Fatalf("Getting correct payload while decrypting with wrong key!")
		}
	}
}
