package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
)

func SetupCipher(info *BucketInfo, ivReader io.Reader) (cipher.Block, []byte, error) {
	block, err := aes.NewCipher([]byte(info.Config.EncryptionKey))

	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, block.BlockSize())
	n, err := io.ReadFull(ivReader, iv)

	if n != len(iv) || err != nil {
		return nil, nil, fmt.Errorf("Cannot build IV: %s", err)
	}

	return block, iv, nil
}

func SetupReadEncryption(input io.Reader, info *BucketInfo) (io.ReadCloser, int64, error) {
	block, iv, err := SetupCipher(info, input)

	if err != nil {
		return nil, -1, err
	}

	decrypter := cipher.NewCFBDecrypter(block, iv[:])

	reader := &cipher.StreamReader{
		S: decrypter,
		R: input,
	}

	return ioutil.NopCloser(reader), int64(len(iv)), nil
}

func SetupWriteEncryption(input io.Reader, info *BucketInfo) (io.ReadCloser, int64, error) {
	block, iv, err := SetupCipher(info, rand.Reader)

	if err != nil {
		return nil, -1, err
	}

	ivReader := bytes.NewReader(iv)
	encrypter := cipher.NewCFBEncrypter(block, iv[:])

	reader := &cipher.StreamReader{
		S: encrypter,
		R: input,
	}

	return ioutil.NopCloser(io.MultiReader(ivReader, reader)), int64(len(iv)), nil
}
