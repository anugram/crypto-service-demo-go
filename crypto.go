package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func encryptAES(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedData := pkcs5Padding(plaintext, block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(paddedData))
	mode.CryptBlocks(encrypted, paddedData)

	return encrypted, nil
}

func decryptAES(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return pkcs5Unpadding(decrypted)
}

func pkcs5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs5Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("decrypted data is empty")
	}

	padding := int(data[length-1])
	if padding > length {
		return nil, fmt.Errorf("invalid padding size")
	}

	return data[:length-padding], nil
}

func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func forwardRequest(url string, req ProtectRevealRequest) ([]byte, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpResp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	return respBody, nil
}
