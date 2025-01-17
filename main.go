package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type EncryptionRequest struct {
	PlainText string `json:"plainText"`
}

type EncryptionResponse struct {
	EncryptedData string `json:"encryptedData"`
}

func main() {
	http.HandleFunc("/encrypt", encryptHandler)
	fmt.Println("Starting server on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EncryptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	key := []byte("this_is_32bytes_long_aes_key!") // 32-byte key for AES-256
	iv := []byte("1234567890123456")               // 16-byte IV

	encryptedData, err := encryptAES([]byte(req.PlainText), key, iv)
	if err != nil {
		http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Encode the encrypted data in Base64
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	resp := EncryptionResponse{EncryptedData: encodedData}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

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

func pkcs5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}
