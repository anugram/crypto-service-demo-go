package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type EncryptionRequest struct {
	PlainText string `json:"plainText"`
}

type DecryptionRequest struct {
	EncryptedData string `json:"encryptedData"`
}

type EncryptionResponse struct {
	EncryptedData string `json:"encryptedData"`
}

type DecryptionResponse struct {
	DecryptedText string `json:"decryptedText"`
}

// Global variables for the AES key and IV
var key []byte
var iv []byte

func main() {
	// Generate a 256-bit (32 bytes) AES key
	var err error
	key, err = generateRandomBytes(32)
	if err != nil {
		log.Fatalf("Failed to generate AES key: %v", err)
	}

	// Generate a 16-byte IV
	iv, err = generateRandomBytes(16)
	if err != nil {
		log.Fatalf("Failed to generate IV: %v", err)
	}

	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler)
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

	encryptedData, err := encryptAES([]byte(req.PlainText), key, iv)
	if err != nil {
		http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	encodedData := base64.StdEncoding.EncodeToString(encryptedData)
	resp := EncryptionResponse{EncryptedData: encodedData}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DecryptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Decode the Base64 encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		http.Error(w, "Invalid encrypted data format", http.StatusBadRequest)
		return
	}

	decryptedData, err := decryptAES(encryptedData, key, iv)
	if err != nil {
		http.Error(w, "Decryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := DecryptionResponse{DecryptedText: string(decryptedData)}
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
