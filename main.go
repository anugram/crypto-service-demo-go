package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

type ProtectRevealRequest struct {
	Data     string `json:"data"`
	Username string `json:"username"`
}

type ProtectRevealResponse struct {
	Result string `json:"result"`
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
	http.HandleFunc("/protect", protectHandler)
	http.HandleFunc("/reveal", revealHandler)

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

func protectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	// Read the body of the incoming request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Unmarshal the JSON into a map to modify it
	var crdpProtectPayload map[string]interface{}
	if err := json.Unmarshal(body, &crdpProtectPayload); err != nil {
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}

	// Add CRDP protection policy to payload
	crdpProtectPayload["protection_policy_name"] = "demo"

	// Marshal payload back to JSON
	payload, err := json.Marshal(crdpProtectPayload)
	if err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
		return
	}

	// Create a new CRDP protect request
	protectAPIReq, err := http.NewRequest("POST", "http://crdp-service:8090/v1/protect", bytes.NewBuffer(payload))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	protectAPIReq.Header.Set("Content-Type", "application/json")

	// Forward the request
	client := &http.Client{}
	resp, err := client.Do(protectAPIReq)
	if err != nil {
		http.Error(w, "Failed to send request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func revealHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract Basic Auth credentials from the request header
	username, _, ok := r.BasicAuth()
	if !ok || username == "" {
		http.Error(w, "Missing or invalid Basic Auth credentials", http.StatusUnauthorized)
		return
	}

	// Read the body of the incoming request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Unmarshal the JSON into a map to modify it
	var crdpRevealPayload map[string]interface{}
	if err := json.Unmarshal(body, &crdpRevealPayload); err != nil {
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}

	// Add CRDP protection policy to payload
	crdpRevealPayload["protection_policy_name"] = "demo"
	crdpRevealPayload["protected_data"] = crdpRevealPayload["data"]
	crdpRevealPayload["username"] = username
	delete(crdpRevealPayload, "data")

	// Marshal payload back to JSON
	payload, err := json.Marshal(crdpRevealPayload)
	if err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
		return
	}

	// Create a new CRDP protect request
	protectAPIReq, err := http.NewRequest("POST", "http://crdp-service:8090/v1/reveal", bytes.NewBuffer(payload))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	protectAPIReq.Header.Set("Content-Type", "application/json")

	// Forward the request
	client := &http.Client{}
	resp, err := client.Do(protectAPIReq)
	if err != nil {
		http.Error(w, "Failed to send request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}
