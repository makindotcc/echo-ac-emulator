package main

import (
	"bytes"
	"encoding/ascii85"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/andybalholm/brotli"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <token>\n", os.Args[0])
		os.Exit(1)
	}

	hwid := "9332b0189f9d3a56b8c61688a8b30020"
	scanFile := "./solution.json"
	token := os.Args[1]

	auth := fmt.Sprintf("%s <[%%%%%s%%%%]>", token, hwid)

	client := &http.Client{}

	// Step 1: POST /tool/scan/progress
	progressBody := []byte(`{"percent":2,"stage":0,"text":"Scanning processes..."}`)
	req, err := http.NewRequest("POST", "https://api.echo.ac/tool/scan/progress", bytes.NewReader(progressBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating progress request: %v\n", err)
		os.Exit(1)
	}
	setCommonHeaders(req, auth)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "progress request failed: %v\n", err)
		os.Exit(1)
	}
	io.Copy(io.Discard, resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading progress response: %v\n", err)
		os.Exit(1)
	}
	resp.Body.Close()
	fmt.Fprintf(os.Stderr, "Devirtualizing modules\n")

	if resp.StatusCode != http.StatusNoContent {
		fmt.Fprintf(os.Stderr, "progress request returned non-204: %s %s\n", resp.Status, body)
		os.Exit(1)
	}

	// Step 2: GET /tool/uploadUrl
	req, err = http.NewRequest("GET", "https://api.echo.ac/tool/uploadUrl", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating uploadUrl request: %v\n", err)
		os.Exit(1)
	}
	setCommonHeaders(req, auth)

	resp, err = client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "uploadUrl request failed: %v\n", err)
		os.Exit(1)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading uploadUrl response: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "uploadUrl request returned non-200: %s %s\n", resp.Status, body)
		os.Exit(1)
	}
	defer resp.Body.Close()
	fmt.Fprintf(os.Stderr, "dumping millionware...\n")

	var uploadResp struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&uploadResp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse uploadUrl response: %v\n", err)
		os.Exit(1)
	}
	// fmt.Fprintf(os.Stderr, "upload URL: %s\n", uploadResp.URL)
	fmt.Fprintf(os.Stderr, "echoac.sys screenshot blocked\n")

	// Step 3: Encode scan data and PUT to presigned URL
	scanJSON, err := os.ReadFile(scanFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read scan file: %v\n", err)
		os.Exit(1)
	}

	encoded := encodeScanData(scanJSON)
	// fmt.Fprintf(os.Stderr, "encoded: json %d -> %d bytes\n", len(scanJSON), len(encoded))
	fmt.Fprintf(os.Stderr, "nmi callbacks bypassed\n")

	req, err = http.NewRequest("PUT", uploadResp.URL, bytes.NewReader(encoded))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating upload request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Go-http-client/1.1")

	resp, err = client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload request failed: %v\n", err)
		os.Exit(1)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// fmt.Fprintf(os.Stderr, "PUT upload -> %s\n", resp.Status)
	fmt.Fprintf(os.Stderr, "Showing my internal to dma user\n")
}

func setCommonHeaders(req *http.Request, auth string) {
	req.Header.Set("User-Agent", "Echo-Tool/v7.1.15")
	req.Header.Set("Authorization", auth)
	req.Header.Set("Echo-Arch", "amd64")
	req.Header.Set("Echo-Game", "0")
	req.Header.Set("Echo-Os", "windows")
}

func encodeScanData(data []byte) []byte {
	// Brotli compress (quality 11)
	var buf bytes.Buffer
	w := brotli.NewWriterOptions(&buf, brotli.WriterOptions{Quality: 11})
	if _, err := w.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "brotli write error: %v\n", err)
		os.Exit(1)
	}
	if err := w.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "brotli close error: %v\n", err)
		os.Exit(1)
	}
	compressed := buf.Bytes()

	// ASCII85 encode
	dst := make([]byte, ascii85.MaxEncodedLen(len(compressed)))
	n := ascii85.Encode(dst, compressed)
	return dst[:n]
}
