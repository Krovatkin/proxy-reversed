package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/krovatkin/proxy-reversed/protocol"
)

var serverPort string

type ActiveRequest struct {
	RawHTTPData *bytes.Buffer
	ID          string
	mu          sync.Mutex
	nextChunk   int
	chunkCond   *sync.Cond
}

func NewActiveRequest(requestID string) *ActiveRequest {
	req := &ActiveRequest{
		ID:          requestID,
		RawHTTPData: bytes.NewBuffer(nil),
		nextChunk:   0,
	}
	req.chunkCond = sync.NewCond(&req.mu)
	return req
}

type ServiceClient struct {
	serverDomain string
	subdomain    string
	authToken    string
	localPort    string
	conn         *websocket.Conn
	activeReqs   map[string]*ActiveRequest
	reqMu        sync.RWMutex
	connMu       sync.Mutex
}

func NewServiceClient(serverDomain, subdomain, authToken, localPort string) *ServiceClient {
	return &ServiceClient{
		serverDomain: serverDomain,
		subdomain:    subdomain,
		authToken:    authToken,
		localPort:    localPort,
		activeReqs:   make(map[string]*ActiveRequest),
	}
}

func (sc *ServiceClient) writeJSON(v interface{}) error {
	sc.connMu.Lock()
	defer sc.connMu.Unlock()
	return sc.conn.WriteJSON(v)
}

func (sc *ServiceClient) connect() error {
	// Create WebSocket connection to registration server
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For development only
		},
	}

	wsURL := fmt.Sprintf("wss://%s:%s/register", sc.serverDomain, serverPort)
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}

	sc.conn = conn

	// Set message size limit
	conn.SetReadLimit(protocol.MessageLimit)

	// Send registration message
	regMsg := protocol.RegistrationMessage{
		Type:      "register",
		Subdomain: sc.subdomain,
		AuthToken: sc.authToken,
	}

	err = sc.writeJSON(regMsg)
	if err != nil {
		return fmt.Errorf("failed to send registration: %v", err)
	}

	// Read confirmation
	var response map[string]interface{}
	err = conn.ReadJSON(&response)
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %v", err)
	}

	if response["status"] != "registered" {
		return fmt.Errorf("registration failed: %v", response)
	}

	log.Printf("Successfully registered subdomain: %s", sc.subdomain)
	return nil
}

func (sc *ServiceClient) handleRequests() {
	for {
		var baseReq protocol.ProxyBaseMessage
		var rawMsg json.RawMessage
		err := sc.conn.ReadJSON(&rawMsg)

		if err != nil {
			log.Printf("Connection closed: %v", err)
			break
		}

		err = json.Unmarshal(rawMsg, &baseReq)
		if err != nil {
			log.Printf("Failed to parse base message: %v", err)
			continue
		}

		sc.reqMu.RLock()
		req, exists := sc.activeReqs[baseReq.ID]
		sc.reqMu.RUnlock()

		if !exists {
			req = NewActiveRequest(baseReq.ID)
			sc.reqMu.Lock()
			sc.activeReqs[baseReq.ID] = req
			sc.reqMu.Unlock()
		}

		go sc.processChunkWhenReady(req, rawMsg, baseReq.ChunkNum)
	}
}

func (sc *ServiceClient) processChunkWhenReady(req *ActiveRequest, rawMsg json.RawMessage, chunkID int) {
	// Wait until it's this chunk's turn
	req.mu.Lock()
	for req.nextChunk != chunkID {
		req.chunkCond.Wait()
	}
	req.mu.Unlock()

	// Process the chunk
	log.Printf("Processing chunk %d for request %s", chunkID, req.ID)
	sc.processMessage(rawMsg)
	log.Printf("Completed chunk %d for request %s", chunkID, req.ID)

	// Mark this chunk as done and notify all waiting goroutines
	req.mu.Lock()
	req.nextChunk++
	req.chunkCond.Broadcast()
	req.mu.Unlock()
}

func (sc *ServiceClient) processMessage(rawMsg json.RawMessage) {
	var msgType struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}

	if err := json.Unmarshal(rawMsg, &msgType); err != nil {
		log.Printf("Failed to parse message: %v", err)
		return
	}

	log.Printf("In processMessage ID = %s type = %s", msgType.ID, msgType.Type)

	switch msgType.Type {
	// case "raw_http_request_start":
	// 	var reqStart protocol.ProxyRawRequestStart
	// 	json.Unmarshal(rawMsg, &reqStart)
	// 	sc.handleRawRequestStart(reqStart)

	// case "raw_http_request_chunk":
	// 	var reqChunk protocol.ProxyRawRequestChunk
	// 	json.Unmarshal(rawMsg, &reqChunk)
	// 	sc.handleRawRequestChunk(reqChunk)
	case "raw_http_request_chunk_with_eos":
		var reqChunk protocol.ProxyRawRequestChunkWithEOS
		json.Unmarshal(rawMsg, &reqChunk)
		sc.handleRawRequestChunkWithEOS(reqChunk)

		// case "raw_http_request_end":
		// 	var reqEnd protocol.ProxyRawRequestEnd
		// 	json.Unmarshal(rawMsg, &reqEnd)
		// 	sc.handleRawRequestEnd(reqEnd)
	}
}

// func (sc *ServiceClient) handleRawRequestStart(reqStart protocol.ProxyRawRequestStart) {
// }

// func (sc *ServiceClient) handleRawRequestChunk(chunk protocol.ProxyRawRequestChunk) {
// 	sc.reqMu.RLock()
// 	activeReq := sc.activeReqs[chunk.ID]
// 	sc.reqMu.RUnlock()

// 	if chunk.Data != "" {
// 		data, err := base64.StdEncoding.DecodeString(chunk.Data)
// 		if err != nil {
// 			log.Printf("Failed to decode chunk: %v", err)
// 			return
// 		}

// 		activeReq.mu.Lock()
// 		activeReq.RawHTTPData.Write(data)
// 		activeReq.mu.Unlock()
// 	}
// }

func (sc *ServiceClient) handleRawRequestChunkWithEOS(chunk protocol.ProxyRawRequestChunkWithEOS) {
	sc.reqMu.RLock()
	activeReq := sc.activeReqs[chunk.ID]
	sc.reqMu.RUnlock()

	if chunk.Data != "" {
		data, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			log.Printf("Failed to decode chunk: %v", err)
			return
		}

		activeReq.mu.Lock()
		activeReq.RawHTTPData.Write(data)
		activeReq.mu.Unlock()
	}

	if chunk.EOS {

		sc.reqMu.RLock()
		activeReq = sc.activeReqs[chunk.ID]
		sc.reqMu.RUnlock()

		sc.executeRawRequest(activeReq)

		sc.reqMu.Lock()
		delete(sc.activeReqs, chunk.ID)
		sc.reqMu.Unlock()

	}
}

func (sc *ServiceClient) handleRawRequestEnd(reqEnd protocol.ProxyRawRequestEnd) {
	sc.reqMu.RLock()
	activeReq := sc.activeReqs[reqEnd.ID]
	sc.reqMu.RUnlock()

	// Execute the complete request
	sc.executeRawRequest(activeReq)

	// Cleanup
	sc.reqMu.Lock()
	delete(sc.activeReqs, reqEnd.ID)
	sc.reqMu.Unlock()
}

func (sc *ServiceClient) executeRawRequest(activeReq *ActiveRequest) {
	// Parse the raw HTTP data
	req, err := sc.createRequestFromRawHTTP(activeReq.RawHTTPData.String())
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		sc.sendErrorResponse(activeReq.ID, 500, "Failed to parse request")
		return
	}

	// Filter out problematic headers
	headersToRemove := []string{
		"Upgrade-Insecure-Requests",
		"Strict-Transport-Security",
		"X-Forwarded-Ssl",
		"X-Url-Scheme",
		"Host", // Will be set automatically by http.Client
	}

	for _, header := range headersToRemove {
		req.Header.Del(header)
	}

	// Remove X-Forwarded-* headers (except the ones we want to keep)
	for headerName := range req.Header {
		lowerName := strings.ToLower(headerName)
		if strings.HasPrefix(lowerName, "x-forwarded-") {
			// Keep X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host
			if lowerName != "x-forwarded-for" &&
				lowerName != "x-forwarded-proto" &&
				lowerName != "x-forwarded-host" {
				req.Header.Del(headerName)
			}
		}
	}

	// Update URL to point to local service

	req.URL.Scheme = "http"
	req.URL.Host = fmt.Sprintf("localhost:%s", sc.localPort)

	req.RequestURI = ""

	log.Printf("Forwarding Request %s to %s", activeReq.ID, req.URL.String())

	// Execute request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to connect to local service: %v", err)
		sc.sendErrorResponse(activeReq.ID, 502, fmt.Sprintf("Failed to connect to local service: %v", err))
		return
	}
	defer resp.Body.Close()

	// Send response start
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	hasBody := resp.ContentLength != 0 && resp.StatusCode != http.StatusNoContent

	chunkNum := 0
	respStart := protocol.ProxyResponseStart{
		Type:       "response_start",
		ID:         activeReq.ID,
		StatusCode: resp.StatusCode,
		Headers:    headers,
		ChunkNum:   chunkNum,
	}

	chunkNum++

	err = sc.writeJSON(respStart)
	if err != nil {
		log.Printf("Failed to send response start: %v", err)
		return
	}

	// Stream response body in chunks if there is one
	if hasBody {
		buffer := make([]byte, protocol.ChunkSize)

		for {
			n, err := resp.Body.Read(buffer)
			if n > 0 {
				chunk := protocol.ProxyResponseChunk{
					Type:     "response_chunk",
					ID:       activeReq.ID,
					Data:     base64.StdEncoding.EncodeToString(buffer[:n]),
					ChunkNum: chunkNum,
				}
				writeErr := sc.writeJSON(chunk)
				if writeErr != nil {
					log.Printf("Failed to send response chunk: %v", writeErr)
					return
				}
				chunkNum++
			}

			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("Error reading response: %v", err)
				break
			}
		}
	}

	// Send response end
	respEnd := protocol.ProxyResponseEnd{
		Type:     "response_end",
		ID:       activeReq.ID,
		ChunkNum: chunkNum,
	}
	sc.writeJSON(respEnd)
}

func (sc *ServiceClient) createRequestFromRawHTTP(rawData string) (*http.Request, error) {
	reader := strings.NewReader(rawData)
	bufReader := bufio.NewReader(reader)

	// Parse using http.ReadRequest
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP request: %v", err)
	}

	return req, nil
}

func (sc *ServiceClient) sendErrorResponse(reqID string, statusCode int, message string) {
	respStart := protocol.ProxyResponseStart{
		Type:       "response_start",
		ID:         reqID,
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "text/plain"},
	}
	sc.writeJSON(respStart)

	chunk := protocol.ProxyResponseChunk{
		Type: "response_chunk",
		ID:   reqID,
		Data: base64.StdEncoding.EncodeToString([]byte(message)),
	}
	sc.writeJSON(chunk)

	respEnd := protocol.ProxyResponseEnd{
		Type: "response_end",
		ID:   reqID,
	}
	sc.writeJSON(respEnd)
}

func (sc *ServiceClient) run() error {
	err := sc.connect()
	if err != nil {
		return err
	}
	defer sc.conn.Close()

	log.Printf("Service client running - forwarding %s.%s:8443 -> localhost:%s",
		sc.subdomain, sc.serverDomain, sc.localPort)

	sc.handleRequests()
	return nil
}

func main() {
	var (
		serverDomain   = flag.String("server", "", "Server domain name")
		subdomain      = flag.String("subdomain", "", "App subdomain to serve requests")
		authToken      = flag.String("token", "", "Authentication token")
		localPort      = flag.String("port", "", "Local port to forward requests to")
		serverPortFlag = flag.String("server-port", "7000", "Server port number")
	)
	flag.Parse()

	serverPort = *serverPortFlag

	if *serverDomain == "" || *subdomain == "" || *authToken == "" || *localPort == "" {
		log.Fatal("All flags are required: -server, -subdomain, -token, -port")
	}

	client := NewServiceClient(*serverDomain, *subdomain, *authToken, *localPort)

	for {
		err := client.run()
		if err != nil {
			log.Printf("Service client error: %v", err)
			log.Println("Retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
		}
	}
}
