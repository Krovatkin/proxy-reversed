package main

import (
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
	Method        string
	Path          string
	Headers       map[string]string
	Body          *bytes.Buffer
	ID            string
	ContentLength int64
	mu            sync.Mutex
	nextChunk     int
	chunkCond     *sync.Cond
}

func NewActiveRequest(requestID string) *ActiveRequest {
	req := &ActiveRequest{
		ID:        requestID,
		Body:      bytes.NewBuffer(nil),
		nextChunk: 0,
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
	connMu       sync.Mutex // Add this for WebSocket write synchronization
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

	// prettyJSON, err := json.MarshalIndent(v, "", "  ")
	// if err == nil {
	// 	log.Printf("writeJSON: \n%s", string(prettyJSON))
	// }

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

// func (sc *ServiceClient) handleRequests() {
// 	for {
// 		var rawMsg json.RawMessage
// 		err := sc.conn.ReadJSON(&rawMsg)
// 		if err != nil {
// 			log.Printf("Connection closed: %v", err)
// 			break
// 		}

// 		go sc.processMessage(rawMsg)
// 	}
// }

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
			// Handle the parsing error
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
		req.chunkCond.Wait() // Sleep until previous chunk notifies
	}
	req.mu.Unlock()

	// Process the chunk
	log.Printf("Processing chunk %d for request %s", chunkID, req.ID)
	sc.processMessage(rawMsg)
	log.Printf("Completed chunk %d for request %s", chunkID, req.ID)

	// Mark this chunk as done and notify all waiting goroutines
	req.mu.Lock()
	req.nextChunk++
	req.chunkCond.Broadcast() // Wake up all waiting goroutines
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
	case "request_start":
		var reqStart protocol.ProxyRequestStart
		json.Unmarshal(rawMsg, &reqStart)
		sc.handleRequestStart(reqStart)

	case "request_chunk":
		var reqChunk protocol.ProxyRequestChunk
		json.Unmarshal(rawMsg, &reqChunk)
		sc.handleRequestChunk(reqChunk)

	case "request_end":
		var reqEnd protocol.ProxyRequestEnd
		json.Unmarshal(rawMsg, &reqEnd)
		sc.handleRequestEnd(reqEnd)
	}
}

func (sc *ServiceClient) handleRequestStart(reqStart protocol.ProxyRequestStart) {

	sc.reqMu.Lock()
	activeReq := sc.activeReqs[reqStart.ID]
	sc.reqMu.Unlock()

	activeReq.Method = reqStart.Method
	activeReq.Path = reqStart.Path
	activeReq.Headers = reqStart.Headers
	activeReq.ContentLength = reqStart.ContentLength

	// if !reqStart.HasBody {
	// 	// No body expected, process immediately
	// 	sc.executeRequest(activeReq)
	// }
}

func (sc *ServiceClient) handleRequestChunk(chunk protocol.ProxyRequestChunk) {
	sc.reqMu.RLock()
	//activeReq, exists := sc.activeReqs[chunk.ID]
	activeReq := sc.activeReqs[chunk.ID]
	sc.reqMu.RUnlock()

	// if !exists {
	// 	return
	// }

	if chunk.Data != "" {
		data, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			log.Printf("Failed to decode chunk: %v", err)
			return
		}
		log.Printf("In handleRequestChunk ID = %s data = %s", chunk.ID, data)
		activeReq.mu.Lock()
		activeReq.Body.Write(data)
		activeReq.mu.Unlock()
	}
}

func (sc *ServiceClient) handleRequestEnd(reqEnd protocol.ProxyRequestEnd) {
	sc.reqMu.RLock()
	//activeReq, exists := sc.activeReqs[reqEnd.ID]
	activeReq := sc.activeReqs[reqEnd.ID]
	sc.reqMu.RUnlock()

	// if !exists {
	// 	return
	// }

	// Execute the complete request
	sc.executeRequest(activeReq)

	// Cleanup
	sc.reqMu.Lock()
	delete(sc.activeReqs, reqEnd.ID)
	sc.reqMu.Unlock()
}

func (sc *ServiceClient) executeRequest(activeReq *ActiveRequest) {
	localURL := fmt.Sprintf("http://localhost:%s%s", sc.localPort, activeReq.Path)

	log.Printf("Forwarding Request %s to %s", activeReq.ID, localURL)
	// Create HTTP request
	req, err := http.NewRequest(activeReq.Method, localURL, activeReq.Body)
	if err != nil {
		log.Printf("Failed to create request %s", activeReq.ID)
		sc.sendErrorResponse(activeReq.ID, 500, "Failed to create request")
		return
	}

	// Set headers (excluding proxy headers)
	for k, v := range activeReq.Headers {
		lowerKey := strings.ToLower(k)
		if !strings.HasPrefix(lowerKey, "x-forwarded-") &&
			strings.ToLower(k) != "host" {

			if lowerKey == "upgrade-insecure-requests" ||
				lowerKey == "strict-transport-security" ||
				lowerKey == "x-forwarded-proto" ||
				lowerKey == "x-forwarded-ssl" ||
				lowerKey == "x-url-scheme" {
				continue
			}

			log.Printf("Setting headers %s : %s", k, v)
			req.Header.Set(k, v)
		}
	}

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
		// HasBody:    hasBody,
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
			// log.Printf("activeReq.ID = %s buffer = %s", activeReq.ID, buffer)
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

func (sc *ServiceClient) sendErrorResponse(reqID string, statusCode int, message string) {
	respStart := protocol.ProxyResponseStart{
		Type:       "response_start",
		ID:         reqID,
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "text/plain"},
		// HasBody:    true,
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
