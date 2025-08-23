package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/krovatkin/proxy-reversed/protocol"
)

var authToken string

type ServiceConnection struct {
	conn      *websocket.Conn
	subdomain string
	requestID int64
	mu        sync.RWMutex
}

type ResponseMessage struct {
	Type  string
	Data  interface{}
	Error error
}

type PendingResponse struct {
	ResponseWriter http.ResponseWriter
	StartTime      time.Time
	ResponseChan   chan ResponseMessage
	ID             string
	mu             sync.Mutex
	nextChunk      int
	chunkCond      *sync.Cond
}

func NewPendingResponse(requestID string, w http.ResponseWriter) *PendingResponse {
	resp := &PendingResponse{
		ResponseWriter: w,
		StartTime:      time.Now(),
		ResponseChan:   make(chan ResponseMessage, 10),
		ID:             requestID,
		nextChunk:      0,
	}
	resp.chunkCond = sync.NewCond(&resp.mu)
	return resp
}

type ProxyServer struct {
	services    map[string]*ServiceConnection
	mu          sync.RWMutex
	upgrader    websocket.Upgrader
	pendingReqs map[string]*PendingResponse
	reqMu       sync.RWMutex
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		services: make(map[string]*ServiceConnection),
		upgrader: websocket.Upgrader{
			CheckOrigin:     func(r *http.Request) bool { return true },
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
		},
		pendingReqs: make(map[string]*PendingResponse),
	}
}

func (ps *ProxyServer) handleServiceRegistration(w http.ResponseWriter, r *http.Request) {
	conn, err := ps.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}
	defer conn.Close()

	// Set message size limit (16MB for individual WebSocket messages)
	conn.SetReadLimit(protocol.MessageLimit)

	// Read registration message
	var regMsg protocol.RegistrationMessage
	err = conn.ReadJSON(&regMsg)
	if err != nil {
		log.Printf("Failed to read registration message: %v", err)
		return
	}

	if regMsg.Type != "register" {
		log.Printf("Invalid registration type: %s", regMsg.Type)
		return
	}

	if regMsg.AuthToken != authToken {
		log.Printf("Missing auth token regMsg.AuthToken %s != authToken %s", regMsg.AuthToken, authToken)
		return
	}

	log.Printf("Registering service for subdomain: %s", regMsg.Subdomain)

	service := &ServiceConnection{
		conn:      conn,
		subdomain: regMsg.Subdomain,
	}

	ps.mu.Lock()
	ps.services[regMsg.Subdomain] = service
	ps.mu.Unlock()

	// Send confirmation
	confirmMsg := map[string]string{
		"status":    "registered",
		"subdomain": regMsg.Subdomain,
	}
	conn.WriteJSON(confirmMsg)

	// Handle incoming messages from service
	for {
		var rawMsg json.RawMessage
		err := conn.ReadJSON(&rawMsg)
		if err != nil {
			log.Printf("Service connection closed for %s: %v", regMsg.Subdomain, err)
			break
		}

		var baseResp protocol.ProxyBaseMessage
		err = json.Unmarshal(rawMsg, &baseResp)
		if err != nil {
			log.Printf("Failed to parse base response: %v", err)
			continue
		}

		ps.reqMu.RLock()
		activeResp := ps.pendingReqs[baseResp.ID]
		ps.reqMu.RUnlock()

		go ps.processResponseChunkWhenReady(activeResp, rawMsg, baseResp.ChunkNum)
	}

	// Cleanup
	ps.mu.Lock()
	delete(ps.services, regMsg.Subdomain)
	ps.mu.Unlock()
	log.Printf("Service %s disconnected", regMsg.Subdomain)
}

func (ps *ProxyServer) processResponseChunkWhenReady(resp *PendingResponse, rawMsg json.RawMessage, chunkID int) {
	// Wait until it's this chunk's turn
	resp.mu.Lock()
	for resp.nextChunk != chunkID {
		resp.chunkCond.Wait() // Sleep until previous chunk notifies
	}
	resp.mu.Unlock()

	// Process the chunk
	log.Printf("Processing response chunk %d for request %s", chunkID, resp.ID)
	ps.handleServiceMessage(rawMsg)
	log.Printf("Completed response chunk %d for request %s", chunkID, resp.ID)

	// Mark this chunk as done and notify all waiting goroutines
	resp.mu.Lock()
	resp.nextChunk++
	resp.chunkCond.Broadcast() // Wake up all waiting goroutines
	resp.mu.Unlock()
}

func (ps *ProxyServer) handleServiceMessage(rawMsg json.RawMessage) {
	var msgType struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}

	if err := json.Unmarshal(rawMsg, &msgType); err != nil {
		log.Printf("Failed to parse message type: %v", err)
		return
	}

	log.Printf("In handleServiceMessage ID = %s Type %s", msgType.ID, msgType.Type)

	ps.reqMu.RLock()
	activeResp, exists := ps.pendingReqs[msgType.ID]
	ps.reqMu.RUnlock()

	if !exists {
		return
	}

	// Send messages through channel instead of direct handling
	switch msgType.Type {
	case "raw_http_request_chunk_with_eos":
		var respChunk protocol.ProxyRawRequestChunkWithEOS
		if err := json.Unmarshal(rawMsg, &respChunk); err != nil {
			ps.sendResponseMessage(activeResp, ResponseMessage{Error: err})
			return
		}
		ps.sendResponseMessage(activeResp, ResponseMessage{
			Type: "raw_http_request_chunk_with_eos",
			Data: respChunk,
		})
	}
}

func (ps *ProxyServer) sendResponseMessage(activeResp *PendingResponse, msg ResponseMessage) {
	select {
	case activeResp.ResponseChan <- msg:
	case <-time.After(1 * time.Second):
		// Channel is blocked or closed, request might have timed out
		log.Printf("Failed to send response message, channel blocked")
	}
}

func (ps *ProxyServer) handleHTTPProxy(w http.ResponseWriter, r *http.Request) {
	// Extract subdomain
	host := r.Host
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		http.Error(w, "Invalid subdomain", http.StatusBadRequest)
		return
	}
	subdomain := parts[0]

	// Find service
	ps.mu.Lock()
	service, exists := ps.services[subdomain]
	requestID := service.requestID
	service.requestID++
	ps.mu.Unlock()

	if !exists {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	// Generate request ID
	reqID := fmt.Sprintf("%s-%d-%d", subdomain, requestID, time.Now().UnixNano())
	log.Printf("In handleHTTPProxy reqID = %s", reqID)

	// Register pending request with PendingResponse
	activeResp := NewPendingResponse(reqID, w)

	ps.reqMu.Lock()
	ps.pendingReqs[reqID] = activeResp
	ps.reqMu.Unlock()

	// Now dump the cleaned request
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		ps.reqMu.Lock()
		delete(ps.pendingReqs, reqID)
		ps.reqMu.Unlock()
		http.Error(w, "Failed to dump request", http.StatusInternalServerError)
		return
	}

	// Send raw request in chunks
	chunkNum := 0
	requestData := requestDump
	totalSize := len(requestData)

	// Send data in chunks
	for offset := 0; offset < totalSize; offset += protocol.ChunkSize {
		end := offset + protocol.ChunkSize
		EOS := false
		if end >= totalSize {
			EOS = true
			end = totalSize
		}

		chunk := protocol.ProxyRawRequestChunkWithEOS{
			Type:     "raw_http_request_chunk_with_eos",
			ID:       reqID,
			Data:     base64.StdEncoding.EncodeToString(requestData[offset:end]),
			EOS:      EOS,
			ChunkNum: chunkNum,
		}

		service.mu.Lock()
		writeErr := service.conn.WriteJSON(chunk)
		service.mu.Unlock()

		if writeErr != nil {
			log.Printf("Failed to send chunk: %v", writeErr)
			break
		}
		chunkNum++
	}

	// Set up timeout cleanup
	ps.processResponse(w, activeResp.ResponseChan)

	// Cleanup
	ps.reqMu.Lock()
	delete(ps.pendingReqs, reqID)
	ps.reqMu.Unlock()
}

func (ps *ProxyServer) processResponse(w http.ResponseWriter, responseChan chan ResponseMessage) {
	headersSent := false
	timeout := time.After(120 * time.Second)
	responseBuffer := &strings.Builder{}

	for {
		select {
		case msg := <-responseChan:
			if msg.Error != nil {
				if !headersSent {
					http.Error(w, "Internal server error", http.StatusInternalServerError)
				}
				return
			}

			switch msg.Type {
			case "raw_http_request_chunk_with_eos":
				chunk := msg.Data.(protocol.ProxyRawRequestChunkWithEOS)
				ps.handleRawResponseChunk(w, chunk, responseBuffer, &headersSent)

				if chunk.EOS {
					return // Complete response
				}
			}

		case <-timeout:
			if !headersSent {
				http.Error(w, "Gateway timeout", http.StatusGatewayTimeout)
			}
			return
		}
	}
}

func (ps *ProxyServer) handleRawResponseChunk(w http.ResponseWriter, chunk protocol.ProxyRawRequestChunkWithEOS, responseBuffer *strings.Builder, headersSent *bool) {
	if chunk.Data == "" {
		return
	}

	data, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil {
		log.Printf("Failed to decode chunk: %v", err)
		return
	}

	responseBuffer.Write(data)

	if chunk.EOS {
		// Parse the complete HTTP response
		rawResponse := responseBuffer.String()
		reader := strings.NewReader(rawResponse)
		bufReader := bufio.NewReader(reader)
		resp, err := http.ReadResponse(bufReader, nil)
		if err != nil {
			log.Printf("Failed to parse HTTP response: %v", err)
			if !*headersSent {
				http.Error(w, "Failed to parse response", http.StatusBadGateway)
			}
			return
		}
		defer resp.Body.Close()

		// Copy headers
		for k, v := range resp.Header {
			for _, val := range v {
				w.Header().Add(k, val)
			}
		}

		// Write status code
		w.WriteHeader(resp.StatusCode)
		*headersSent = true

		// Copy body using io.Copy
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("Failed to write response body: %v", err)
		}

		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	server := NewProxyServer()
	servicePort := flag.Int("servicePort", 7000, "Port for the service registration server")
	publicPort := flag.Int("publicPort", 8443, "Port for the public-facing HTTP proxy server")
	certFile := flag.String("certFile", "", "Path to the TLS certificate file")
	keyFile := flag.String("keyFile", "", "Path to the TLS key file")
	svcCertFile := flag.String("svcCertFile", "", "Path to the TLS certificate file")
	svcKeyFile := flag.String("svcKeyFile", "", "Path to the TLS key file")
	authTokenFlag := flag.String("authToken", "", "Path to the TLS key file")

	flag.Parse()

	authToken = *authTokenFlag

	if authToken == "" {
		fmt.Println("Error: --authToken flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	if *certFile == "" || *keyFile == "" {
		fmt.Println("Error: --certFile and --keyFile flags are required.")
		flag.Usage()
		os.Exit(1)
	}

	if *svcCertFile == "" || *svcKeyFile == "" {
		fmt.Println("Error: --svcCertFile flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	// Service registration server (port 7000)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/register", server.handleServiceRegistration)

		mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		})

		tlsConfig := &tls.Config{}

		srv := &http.Server{
			Addr:      fmt.Sprintf(":%d", *servicePort),
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		log.Printf("Service registration server starting on :%d\n", *servicePort)
		log.Fatal(srv.ListenAndServeTLS(*svcCertFile, *svcKeyFile))
	}()

	// HTTP proxy server (port 8443)
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleHTTPProxy)

	tlsConfig := &tls.Config{}

	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", *publicPort),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("HTTP proxy server starting on :%d", *publicPort)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}
