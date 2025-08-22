package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
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
		// activeResp, exists := ps.pendingReqs[baseResp.ID]
		activeResp := ps.pendingReqs[baseResp.ID]
		ps.reqMu.RUnlock()

		// if !exists {
		// 	activeResp = NewPendingResponse(baseResp.ID, nil) // w will be nil but we won't use it
		// 	ps.reqMu.Lock()
		// 	ps.pendingReqs[baseResp.ID] = activeResp
		// 	ps.reqMu.Unlock()
		// }

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
	case "response_start":
		var respStart protocol.ProxyResponseStart
		if err := json.Unmarshal(rawMsg, &respStart); err != nil {
			ps.sendResponseMessage(activeResp, ResponseMessage{Error: err})
			return
		}
		ps.sendResponseMessage(activeResp, ResponseMessage{
			Type: "response_start",
			Data: respStart,
		})

	case "response_chunk":
		var respChunk protocol.ProxyResponseChunk
		if err := json.Unmarshal(rawMsg, &respChunk); err != nil {
			ps.sendResponseMessage(activeResp, ResponseMessage{Error: err})
			return
		}
		ps.sendResponseMessage(activeResp, ResponseMessage{
			Type: "response_chunk",
			Data: respChunk,
		})

	case "response_end":
		var respEnd protocol.ProxyResponseEnd
		json.Unmarshal(rawMsg, &respEnd)
		ps.sendResponseMessage(activeResp, ResponseMessage{
			Type: "response_end",
			Data: respEnd,
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

	// Prepare headers
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	headers["X-Forwarded-For"] = r.RemoteAddr
	headers["X-Forwarded-Proto"] = "https"
	headers["X-Forwarded-Host"] = r.Host

	Query := ""
	if r.URL.RawQuery != "" {
		Query = "?" + r.URL.RawQuery
	}

	chunkNum := 0
	// Send request start
	reqStart := protocol.ProxyRequestStart{
		Type:          "request_start",
		Method:        r.Method,
		Path:          r.URL.Path + Query,
		Headers:       headers,
		ID:            reqID,
		ContentLength: r.ContentLength,
		ChunkNum:      chunkNum,
	}
	chunkNum++

	service.mu.Lock()
	err := service.conn.WriteJSON(reqStart)
	service.mu.Unlock()

	if err != nil {
		ps.reqMu.Lock()
		delete(ps.pendingReqs, reqID)
		ps.reqMu.Unlock()
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}

	// Stream request body in chunks if present
	if r.ContentLength > 0 {
		buffer := make([]byte, protocol.ChunkSize)

		for {
			n, err := r.Body.Read(buffer)
			if n > 0 {
				chunk := protocol.ProxyRequestChunk{
					Type:     "request_chunk",
					ID:       reqID,
					Data:     base64.StdEncoding.EncodeToString(buffer[:n]),
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

			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("Error reading request body: %v", err)
				break
			}
		}
	}

	// Send request end
	reqEnd := protocol.ProxyRequestEnd{
		Type:     "request_end",
		ID:       reqID,
		ChunkNum: chunkNum,
	}

	service.mu.Lock()
	service.conn.WriteJSON(reqEnd)
	service.mu.Unlock()

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
			case "response_start":
				if !headersSent {
					resp := msg.Data.(protocol.ProxyResponseStart)
					ps.handleResponseStartSync(w, resp)
					headersSent = true
				}

			case "response_chunk":
				if headersSent {
					chunk := msg.Data.(protocol.ProxyResponseChunk)
					ps.handleResponseChunkSync(w, chunk)
				}

			case "response_end":
				return // Complete response
			}

		case <-timeout:
			if !headersSent {
				http.Error(w, "Gateway timeout", http.StatusGatewayTimeout)
			}
			return
		}
	}
}

func (ps *ProxyServer) handleResponseStartSync(w http.ResponseWriter, resp protocol.ProxyResponseStart) {
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(resp.StatusCode)
}

func (ps *ProxyServer) handleResponseChunkSync(w http.ResponseWriter, chunk protocol.ProxyResponseChunk) {
	if chunk.Data == "" {
		return
	}

	data, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil {
		log.Printf("Failed to decode chunk: %v", err)
		return
	}

	w.Write(data)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
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
