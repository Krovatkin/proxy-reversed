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

type PendingResponse struct {
	ResponseWriter http.ResponseWriter
	StartTime      time.Time
	ResponseChan   chan json.RawMessage
	ID             string
}

func NewPendingResponse(requestID string, w http.ResponseWriter) *PendingResponse {
	return &PendingResponse{
		ResponseWriter: w,
		StartTime:      time.Now(),
		ResponseChan:   make(chan json.RawMessage, 10),
		ID:             requestID,
	}
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

// Fast ID extraction without full JSON parsing
func fastExtractID(data []byte) string {
	// Look for `"id":"` pattern
	idPattern := []byte(`"id":"`)
	start := bytes.Index(data, idPattern)
	if start == -1 {
		return ""
	}
	start += len(idPattern)

	// Find closing quote
	end := bytes.IndexByte(data[start:], '"')
	if end == -1 {
		return ""
	}

	return string(data[start : start+end])
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

		ps.handleServiceMessage(rawMsg)
	}

	// Cleanup
	ps.mu.Lock()
	delete(ps.services, regMsg.Subdomain)
	ps.mu.Unlock()
	log.Printf("Service %s disconnected", regMsg.Subdomain)
}

func (ps *ProxyServer) handleServiceMessage(rawMsg json.RawMessage) {
	// Fast ID extraction - minimal parsing on critical path
	id := fastExtractID(rawMsg)
	if id == "" {
		log.Printf("Failed to extract ID from message")
		return
	}

	log.Printf("In handleServiceMessage ID = %s", id)

	ps.reqMu.RLock()
	activeResp, exists := ps.pendingReqs[id]
	ps.reqMu.RUnlock()

	if !exists {
		return
	}

	// Forward raw JSON - parsing happens later when actually needed
	select {
	case activeResp.ResponseChan <- rawMsg:
	case <-time.After(1 * time.Second):
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
	if !exists {
		ps.mu.Unlock()
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}
	requestID := service.requestID
	service.requestID++
	ps.mu.Unlock()

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
			ps.reqMu.Lock()
			delete(ps.pendingReqs, reqID)
			ps.reqMu.Unlock()
			http.Error(w, "Failed to forward request", http.StatusBadGateway)
			return
		}
		chunkNum++
	}

	// Process response
	ps.processResponse(w, activeResp.ResponseChan)

	// Cleanup
	ps.reqMu.Lock()
	delete(ps.pendingReqs, reqID)
	ps.reqMu.Unlock()
}

func (ps *ProxyServer) processResponse(w http.ResponseWriter, responseChan chan json.RawMessage) {
	headersSent := false
	timeout := time.After(120 * time.Second)
	responseBuffer := &strings.Builder{}

	for {
		select {
		case rawMsg := <-responseChan:
			// Parse only when we actually need to process it
			var chunk protocol.ProxyRawRequestChunkWithEOS
			if err := json.Unmarshal(rawMsg, &chunk); err != nil {
				log.Printf("Failed to parse response chunk: %v", err)
				continue
			}

			ps.handleRawResponseChunk(w, chunk, responseBuffer, &headersSent)

			if chunk.EOS {
				return
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
	authTokenFlag := flag.String("authToken", "", "Authentication token")

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

		tlsConfig := &tls.Config{
			NextProtos: []string{"http/1.1"}, // Force HTTP/1.1
		}

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

	tlsConfig := &tls.Config{
		NextProtos: []string{"http/1.1"}, // Force HTTP/1.1
	}

	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", *publicPort),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("HTTP proxy server starting on :%d", *publicPort)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}
