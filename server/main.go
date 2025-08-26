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
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/krovatkin/proxy-reversed/protocol"
	"gopkg.in/yaml.v3"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
	authToken string
)

// Config represents the YAML configuration structure
type Config struct {
	ServicePort int    `yaml:"servicePort"`
	PublicPort  int    `yaml:"publicPort"`
	SSHPort     int    `yaml:"sshPort"`
	CertFile    string `yaml:"certFile"`
	KeyFile     string `yaml:"keyFile"`
	SvcCertFile string `yaml:"svcCertFile"`
	SvcKeyFile  string `yaml:"svcKeyFile"`
	AuthToken   string `yaml:"authToken"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	config := &Config{
		// Set defaults
		ServicePort: 7000,
		PublicPort:  8443,
		SSHPort:     2200,
	}

	// Load from file if provided
	if filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	return config, nil
}

// Validate checks if required configuration values are present
func (c *Config) Validate() error {
	if c.AuthToken == "" {
		return fmt.Errorf("authToken is required")
	}
	if c.CertFile == "" {
		return fmt.Errorf("certFile is required")
	}
	if c.KeyFile == "" {
		return fmt.Errorf("keyFile is required")
	}
	if c.SvcCertFile == "" {
		return fmt.Errorf("svcCertFile is required")
	}
	if c.SvcKeyFile == "" {
		return fmt.Errorf("svcKeyFile is required")
	}
	return nil
}

type ServiceConnection struct {
	conn       *websocket.Conn
	subdomain  string
	requestID  int64
	sshEnabled bool
	mu         sync.RWMutex
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
	services    map[string]*ServiceConnection // subdomain -> connection
	sshServices map[string]*ServiceConnection // subdomain -> connection (for SSH)
	sshConns    map[string]net.Conn           // connectionID -> TCP connection
	mu          sync.RWMutex
	upgrader    websocket.Upgrader
	pendingReqs map[string]*PendingResponse
	reqMu       sync.RWMutex
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		services:    make(map[string]*ServiceConnection),
		sshServices: make(map[string]*ServiceConnection),
		sshConns:    make(map[string]net.Conn),
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

// Start SSH tunnel listener - single port for all subdomains
func (ps *ProxyServer) startSSHTunnelListener(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to start SSH tunnel listener: %v", err)
	}
	defer listener.Close()

	log.Printf("SSH tunnel listener started on port %d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept SSH connection: %v", err)
			continue
		}

		go ps.handleSSHConnection(conn)
	}
}

func extractSubdomainFromSSHVersion(versionString string) string {
	// Look for space-separated addendum first
	if spaceIndex := strings.LastIndex(versionString, " "); spaceIndex != -1 {
		return strings.TrimSpace(versionString[spaceIndex+1:])
	}

	// Fallback to dash-separated parsing
	parts := strings.Split(versionString, "-")
	if len(parts) >= 4 {
		return parts[len(parts)-1]
	}

	return ""
}

func (ps *ProxyServer) handleSSHConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, protocol.ChunkSize)
	chunkNum := 0
	var service *ServiceConnection
	var finalConnectionID string
	subdomainExtracted := false

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if service != nil {
				// Send EOS chunk
				chunk := protocol.SSHDataChunk{
					Type:     "ssh_data_chunk",
					ID:       finalConnectionID,
					Data:     "",
					EOS:      true,
					ChunkNum: chunkNum,
				}
				service.mu.Lock()
				service.conn.WriteJSON(chunk)
				service.mu.Unlock()
				log.Printf("Sent EOS for SSH connection %s", finalConnectionID)
			}
			break
		}

		// First chunk - extract subdomain from ProxyCommand prefix
		if !subdomainExtracted {
			data := string(buffer[:n])

			// Look for subdomain in first line (sent by ProxyCommand)
			lines := strings.Split(data, "\n")
			if len(lines) > 0 {
				firstLine := strings.TrimSpace(lines[0])

				var subdomain string
				var sshDataStart int

				// Check if first line is subdomain (not SSH version)
				if !strings.HasPrefix(firstLine, "SSH-") {
					// First line is subdomain from ProxyCommand
					subdomain = firstLine
					log.Printf("Extracted subdomain from ProxyCommand: %s", subdomain)

					// Find where SSH data starts (after first \n)
					if newlinePos := strings.Index(data, "\n"); newlinePos != -1 {
						sshDataStart = newlinePos + 1
					}
				} else {
					// Fallback: try to extract from SSH version string (your original logic)
					if strings.HasPrefix(data, "SSH-2.0") || strings.HasPrefix(data, "SSH-1.") {
						clientVersion := firstLine
						log.Printf("Received SSH version: %s", clientVersion)
						subdomain = extractSubdomainFromSSHVersion(clientVersion)
						sshDataStart = 0 // All data is SSH data
					}
				}

				if subdomain == "" {
					log.Printf("No subdomain found in connection data")
					return
				}

				// Find the SSH service
				ps.mu.RLock()
				var exists bool
				service, exists = ps.sshServices[subdomain]
				ps.mu.RUnlock()

				if !exists {
					log.Printf("No SSH tunnel registered for subdomain: %s", subdomain)
					return
				}

				// Setup connection
				finalConnectionID = fmt.Sprintf("ssh-%s-%d", subdomain, time.Now().UnixNano())

				log.Printf("New SSH connection %s for subdomain %s", finalConnectionID, subdomain)

				// Send connection request to client
				connReq := protocol.SSHConnectionRequest{
					Type:         "ssh_connection_request",
					ConnectionID: finalConnectionID,
				}

				service.mu.Lock()
				err = service.conn.WriteJSON(connReq)
				service.mu.Unlock()

				if err != nil {
					log.Printf("Failed to send SSH connection request: %v", err)
					return
				}

				ps.mu.Lock()
				ps.sshConns[finalConnectionID] = conn
				ps.mu.Unlock()

				defer func() {
					ps.mu.Lock()
					delete(ps.sshConns, finalConnectionID)
					ps.mu.Unlock()
					log.Printf("Cleaned up SSH connection %s", finalConnectionID)
				}()

				subdomainExtracted = true

				// If we have SSH data after the subdomain in this chunk, send it
				if sshDataStart > 0 && sshDataStart < n {
					sshData := buffer[sshDataStart:n]
					chunk := protocol.SSHDataChunk{
						Type:     "ssh_data_chunk",
						ID:       finalConnectionID,
						Data:     base64.StdEncoding.EncodeToString(sshData),
						EOS:      false,
						ChunkNum: chunkNum,
					}

					service.mu.Lock()
					writeErr := service.conn.WriteJSON(chunk)
					service.mu.Unlock()

					if writeErr != nil {
						log.Printf("Failed to send SSH data chunk: %v", writeErr)
						break
					}
					chunkNum++
				}
			}
		} else {
			// Forward the chunk if we have a service (all subsequent chunks are SSH data)
			if service != nil {
				chunk := protocol.SSHDataChunk{
					Type:     "ssh_data_chunk",
					ID:       finalConnectionID,
					Data:     base64.StdEncoding.EncodeToString(buffer[:n]),
					EOS:      false,
					ChunkNum: chunkNum,
				}

				service.mu.Lock()
				writeErr := service.conn.WriteJSON(chunk)
				service.mu.Unlock()

				if writeErr != nil {
					log.Printf("Failed to send SSH data chunk: %v", writeErr)
					break
				}

				chunkNum++
			}
		}
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

		ps.handleServiceMessage(rawMsg, regMsg.Subdomain, service)
	}

	// Cleanup
	ps.cleanupService(regMsg.Subdomain)
	log.Printf("Service %s disconnected", regMsg.Subdomain)
}

func (ps *ProxyServer) handleServiceMessage(rawMsg json.RawMessage, subdomain string, service *ServiceConnection) {
	// Extract type first
	var msgType struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rawMsg, &msgType); err != nil {
		log.Printf("Failed to parse message type: %v", err)
		return
	}

	switch msgType.Type {
	case "ssh_tunnel_register":
		var sshReg protocol.SSHTunnelRegistrationMessage
		if err := json.Unmarshal(rawMsg, &sshReg); err != nil {
			log.Printf("Failed to parse SSH registration: %v", err)
			return
		}
		ps.handleSSHTunnelRegistration(sshReg, subdomain, service)

	case "ssh_data_chunk":
		var chunk protocol.SSHDataChunk
		if err := json.Unmarshal(rawMsg, &chunk); err != nil {
			log.Printf("Failed to parse SSH data chunk: %v", err)
			return
		}
		ps.handleSSHDataChunk(chunk)

	default:
		// Handle existing HTTP messages
		id := fastExtractID(rawMsg)
		if id == "" {
			log.Printf("Failed to extract ID from message")
			return
		}

		log.Printf("Received rawMsg w/ ID %s", id)

		ps.reqMu.RLock()
		activeResp, exists := ps.pendingReqs[id]
		ps.reqMu.RUnlock()

		if !exists {
			log.Printf("ID %s doesn't exist", id)
			return
		}

		// Forward raw JSON - parsing happens later when actually needed
		select {
		case activeResp.ResponseChan <- rawMsg:
		case <-time.After(1 * time.Second):
			log.Printf("Failed to send response message, channel blocked")
		}
	}
}

func (ps *ProxyServer) handleSSHTunnelRegistration(reg protocol.SSHTunnelRegistrationMessage, subdomain string, service *ServiceConnection) {
	log.Printf("Registered SSH tunnel for subdomain: %s (local port: %d)", subdomain, reg.LocalPort)

	// Mark SSH as enabled for this service
	service.mu.Lock()
	service.sshEnabled = true
	service.mu.Unlock()

	// Register SSH service
	ps.mu.Lock()
	ps.sshServices[subdomain] = service
	ps.mu.Unlock()

	// Send confirmation
	confirmMsg := map[string]interface{}{
		"type":      "ssh_tunnel_registered",
		"subdomain": subdomain,
		"localPort": reg.LocalPort,
		"sshPort":   2200, // Single SSH port for all subdomains
	}
	service.conn.WriteJSON(confirmMsg)
}

func (ps *ProxyServer) handleSSHDataChunk(chunk protocol.SSHDataChunk) {
	ps.mu.RLock()
	conn, exists := ps.sshConns[chunk.ID]
	ps.mu.RUnlock()

	if !exists {
		log.Printf("SSH connection %s not found", chunk.ID)
		return
	}

	if chunk.Data != "" {
		data, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			log.Printf("Failed to decode SSH data: %v", err)
			return
		}

		_, err = conn.Write(data)
		if err != nil {
			log.Printf("Failed to write to SSH connection %s: %v", chunk.ID, err)
			ps.mu.Lock()
			delete(ps.sshConns, chunk.ID)
			ps.mu.Unlock()
			conn.Close()
		}
	}

	if chunk.EOS {
		log.Printf("Closing SSH connection %s (EOS received)", chunk.ID)
		ps.mu.Lock()
		delete(ps.sshConns, chunk.ID)
		ps.mu.Unlock()
		conn.Close()
	}
}

func (ps *ProxyServer) cleanupService(subdomain string) {
	ps.mu.Lock()
	delete(ps.services, subdomain)
	delete(ps.sshServices, subdomain)

	// Close all SSH connections for this subdomain
	connectionsToClose := make([]string, 0)
	for connID := range ps.sshConns {
		if strings.HasPrefix(connID, fmt.Sprintf("ssh-%s-", subdomain)) {
			connectionsToClose = append(connectionsToClose, connID)
		}
	}

	for _, connID := range connectionsToClose {
		if conn, exists := ps.sshConns[connID]; exists {
			conn.Close()
			delete(ps.sshConns, connID)
		}
	}
	ps.mu.Unlock()

	log.Printf("Service %s disconnected, closed %d SSH connections", subdomain, len(connectionsToClose))
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
	log.Printf("Assigned reqID %s to a new http(s) request", reqID)

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
	log.SetFlags(log.LstdFlags | log.Llongfile)

	// Print version information
	log.Printf("Pontifex Server %s (built %s, commit %s)", version, buildDate, gitCommit)

	server := NewProxyServer()

	// First pass: define all flags but only use config and version
	configFile := flag.String("config", "", "Path to YAML configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	// Define other flags but don't use their values yet
	flag.Int("servicePort", 7000, "Port for the service registration server")
	flag.Int("publicPort", 8443, "Port for the public-facing HTTP proxy server")
	flag.Int("sshPort", 2200, "Port for SSH tunnel connections")
	flag.String("certFile", "", "Path to the TLS certificate file")
	flag.String("keyFile", "", "Path to the TLS key file")
	flag.String("svcCertFile", "", "Path to the TLS certificate file for service registration")
	flag.String("svcKeyFile", "", "Path to the TLS key file for service registration")
	flag.String("authToken", "", "Authentication token")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Pontifex Server %s\n", version)
		fmt.Printf("Build Date: %s\n", buildDate)
		fmt.Printf("Git Commit: %s\n", gitCommit)
		os.Exit(0)
	}

	// Load config from file
	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Reset flag package for second pass
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Second pass: create flags using config values as defaults
	flag.String("config", "", "Path to YAML configuration file") // Re-add for help text
	flag.Bool("version", false, "Show version information")      // Re-add for help text
	servicePort := flag.Int("servicePort", config.ServicePort, "Port for the service registration server")
	publicPort := flag.Int("publicPort", config.PublicPort, "Port for the public-facing HTTP proxy server")
	sshPort := flag.Int("sshPort", config.SSHPort, "Port for SSH tunnel connections")
	certFile := flag.String("certFile", config.CertFile, "Path to the TLS certificate file")
	keyFile := flag.String("keyFile", config.KeyFile, "Path to the TLS key file")
	svcCertFile := flag.String("svcCertFile", config.SvcCertFile, "Path to the TLS certificate file for service registration")
	svcKeyFile := flag.String("svcKeyFile", config.SvcKeyFile, "Path to the TLS key file for service registration")
	authTokenFlag := flag.String("authToken", config.AuthToken, "Authentication token")

	flag.Parse()

	// Copy flag values back to config (flags override config file values)
	config.ServicePort = *servicePort
	config.PublicPort = *publicPort
	config.SSHPort = *sshPort
	config.CertFile = *certFile
	config.KeyFile = *keyFile
	config.SvcCertFile = *svcCertFile
	config.SvcKeyFile = *svcKeyFile
	config.AuthToken = *authTokenFlag

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	// Set global auth token
	authToken = config.AuthToken

	// SSH tunnel listener
	if config.SSHPort > 0 {
		go server.startSSHTunnelListener(config.SSHPort)
	}

	// Service registration server
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
			Addr:      fmt.Sprintf(":%d", config.ServicePort),
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		log.Printf("Service registration server starting on :%d\n", config.ServicePort)
		log.Fatal(srv.ListenAndServeTLS(config.SvcCertFile, config.SvcKeyFile))
	}()

	// HTTP proxy server
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleHTTPProxy)

	tlsConfig := &tls.Config{
		NextProtos: []string{"http/1.1"}, // Force HTTP/1.1
	}

	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.PublicPort),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("HTTP proxy server starting on :%d", config.PublicPort)
	if config.SSHPort > 0 {
		log.Printf("SSH tunnel server starting on :%d", config.SSHPort)
	}
	log.Fatal(srv.ListenAndServeTLS(config.CertFile, config.KeyFile))
}
