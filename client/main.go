package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
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
	version    = "dev"
	buildDate  = "unknown"
	gitCommit  = "unknown"
	serverPort string
)

// Config represents the YAML configuration structure
type Config struct {
	ServerDomain string `yaml:"serverDomain"`
	Subdomain    string `yaml:"subdomain"`
	AuthToken    string `yaml:"authToken"`
	LocalPort    string `yaml:"localPort"`
	ServerPort   string `yaml:"serverPort"`
	SSHPort      int    `yaml:"sshPort"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	config := &Config{
		// Set defaults
		ServerPort: "7000",
		SSHPort:    0, // SSH disabled by default
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
	if c.ServerDomain == "" {
		return fmt.Errorf("serverDomain is required")
	}
	if c.Subdomain == "" {
		return fmt.Errorf("subdomain is required")
	}
	if c.AuthToken == "" {
		return fmt.Errorf("authToken is required")
	}
	if c.LocalPort == "" {
		return fmt.Errorf("localPort is required")
	}
	return nil
}

type ActiveRequest struct {
	ID        string
	mu        sync.Mutex
	nextChunk int
	chunkCond *sync.Cond
	payload   interface{} // Can be *bytes.Buffer for HTTP or net.Conn for SSH
}

func NewActiveRequestHTTP(requestID string) *ActiveRequest {
	req := &ActiveRequest{
		ID:      requestID,
		payload: bytes.NewBuffer(nil),
	}
	req.chunkCond = sync.NewCond(&req.mu)
	return req
}

type ServiceClient struct {
	serverDomain string
	subdomain    string
	authToken    string
	localPort    string
	sshPort      int // Local SSH port (22)
	conn         *websocket.Conn
	activeReqs   map[string]*ActiveRequest // Unified map for both HTTP and SSH
	reqMu        sync.RWMutex
	connMu       sync.Mutex
}

func NewServiceClient(serverDomain, subdomain, authToken, localPort string) *ServiceClient {
	return &ServiceClient{
		serverDomain: serverDomain,
		subdomain:    subdomain,
		authToken:    authToken,
		localPort:    localPort,
		sshPort:      0, // SSH disabled by default
		activeReqs:   make(map[string]*ActiveRequest),
	}
}

// Method to enable SSH tunneling
func (sc *ServiceClient) EnableSSH(sshPort int) {
	sc.sshPort = sshPort
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

	// Send HTTP service registration message
	regMsg := protocol.RegistrationMessage{
		Type:      "register",
		Subdomain: sc.subdomain,
		AuthToken: sc.authToken,
	}

	err = sc.writeJSON(regMsg)
	if err != nil {
		return fmt.Errorf("failed to send registration: %v", err)
	}

	// Read confirmation for HTTP registration
	var response map[string]interface{}
	err = conn.ReadJSON(&response)
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %v", err)
	}

	if response["status"] != "registered" {
		return fmt.Errorf("HTTP registration failed: %v", response)
	}

	log.Printf("Successfully registered HTTP subdomain: %s", sc.subdomain)

	// Register SSH tunnel if enabled
	if sc.sshPort > 0 {
		err = sc.registerSSHTunnel()
		if err != nil {
			return fmt.Errorf("failed to register SSH tunnel: %v", err)
		}

		// Read SSH tunnel confirmation
		var sshResponse map[string]interface{}
		err = conn.ReadJSON(&sshResponse)
		if err != nil {
			return fmt.Errorf("failed to read SSH tunnel confirmation: %v", err)
		}

		if sshResponse["type"] == "ssh_tunnel_registered" {
			log.Printf("Successfully registered SSH tunnel for subdomain: %s", sc.subdomain)
			log.Printf("Users can connect with: ssh -o 'VersionAddendum %s' user@%s -p 2200", sc.subdomain, sc.serverDomain)
		} else {
			log.Printf("SSH tunnel registration response: %v", sshResponse)
		}
	}

	return nil
}

// Helper method for SSH tunnel registration
func (sc *ServiceClient) registerSSHTunnel() error {
	if sc.sshPort == 0 {
		return nil // SSH not enabled
	}

	tunnelReg := protocol.SSHTunnelRegistrationMessage{
		Type:      "ssh_tunnel_register",
		AuthToken: sc.authToken,
		LocalPort: sc.sshPort,
	}

	log.Printf("Registering SSH tunnel: %s -> localhost:%d", sc.subdomain, sc.sshPort)
	return sc.writeJSON(tunnelReg)
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
		log.Printf("Received RawMsg ID = %s, ChunkNum = %d, Type = %s", baseReq.ID, baseReq.ChunkNum, baseReq.Type)
		if err != nil {
			log.Printf("Failed to parse base message: %v", err)
			continue
		}

		sc.reqMu.RLock()
		req, exists := sc.activeReqs[baseReq.ID]
		sc.reqMu.RUnlock()

		if !exists {
			req = &ActiveRequest{
				ID: baseReq.ID,
			}
			req.chunkCond = sync.NewCond(&req.mu)
			sc.reqMu.Lock()
			sc.activeReqs[baseReq.ID] = req
			sc.reqMu.Unlock()
		}

		go sc.processChunkWhenReady(req, rawMsg, baseReq.ChunkNum)
	}
}

func (sc *ServiceClient) processChunkWhenReady(req *ActiveRequest, rawMsg json.RawMessage, chunkID int) {

	log.Printf("Ready to process chunk %d for request ID %s", chunkID, req.ID)
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
		Type     string `json:"type"`
		ID       string `json:"id"`
		ChunkNum int    `json:"chunkNum"`
	}

	if err := json.Unmarshal(rawMsg, &msgType); err != nil {
		log.Printf("Failed to parse message: %v", err)
		return
	}

	log.Printf("Received rawMsg ID = %s type = %s chunkNum = %d", msgType.ID, msgType.Type, msgType.ChunkNum)

	switch msgType.Type {
	// Existing HTTP handling
	case "raw_http_request_chunk_with_eos":
		var reqChunk protocol.ProxyRawRequestChunkWithEOS
		json.Unmarshal(rawMsg, &reqChunk)
		sc.handleRawRequestChunkWithEOS(reqChunk)

	// New SSH handling
	case "ssh_connection_request":
		var connReq protocol.SSHConnectionRequest
		json.Unmarshal(rawMsg, &connReq)
		sc.handleSSHConnectionRequest(connReq)

	case "ssh_data_chunk":
		var chunk protocol.SSHDataChunk
		json.Unmarshal(rawMsg, &chunk)
		sc.handleSSHDataChunk(chunk)

	case "ssh_tunnel_registered":
		var confirm map[string]interface{}
		json.Unmarshal(rawMsg, &confirm)
		log.Printf("SSH tunnel registered for subdomain %s", confirm["subdomain"])

	default:
		log.Printf("Unknown message type: %s", msgType.Type)
	}
}

func (sc *ServiceClient) handleSSHConnectionRequest(req protocol.SSHConnectionRequest) {
	// Connect to local SSH server
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", sc.sshPort), 15*time.Second)
	if err != nil {
		log.Printf("Failed to connect to local SSH server: %v", err)
		// Send error/close message
		chunk := protocol.SSHDataChunk{
			Type:     "ssh_data_chunk",
			ID:       req.ID,
			Data:     "",
			EOS:      true,
			ChunkNum: 0,
		}
		sc.writeJSON(chunk)
		return
	}

	// Update the existing ActiveRequest with the SSH connection
	sc.reqMu.Lock()
	activeReq, exists := sc.activeReqs[req.ID]
	if exists {
		activeReq.payload = conn
	} else {
		log.Printf("ActiveRequest with connectionID %s not found", req.ID)
	}
	sc.reqMu.Unlock()

	log.Printf("Established SSH connection %s -> localhost:%d", req.ID, sc.sshPort)

	// Forward data from local SSH to WebSocket
	go sc.forwardSSHToWebSocket(conn, req.ID)
}

func (sc *ServiceClient) forwardSSHToWebSocket(conn net.Conn, connectionID string) {
	defer func() {
		conn.Close()
		sc.reqMu.Lock()
		delete(sc.activeReqs, connectionID)
		sc.reqMu.Unlock()
		log.Printf("Closed SSH connection %s", connectionID)
	}()

	buffer := make([]byte, protocol.ChunkSize)
	chunkNum := 0

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			// Send EOS
			chunk := protocol.SSHDataChunk{
				Type:     "ssh_data_chunk",
				ID:       connectionID,
				Data:     "",
				EOS:      true,
				ChunkNum: chunkNum,
			}
			sc.writeJSON(chunk)
			log.Printf("Sent EOS for SSH connection %s", connectionID)
			break
		}

		chunk := protocol.SSHDataChunk{
			Type:     "ssh_data_chunk",
			ID:       connectionID,
			Data:     base64.StdEncoding.EncodeToString(buffer[:n]),
			EOS:      false,
			ChunkNum: chunkNum,
		}

		if err := sc.writeJSON(chunk); err != nil {
			log.Printf("Failed to send SSH data for %s: %v", connectionID, err)
			break
		}
		chunkNum++
	}
}

func (sc *ServiceClient) handleSSHDataChunk(chunk protocol.SSHDataChunk) {
	sc.reqMu.RLock()
	activeReq, exists := sc.activeReqs[chunk.ID]
	sc.reqMu.RUnlock()

	if !exists {
		log.Printf("SSH connection %s not found", chunk.ID)
		return
	}

	conn, ok := activeReq.payload.(net.Conn)
	if !ok {
		log.Printf("Invalid payload type for SSH connection %s", chunk.ID)
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
			log.Printf("Failed to write SSH data: %v", err)
		}
	}

	if chunk.EOS {
		sc.reqMu.Lock()
		delete(sc.activeReqs, chunk.ID)
		sc.reqMu.Unlock()
		conn.Close()
		log.Printf("Closed SSH connection %s (EOS)", chunk.ID)
	}
}

func (sc *ServiceClient) handleRawRequestChunkWithEOS(chunk protocol.ProxyRawRequestChunkWithEOS) {
	sc.reqMu.RLock()
	activeReq, exists := sc.activeReqs[chunk.ID]
	sc.reqMu.RUnlock()

	if !exists {
		log.Printf("HTTP request %s not found", chunk.ID)
		return
	}

	// Ensure we have an HTTP buffer payload
	if activeReq.payload == nil {
		activeReq.payload = bytes.NewBuffer(nil)
	}

	httpBuffer, ok := activeReq.payload.(*bytes.Buffer)
	if !ok {
		log.Printf("Invalid payload type for HTTP request %s", chunk.ID)
		return
	}

	if chunk.Data != "" {
		data, err := base64.StdEncoding.DecodeString(chunk.Data)
		if err != nil {
			log.Printf("Failed to decode chunk: %v", err)
			return
		}

		activeReq.mu.Lock()
		httpBuffer.Write(data)
		activeReq.mu.Unlock()
	}

	if chunk.EOS {
		sc.executeRawRequest(activeReq)

		sc.reqMu.Lock()
		delete(sc.activeReqs, chunk.ID)
		sc.reqMu.Unlock()
	}
}

func (sc *ServiceClient) executeRawRequest(activeReq *ActiveRequest) {
	httpBuffer, ok := activeReq.payload.(*bytes.Buffer)
	if !ok {
		log.Printf("Invalid payload type for HTTP request %s", activeReq.ID)
		sc.sendErrorResponse(activeReq.ID, 500, "Invalid request payload")
		return
	}

	// Parse the raw HTTP data
	req, err := sc.createRequestFromRawHTTP(httpBuffer.String())
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

	// Dump the entire response as raw HTTP
	responseDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("Failed to dump response: %v", err)
		sc.sendErrorResponse(activeReq.ID, 500, "Failed to dump response")
		return
	}

	// Send raw response in chunks using the same chunk type
	chunkNum := 0
	responseData := responseDump
	totalSize := len(responseData)

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
			ID:       activeReq.ID,
			Data:     base64.StdEncoding.EncodeToString(responseData[offset:end]),
			EOS:      EOS,
			ChunkNum: chunkNum,
		}

		writeErr := sc.writeJSON(chunk)
		if writeErr != nil {
			log.Printf("Failed to send response chunk: %v", writeErr)
			return
		}
		chunkNum++
	}
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
	// Create a simple HTTP response
	errorResponse := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode, http.StatusText(statusCode), len(message), message)

	// Send as raw HTTP response chunks
	chunkNum := 0
	responseData := []byte(errorResponse)
	totalSize := len(responseData)

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
			Data:     base64.StdEncoding.EncodeToString(responseData[offset:end]),
			EOS:      EOS,
			ChunkNum: chunkNum,
		}

		sc.writeJSON(chunk)
		chunkNum++
	}
}

func (sc *ServiceClient) run() error {
	err := sc.connect()
	if err != nil {
		return err
	}
	defer sc.conn.Close()

	log.Printf("Service client running - forwarding %s.%s:8443 -> localhost:%s",
		sc.subdomain, sc.serverDomain, sc.localPort)

	if sc.sshPort > 0 {
		log.Printf("SSH tunnel enabled - users can connect with:")
		log.Printf("  ssh -o 'VersionAddendum %s' user@%s -p 2200", sc.subdomain, sc.serverDomain)
	}

	sc.handleRequests()
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
	// Print version information
	log.Printf("Pontivex Client %s (built %s, commit %s)", version, buildDate, gitCommit)

	// First pass: define all flags but only use config and version
	configFile := flag.String("config", "", "Path to YAML configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	// Define other flags but don't use their values yet
	flag.String("server", "", "Server domain name")
	flag.String("subdomain", "", "App subdomain to serve requests")
	flag.String("token", "", "Authentication token")
	flag.String("port", "", "Local port to forward requests to")
	flag.String("server-port", "7000", "Server port number")
	flag.Int("ssh-port", 0, "Local SSH port to forward SSH connections to (0 to disable)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Pontivex Client %s\n", version)
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
	serverDomain := flag.String("server", config.ServerDomain, "Server domain name")
	subdomain := flag.String("subdomain", config.Subdomain, "App subdomain to serve requests")
	authToken := flag.String("token", config.AuthToken, "Authentication token")
	localPort := flag.String("port", config.LocalPort, "Local port to forward requests to")
	serverPortFlag := flag.String("server-port", config.ServerPort, "Server port number")
	sshPortFlag := flag.Int("ssh-port", config.SSHPort, "Local SSH port to forward SSH connections to (0 to disable)")

	flag.Parse()

	// Copy flag values back to config (flags override config file values)
	config.ServerDomain = *serverDomain
	config.Subdomain = *subdomain
	config.AuthToken = *authToken
	config.LocalPort = *localPort
	config.ServerPort = *serverPortFlag
	config.SSHPort = *sshPortFlag

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	// Set global server port
	serverPort = config.ServerPort

	client := NewServiceClient(config.ServerDomain, config.Subdomain, config.AuthToken, config.LocalPort)

	// Enable SSH if configured
	if config.SSHPort > 0 {
		client.EnableSSH(config.SSHPort)
	}

	for {
		err := client.run()
		if err != nil {
			log.Printf("Service client error: %v", err)
			log.Println("Retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
		}
	}
}
