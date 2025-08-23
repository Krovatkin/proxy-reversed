package protocol

const ChunkSize = 256 * 1024          // 64KiB chunks
const MessageLimit = 16 * 1024 * 1024 // 16MiB

// Registration message
type RegistrationMessage struct {
	Type      string `json:"type"`
	Subdomain string `json:"subdomain"`
	AuthToken string `json:"auth_token"`
}

type ProxyBaseMessage struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	ChunkNum int    `json:"chunk_num"`
}

// Request messages
type ProxyRequestStart struct {
	Type          string            `json:"type"` // "request_start"
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers"`
	ID            string            `json:"id"`
	ContentLength int64             `json:"content_length"`
	ChunkNum      int               `json:"chunk_num"`
	// HasBody       bool              `json:"has_body"`
}

type ProxyRequestChunk struct {
	Type     string `json:"type"` // "request_chunk"
	ID       string `json:"id"`
	Data     string `json:"data"` // base64 encoded
	ChunkNum int    `json:"chunk_num"`
}

type ProxyRequestEnd struct {
	Type     string `json:"type"` // "request_end"
	ID       string `json:"id"`
	ChunkNum int    `json:"chunk_num"`
}

// Response messages
type ProxyResponseStart struct {
	Type       string            `json:"type"` // "response_start"
	ID         string            `json:"id"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	ChunkNum   int               `json:"chunk_num"`
	// HasBody    bool              `json:"has_body"`
}

type ProxyResponseChunk struct {
	Type     string `json:"type"` // "response_chunk"
	ID       string `json:"id"`
	Data     string `json:"data"`
	ChunkNum int    `json:"chunk_num"`
}

type ProxyResponseEnd struct {
	Type     string `json:"type"` // "response_end"
	ID       string `json:"id"`
	ChunkNum int    `json:"chunk_num"`
}

type ProxyRawRequestStart struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	TotalSize int    `json:"total_size"`
	ChunkNum  int    `json:"chunk_num"`
}

type ProxyRawRequestChunk struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Data     string `json:"data"` // base64 encoded chunk
	ChunkNum int    `json:"chunk_num"`
}
type ProxyRawRequestChunkWithEOS struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	EOS      bool   `json:"eos"`
	Data     string `json:"data"` // base64 encoded chunk
	ChunkNum int    `json:"chunk_num"`
}

type ProxyRawRequestEnd struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	ChunkNum int    `json:"chunk_num"`
}
