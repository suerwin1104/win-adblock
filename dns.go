package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// QueryLogEntry represents a single DNS query record for dashboard display.
type QueryLogEntry struct {
	Timestamp string `json:"timestamp"`
	ClientIP  string `json:"client_ip"`
	Domain    string `json:"domain"`
	QType     string `json:"qtype"`
	Blocked   bool   `json:"blocked"`
	Reason    string `json:"reason"`
}

// DNSServer encapsulates the UDP listener, blocklist reference, and forwarder.
type DNSServer struct {
	ListenAddr   string
	UpstreamAddr string
	Blocklist    *Blocklist

	// Statistics
	TotalQueries uint64
	TotalBlocked uint64
	TotalAllowed uint64

	// Blocking state (support pause for N minutes)
	BlockingEnabled atomic.Bool
	ResumeAt        time.Time
	pauseMu         sync.Mutex

	// Query Ring Buffer
	logMu    sync.RWMutex
	queryLog []QueryLogEntry
	maxLogs  int

	udpConn *net.UDPConn
	closing atomic.Bool
}

// NewDNSServer initializes a new DNS Server instance.
func NewDNSServer(listenAddr, upstreamAddr string, bl *Blocklist) *DNSServer {
	s := &DNSServer{
		ListenAddr:   listenAddr,
		UpstreamAddr: upstreamAddr,
		Blocklist:    bl,
		maxLogs:      100,
		queryLog:     make([]QueryLogEntry, 0, 100),
	}
	s.BlockingEnabled.Store(true)
	return s
}

// RecordLog adds a query entry into the ring buffer.
func (s *DNSServer) RecordLog(entry QueryLogEntry) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if len(s.queryLog) >= s.maxLogs {
		s.queryLog = s.queryLog[1:]
	}
	s.queryLog = append(s.queryLog, entry)
}

// GetLogs returns a snapshot of recent queries.
func (s *DNSServer) GetLogs() []QueryLogEntry {
	s.logMu.RLock()
	defer s.logMu.RUnlock()
	res := make([]QueryLogEntry, len(s.queryLog))
	copy(res, s.queryLog)
	return res
}

// PauseBlocking temporarily disables sinkhole filtering for specified seconds.
func (s *DNSServer) PauseBlocking(seconds int) {
	s.pauseMu.Lock()
	defer s.pauseMu.Unlock()
	s.BlockingEnabled.Store(false)
	if seconds > 0 {
		s.ResumeAt = time.Now().Add(time.Duration(seconds) * time.Second)
	} else {
		s.ResumeAt = time.Time{} // paused indefinitely
	}
	log.Printf("[DNS] 阻擋功能已暫停 (%d 秒)", seconds)
}

// ResumeBlocking immediately enables sinkhole filtering.
func (s *DNSServer) ResumeBlocking() {
	s.pauseMu.Lock()
	defer s.pauseMu.Unlock()
	s.BlockingEnabled.Store(true)
	s.ResumeAt = time.Time{}
	log.Println("[DNS] 阻擋功能已恢復啟用")
}

// CheckPauseExpiration checks if the pause timer has elapsed.
func (s *DNSServer) CheckPauseExpiration() {
	s.pauseMu.Lock()
	defer s.pauseMu.Unlock()
	if !s.BlockingEnabled.Load() && !s.ResumeAt.IsZero() {
		if time.Now().After(s.ResumeAt) {
			s.BlockingEnabled.Store(true)
			s.ResumeAt = time.Time{}
			log.Println("[DNS] 暫停時間結束，自動恢復阻擋")
		}
	}
}

// Start begins listening and serving DNS queries over UDP.
func (s *DNSServer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen address error: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("bind UDP port error: %w", err)
	}
	s.udpConn = conn

	log.Printf("[DNS] 伺服器成功監聽於 UDP %s (上游解析伺服器: %s)", s.ListenAddr, s.UpstreamAddr)

	buf := make([]byte, 2048)
	for {
		if s.closing.Load() {
			break
		}
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if s.closing.Load() {
				break
			}
			continue
		}

		// Handle packet concurrently in goroutine
		pktCopy := make([]byte, n)
		copy(pktCopy, buf[:n])
		go s.handlePacket(pktCopy, clientAddr)
	}
	return nil
}

// Close terminates the DNS server socket.
func (s *DNSServer) Close() {
	s.closing.Store(true)
	if s.udpConn != nil {
		s.udpConn.Close()
	}
}

// parseQuery parses QNAME, QTYPE, and question end offset from wire format.
func parseQuery(pkt []byte) (domain string, qend int, qtype uint16, err error) {
	if len(pkt) < 13 {
		return "", 0, 0, fmt.Errorf("packet too short")
	}

	labels := make([]string, 0, 6)
	curr := 12
	for curr < len(pkt) {
		length := int(pkt[curr])
		if length == 0 {
			curr++
			break
		}
		// Compression pointers in question not standard in simple queries, but guard against:
		if (length & 0xC0) != 0 {
			return "", 0, 0, fmt.Errorf("compression pointer in question unsupported")
		}
		curr++
		if curr+length > len(pkt) {
			return "", 0, 0, fmt.Errorf("malformed label length")
		}
		labels = append(labels, strings.ToLower(string(pkt[curr:curr+length])))
		curr += length
	}

	if curr+4 > len(pkt) {
		return "", 0, 0, fmt.Errorf("missing qtype/qclass")
	}

	qtype = binary.BigEndian.Uint16(pkt[curr : curr+2])
	// qclass = binary.BigEndian.Uint16(pkt[curr+2 : curr+4])
	qend = curr + 4
	domain = strings.Join(labels, ".")
	return domain, qend, qtype, nil
}

// buildBlockedAnswer creates a sinkhole response (0.0.0.0 for A, :: for AAAA).
func buildBlockedAnswer(pkt []byte, qend int, qtype uint16) []byte {
	resp := make([]byte, qend, qend+32)
	copy(resp, pkt[:qend])

	// Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0 (0x8180)
	resp[2] = 0x81
	resp[3] = 0x80

	// QDCOUNT = 1 (preserve)
	// ANCOUNT = 1 if A or AAAA, else 0
	if qtype == 1 || qtype == 28 {
		resp[6] = 0x00
		resp[7] = 0x01
	} else {
		resp[6] = 0x00
		resp[7] = 0x00
	}
	resp[8] = 0x00
	resp[9] = 0x00
	resp[10] = 0x00
	resp[11] = 0x00

	if qtype == 1 {
		// A record: Pointer (0xC00C), Type A (1), Class IN (1), TTL 300, RDLEN 4, 0.0.0.0
		ans := []byte{
			0xC0, 0x0C,
			0x00, 0x01,
			0x00, 0x01,
			0x00, 0x00, 0x01, 0x2C, // 300s TTL
			0x00, 0x04,
			0x00, 0x00, 0x00, 0x00, // 0.0.0.0
		}
		resp = append(resp, ans...)
	} else if qtype == 28 {
		// AAAA record: Pointer (0xC00C), Type AAAA (28), Class IN (1), TTL 300, RDLEN 16, ::
		ans := []byte{
			0xC0, 0x0C,
			0x00, 0x1C,
			0x00, 0x01,
			0x00, 0x00, 0x01, 0x2C,
			0x00, 0x10,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		resp = append(resp, ans...)
	}

	return resp
}

func qtypeToString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// handlePacket processes an individual DNS query.
func (s *DNSServer) handlePacket(pkt []byte, clientAddr *net.UDPAddr) {
	atomic.AddUint64(&s.TotalQueries, 1)
	s.CheckPauseExpiration()

	domain, qend, qtype, err := parseQuery(pkt)
	if err != nil {
		// Malformed query, forward or ignore
		return
	}

	isBlocked := false
	matchReason := ""

	if s.BlockingEnabled.Load() {
		blocked, reason := s.Blocklist.IsBlocked(domain)
		if blocked {
			isBlocked = true
			matchReason = reason
		}
	}

	nowStr := time.Now().Format("15:04:05")

	if isBlocked {
		atomic.AddUint64(&s.TotalBlocked, 1)
		resp := buildBlockedAnswer(pkt, qend, qtype)
		s.udpConn.WriteToUDP(resp, clientAddr)

		s.RecordLog(QueryLogEntry{
			Timestamp: nowStr,
			ClientIP:  clientAddr.IP.String(),
			Domain:    domain,
			QType:     qtypeToString(qtype),
			Blocked:   true,
			Reason:    matchReason,
		})
	} else {
		atomic.AddUint64(&s.TotalAllowed, 1)
		// Forward to upstream
		go s.forwardUpstream(pkt, clientAddr)

		s.RecordLog(QueryLogEntry{
			Timestamp: nowStr,
			ClientIP:  clientAddr.IP.String(),
			Domain:    domain,
			QType:     qtypeToString(qtype),
			Blocked:   false,
			Reason:    "allowed",
		})
	}
}

// forwardUpstream relays the query to the configured upstream DNS server and returns the answer.
func (s *DNSServer) forwardUpstream(pkt []byte, clientAddr *net.UDPAddr) {
	upConn, err := net.DialTimeout("udp", s.UpstreamAddr, 2*time.Second)
	if err != nil {
		return
	}
	defer upConn.Close()

	_ = upConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	if _, err := upConn.Write(pkt); err != nil {
		return
	}

	resp := make([]byte, 2048)
	n, err := upConn.Read(resp)
	if err != nil || n < 12 {
		return
	}

	if s.udpConn != nil {
		s.udpConn.WriteToUDP(resp[:n], clientAddr)
	}
}
