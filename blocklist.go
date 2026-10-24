package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	FNVOffset uint64 = 0xcbf29ce484222325
	FNVPrime  uint64 = 0x100000001b3
	HashBytes        = 5
	HashMask  uint64 = (1 << (HashBytes * 8)) - 1 // 40-bit mask
)

// FNV40 calculates the 40-bit FNV-1a hash, matching esp32-c3-adblock exactly.
func FNV40(s string) uint64 {
	h := FNVOffset
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= FNVPrime
	}
	return h & HashMask
}

// NormalizeDomain standardizes domain strings (lowercase, trim whitespace/dots, remove www. prefix).
func NormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.Trim(d, "*.")
	if strings.HasPrefix(d, "www.") {
		d = d[4:]
	}
	return d
}

// BlocklistSource defines an online blocklist provider.
type BlocklistSource struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"` // "auto", "hosts", "domains", "adguard"
}

// DefaultSources provides reputable, high-quality, safe-for-daily-use blocklists.
var DefaultSources = []BlocklistSource{
	{
		Name:    "StevenBlack Unified Hosts",
		URL:     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Enabled: true,
		Type:    "hosts",
	},
	{
		Name:    "Hagezi Light DNS Blocklist",
		URL:     "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
		Enabled: true,
		Type:    "domains",
	},
	{
		Name:    "URLHaus Malware Filter",
		URL:     "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-hosts.txt",
		Enabled: true,
		Type:    "hosts",
	},
}

// Blocklist holds the in-memory sorted 40-bit hashes and custom rules.
type Blocklist struct {
	mu           sync.RWMutex
	hashes       []uint64
	customBlocks map[uint64]string
	customAllow  map[uint64]string
	sourcesStats map[string]int
	updatedAt    time.Time
	totalDomains int
}

// NewBlocklist initializes an empty Blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{
		hashes:       make([]uint64, 0),
		customBlocks: make(map[uint64]string),
		customAllow:  make(map[uint64]string),
		sourcesStats: make(map[string]int),
		updatedAt:    time.Now(),
	}
}

// Contains checks if a 40-bit hash exists in the sorted slice via binary search.
func (b *Blocklist) Contains(h uint64) bool {
	n := len(b.hashes)
	if n == 0 {
		return false
	}
	idx := sort.Search(n, func(i int) bool {
		return b.hashes[i] >= h
	})
	return idx < n && b.hashes[idx] == h
}

// IsBlocked performs suffix-level checking against the blocklist and custom rules.
func (b *Blocklist) IsBlocked(domain string) (blocked bool, matchedRule string) {
	d := NormalizeDomain(domain)
	if d == "" {
		return false, ""
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// 1. Check Allowlist (whitelisting has highest priority)
	parts := strings.Split(d, ".")
	for i := 0; i < len(parts)-1; i++ {
		sub := strings.Join(parts[i:], ".")
		h := FNV40(sub)
		if _, ok := b.customAllow[h]; ok {
			return false, ""
		}
	}

	// 2. Check Custom Blocklist
	for i := 0; i < len(parts)-1; i++ {
		sub := strings.Join(parts[i:], ".")
		h := FNV40(sub)
		if orig, ok := b.customBlocks[h]; ok {
			return true, "custom:" + orig
		}
	}

	// 3. Check 40-bit Flash/Memory Blocklist
	for i := 0; i < len(parts)-1; i++ {
		sub := strings.Join(parts[i:], ".")
		h := FNV40(sub)
		if b.Contains(h) {
			return true, sub
		}
	}

	return false, ""
}

// AddCustomBlock adds a custom domain to block.
func (b *Blocklist) AddCustomBlock(domain string) {
	d := NormalizeDomain(domain)
	if d == "" || !strings.Contains(d, ".") {
		return
	}
	h := FNV40(d)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.customBlocks[h] = d
	delete(b.customAllow, h)
}

// RemoveCustomBlock removes a custom domain from blocklist.
func (b *Blocklist) RemoveCustomBlock(domain string) {
	d := NormalizeDomain(domain)
	h := FNV40(d)
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.customBlocks, h)
}

// AddCustomAllow adds a domain to whitelist.
func (b *Blocklist) AddCustomAllow(domain string) {
	d := NormalizeDomain(domain)
	if d == "" || !strings.Contains(d, ".") {
		return
	}
	h := FNV40(d)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.customAllow[h] = d
	delete(b.customBlocks, h)
}

// RemoveCustomAllow removes a domain from whitelist.
func (b *Blocklist) RemoveCustomAllow(domain string) {
	d := NormalizeDomain(domain)
	h := FNV40(d)
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.customAllow, h)
}

// SaveBin saves hashes in the exact 5-byte little-endian format compatible with esp32-c3-adblock.
func (b *Blocklist) SaveBin(filePath string) error {
	b.mu.RLock()
	hashes := make([]uint64, len(b.hashes))
	copy(hashes, b.hashes)
	b.mu.RUnlock()

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create file error: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	buf := make([]byte, HashBytes)
	for _, h := range hashes {
		buf[0] = byte(h)
		buf[1] = byte(h >> 8)
		buf[2] = byte(h >> 16)
		buf[3] = byte(h >> 24)
		buf[4] = byte(h >> 32)
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	return w.Flush()
}

// LoadBin loads precompiled 5-byte hashes from binary file.
func (b *Blocklist) LoadBin(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	total := len(data) / HashBytes
	hashes := make([]uint64, total)
	for i := 0; i < total; i++ {
		off := i * HashBytes
		h := uint64(data[off]) |
			(uint64(data[off+1]) << 8) |
			(uint64(data[off+2]) << 16) |
			(uint64(data[off+3]) << 24) |
			(uint64(data[off+4]) << 32)
		hashes[i] = h
	}

	b.mu.Lock()
	b.hashes = hashes
	b.totalDomains = total
	b.updatedAt = time.Now()
	b.sourcesStats["local_cache"] = total
	b.mu.Unlock()

	log.Printf("[Blocklist] 成功載入本地二進位快取 %s，共 %d 筆 40-bit 雜湊", filePath, total)
	return nil
}

// FetchAndBuild downloads lists from configured sources, parses, deduplicates, and hot-updates the blocklist.
func (b *Blocklist) FetchAndBuild(sources []BlocklistSource, saveBinPath string) error {
	client := &http.Client{
		Timeout: 45 * time.Second,
	}

	rawHashes := make([]uint64, 0, 300000)
	stats := make(map[string]int)
	allowMap := make(map[uint64]bool)

	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		log.Printf("[Updater] 正在下載知名來源: %s (%s)...", src.Name, src.URL)
		req, err := http.NewRequest("GET", src.URL, nil)
		if err != nil {
			log.Printf("[Updater] 建立請求失敗 (%s): %v", src.Name, err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WinAdBlock/1.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[Updater] 下載失敗 (%s): %v", src.Name, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf("[Updater] 來源回應非 200 狀態碼 (%s): HTTP %d", src.Name, resp.StatusCode)
			continue
		}

		count := 0
		scanner := bufio.NewScanner(resp.Body)
		// Set scanner buffer up to 1MB per line
		buf := make([]byte, 1024*1024)
		scanner.Buffer(buf, len(buf))

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") {
				continue
			}

			// Handle AdGuard allow rules (@@||domain^)
			if strings.HasPrefix(line, "@@||") {
				d := strings.TrimPrefix(line, "@@||")
				if idx := strings.IndexAny(d, "^$/"); idx != -1 {
					d = d[:idx]
				}
				d = NormalizeDomain(d)
				if d != "" && strings.Contains(d, ".") {
					allowMap[FNV40(d)] = true
				}
				continue
			}

			// Handle AdGuard block rules (||domain^)
			if strings.HasPrefix(line, "||") {
				d := strings.TrimPrefix(line, "||")
				if idx := strings.IndexAny(d, "^$/"); idx != -1 {
					d = d[:idx]
				}
				d = NormalizeDomain(d)
				if d != "" && strings.Contains(d, ".") {
					rawHashes = append(rawHashes, FNV40(d))
					count++
				}
				continue
			}

			// Handle hosts format (0.0.0.0 domain or 127.0.0.1 domain)
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
				for _, dom := range fields[1:] {
					if strings.HasPrefix(dom, "#") {
						break
					}
					d := NormalizeDomain(dom)
					if d != "" && d != "localhost" && d != "local" && strings.Contains(d, ".") {
						rawHashes = append(rawHashes, FNV40(d))
						count++
					}
				}
				continue
			}

			// Handle raw domain list
			d := NormalizeDomain(line)
			if d != "" && strings.Contains(d, ".") && !strings.ContainsAny(d, " /\\:;*?\"<>|") {
				rawHashes = append(rawHashes, FNV40(d))
				count++
			}
		}
		resp.Body.Close()

		if err := scanner.Err(); err != nil && err != io.EOF {
			log.Printf("[Updater] 讀取來源數據時發生警告 (%s): %v", src.Name, err)
		}
		stats[src.Name] = count
		log.Printf("[Updater] %s 解析完成，收錄 %d 筆網域", src.Name, count)
	}

	if len(rawHashes) == 0 {
		return fmt.Errorf("未能從任何線上來源取得網域名稱")
	}

	// Filter out allowlisted hashes
	filtered := make([]uint64, 0, len(rawHashes))
	for _, h := range rawHashes {
		if !allowMap[h] {
			filtered = append(filtered, h)
		}
	}

	// Sort and deduplicate
	log.Printf("[Updater] 正在進行 40-bit 雜湊排序與去重 (原始筆數: %d)...", len(filtered))
	sort.Slice(filtered, func(i, j int) bool { return filtered[i] < filtered[j] })

	uniqueHashes := filtered[:0]
	var last uint64
	for i, h := range filtered {
		if i == 0 || h != last {
			uniqueHashes = append(uniqueHashes, h)
			last = h
		}
	}

	// Atomically swap in-memory list
	b.mu.Lock()
	b.hashes = uniqueHashes
	b.sourcesStats = stats
	b.updatedAt = time.Now()
	b.totalDomains = len(uniqueHashes)
	b.mu.Unlock()

	log.Printf("[Updater] 更新成功！最終收錄 %d 筆不重複 40-bit 雜湊阻擋規則", len(uniqueHashes))

	// Persist to disk as cache
	if saveBinPath != "" {
		if err := b.SaveBin(saveBinPath); err != nil {
			log.Printf("[Updater] 警告: 儲存本地快取失敗: %v", err)
		} else {
			log.Printf("[Updater] 已成功持久化至本地二進位快取: %s", saveBinPath)
		}
	}

	return nil
}

// Stats returns a summary snapshot of the blocklist.
func (b *Blocklist) Stats() (total int, updatedAt string, sources map[string]int, customBlockCount int, customAllowCount int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	cpSources := make(map[string]int)
	for k, v := range b.sourcesStats {
		cpSources[k] = v
	}
	return b.totalDomains, b.updatedAt.Format("2006-01-02 15:04:05"), cpSources, len(b.customBlocks), len(b.customAllow)
}
