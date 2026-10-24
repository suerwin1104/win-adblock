package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var (
	Version   = "1.0.0"
	BuildDate = "2026-10"
)

func printBanner() {
	banner := `
==============================================================
   WinAdBlock — Windows Native 40-bit FNV-1a DNS Sinkhole
   移植自 M-Abozaid/esp32-c3-adblock 架構 (極致輕量 & 高效)
==============================================================`
	fmt.Println(banner)
}

func main() {
	printBanner()

	// Command line flags
	listenIP := flag.String("listen", "127.0.0.1", "DNS 監聽 IP 位址 (例如 127.0.0.1 或 0.0.0.0 供全 LAN 使用)")
	dnsPort := flag.Int("port", 53, "DNS 監聽 UDP 埠號 (預設 53)")
	webAddr := flag.String("web", "127.0.0.1:8080", "Web 儀表板與 API 監聽位址")
	upstream := flag.String("upstream", "9.9.9.9:53", "上游 DNS 伺服器位址 (例如 Quad9 9.9.9.9:53 或 1.1.1.1:53)")
	cacheFile := flag.String("cache", "blocklist.bin", "本地 40-bit 雜湊二進位快取檔路徑")
	updateNow := flag.Bool("update-now", false, "啟動時強制自知名組織線上拉取最新黑名單")
	updateIntervalH := flag.Int("update-interval", 24, "定時自動更新間隔 (小時，0 代表不停更)")
	flag.Parse()

	// Ensure absolute path or local relative path
	absCache, err := filepath.Abs(*cacheFile)
	if err != nil {
		absCache = *cacheFile
	}

	// 1. Initialize Blocklist
	bl := NewBlocklist()

	// Try loading from local binary cache first
	hasCache := false
	if _, err := os.Stat(absCache); err == nil {
		if err := bl.LoadBin(absCache); err == nil {
			hasCache = true
		}
	}

	// 2. Decide if initial online download is required
	if !hasCache || *updateNow {
		log.Println("[Init] 正在自知名組織 (StevenBlack, Hagezi, URLHaus) 下載並建置 40-bit 雜湊名單...")
		go func() {
			if err := bl.FetchAndBuild(DefaultSources, absCache); err != nil {
				log.Printf("[Init] 初次更新失敗: %v", err)
			}
		}()
	}

	// 3. Setup scheduled auto-updater
	if *updateIntervalH > 0 {
		ticker := time.NewTicker(time.Duration(*updateIntervalH) * time.Hour)
		go func() {
			for range ticker.C {
				log.Println("[Cron] 觸發排程定期更新黑名單...")
				_ = bl.FetchAndBuild(DefaultSources, absCache)
			}
		}()
	}

	// 4. Initialize DNS Server
	dnsAddr := fmt.Sprintf("%s:%d", *listenIP, *dnsPort)
	dnsServer := NewDNSServer(dnsAddr, *upstream, bl)

	go func() {
		if err := dnsServer.Start(); err != nil {
			log.Printf("\n[錯誤] DNS 伺服器啟動失敗: %v", err)
			log.Println("提示:")
			log.Println(" 1. 綁定 UDP 53 埠通常需要 Windows 系統「以系統管理員身分執行」。")
			log.Println(" 2. 若連接埠 53 被 Windows 系統服務 (ICS/Hyper-V/DNS Client) 佔用，請嘗試使用參數: -port 1053")
			log.Println(" 3. 測試時可使用: -listen 127.0.0.1 -port 1053\n")
		}
	}()

	// 5. Initialize Web Dashboard Server
	webServer := NewWebServer(*webAddr, dnsServer, DefaultSources, absCache)
	go func() {
		if err := webServer.Start(); err != nil {
			log.Printf("[Web] Web 伺服器啟動失敗: %v", err)
		}
	}()

	fmt.Printf("\n>>> 系統就緒！\n")
	fmt.Printf(" * DNS 服務位址: UDP %s\n", dnsAddr)
	fmt.Printf(" * Web 儀表板: http://%s\n", *webAddr)
	fmt.Printf(" * 快取檔案路徑: %s\n", absCache)
	fmt.Println(" * 按 Ctrl+C 可優雅停止伺服器...\n")

	// 6. Graceful Shutdown on SIGINT/SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[系統] 收到中斷信號，正在清理資源並安全退出...")
	dnsServer.Close()
	time.Sleep(500 * time.Millisecond)
	log.Println("[系統] 服務已停止。")
}
