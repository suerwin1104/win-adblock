# WinAdBlock (Windows Native 40-bit FNV-1a DNS Sinkhole)

[![GitHub Repo](https://img.shields.io/badge/GitHub-suerwin1104%2Fwin--adblock-181717?logo=github)](https://github.com/suerwin1104/win-adblock)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6?logo=windows)](https://github.com/suerwin1104/win-adblock)
[![Language](https://img.shields.io/badge/Language-Go%201.26-00ADD8?logo=go)](https://golang.org/)
[![Memory Footprint](https://img.shields.io/badge/RAM%20Usage-~2--6%20MB-success)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/suerwin1104/win-adblock/blob/main/LICENSE)

**WinAdBlock** 是一套專為 Windows 環境量身打造的原生、超輕量、微秒級 DNS 廣告與惡意網站阻擋中樞（DNS Sinkhole）。專案原始碼託管於 GitHub：[https://github.com/suerwin1104/win-adblock](https://github.com/suerwin1104/win-adblock)。

本專案的核心思想與演算法架構移植自知名熱門開源專案 **[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)**。透過其創新的 **40-bit (5-Byte) FNV-1a 雜湊檢索機制**，突破了傳統 DNS 阻擋器動輒耗費數百 MB 記憶體的限制，在 Windows 上僅需 **2 ~ 6 MB RAM** 即可輕鬆乘載 12 萬至 50 萬筆阻擋網域，並提供**隨時線上熱更新**全球知名資安組織黑名單之能力。

---

## 📑 目錄

- [一、專案緣起與致謝 (Acknowledgments & Credits)](#一專案緣起與致謝-acknowledgments--credits)
- [二、核心架構與專案特色 (Features & Architecture)](#二核心架構與專案特色-features--architecture)
- [三、快速上手與使用方式 (Quick Start & Usage)](#三快速上手與使用方式-quick-start--usage)
  - [1. 啟動 WinAdBlock 服務](#1-啟動-winadblock-服務)
  - [2. 將 Windows 網路卡 DNS 指向本機](#2-將-windows-網路卡-dns-指向本機)
  - [3. 透過 Web 控制儀表板管理](#3-透過-web-控制儀表板管理)
  - [4. 驗證阻擋效果](#4-驗證阻擋效果)
- [四、命令列參數說明 (CLI Flags)](#四命令列參數說明-cli-flags)
- [五、實務注意事項與故障排除 (Notes & Troubleshooting)](#五實務注意事項與故障排除-notes--troubleshooting)
- [六、開源授權與免責聲明 (License & Disclaimer)](#六開源授權與免責聲明-license--disclaimer)

---

## 一、專案緣起與致謝 (Acknowledgments & Credits)

在此向以下開源社群、專案作者與資安組織致上最誠摯的感謝：

1. **[M-Abozaid / esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)**  
   * **作者**：Zed ([@M-Abozaid](https://github.com/M-Abozaid))
   * **貢獻**：原作者極具巧思地提出「將網域以 40-bit FNV-1a 截斷雜湊儲存於 Flash 並進行二分檢索」的架構，以生日悖論推導出 40 位元為容量與碰撞率的最佳平衡點。本專案以此數學原理為基礎，成功實現了 Windows 原生作業系統級別的極致輕量化移植。
2. **[StevenBlack / hosts](https://github.com/StevenBlack/hosts)**  
   * **作者**：Steven Black 與全球開源貢獻者
   * **貢獻**：提供全球最受信賴、整合多重過濾來源之廣告、惡意網站與追蹤器標準清單。
3. **[HaGeZi / dns-blocklists](https://github.com/hagezi/dns-blocklists)**  
   * **作者**：HaGeZi
   * **貢獻**：維護極高品質、誤報率極低的「Light / Multi」DNS 封鎖名單，專為一般家庭與日常通訊環境調校，不誤擋 LINE、WhatsApp 等社交通訊軟體。
4. **[URLHaus (abuse.ch)](https://urlhaus.abuse.ch/)**  
   * **組織**：瑞士伯恩應用科技大學資安研究專案 abuse.ch
   * **貢獻**：提供全球活躍惡意軟體、勒索軟體散播網域的即時防禦威脅情報。
5. **[Quad9 (9.9.9.9)](https://www.quad9.net/)**  
   * **貢獻**：具備威脅攔截與隱私保障的非營利公共 DNS 遞迴解析服務，作為 WinAdBlock 的預設安全上游解析器。

---

## 二、核心架構與專案特色 (Features & Architecture)

### 1. 40-bit (5-Byte) FNV-1a 雜湊檢索機制
* **極高壓縮比**：捨棄傳統在記憶體中存放龐大網域字串（Strings-in-RAM）的作法，改為將所有阻擋網域壓縮為 5 位元組（40-bit）的截斷 FNV-1a 雜湊值。
* **數學碰撞平衡**：根據生日悖論（Birthday Bound），在 14 萬筆網域下碰撞率期望值趨近於 $0$；即便擴充至 50 萬筆，碰撞數也僅約 $1$ 筆，兼具極致壓縮與精準阻擋。

### 2. 微秒級檢索 (<100 奈秒) 與極致記憶體節約
* 採用排序連續記憶體陣列（Sorted Slice）配合 CPU 快取親和性優化二分搜尋（Binary Search）。
* 載入超過 **120,000 筆** 知名組織黑名單時，整體系統 RAM 佔用僅 **~2 MB 至 6 MB**，檢索耗時小於 **100 奈秒 (ns)**，相較傳統 Docker 容器或大型軟體方案減少了 98% 以上的資源消耗。

### 3. 無鎖零停機線上熱更新 (Zero-Downtime Hot-Swap)
* **隨時一鍵更新**：支援 Web 介面即時按鈕、定時背景排程（預設每 24 小時）以及 REST API (`POST /api/update`)。
* **背景無感替換**：背景線程自知名組織並行抓取、多格式解析（Hosts 格式、AdGuard `||domain^` / `@@||domain^` 語法、純網域名單）、自動去重與排序；透過**原子指標切換（Atomic Pointer Swap）**瞬間完成熱替換，DNS 查詢服務完全不中斷、無鎖競爭（Lock-free）。

### 4. 雙棧協定阻擋 (Dual-Stack IPv4 & IPv6 Sinkhole)
* **IPv4 (A 紀錄)**：命中時立即回覆 `0.0.0.0`（TTL 300 秒）。
* **IPv6 (AAAA 紀錄)**：原生支援回覆 `::`，徹底封鎖現代 IPv6 廣告流量。
* **其他查詢 (HTTPS/TXT/CNAME)**：自動回覆 NOERROR 空白應答，強制客戶端快速終止連線。

### 5. 獨立純綠色單一執行檔
* 編譯為單一靜態二進位檔案 **`win-adblock.exe`**（~6.9 MB），無須安裝 Python、Node.js、Java 或 Docker 環境，隨開即用。

### 6. 現代化內嵌 Web 控制儀表板 (http://127.0.0.1:8080)
* **即時統計看板**：監控總查詢次數、攔截次數、正常放行次數、阻擋百分比與即時記憶體佔用。
* **即時查詢日誌**：以 Ring Buffer 保留最近 100 筆查詢紀錄（時間、來源 IP、網域名稱、查詢類型、攔截原因）。
* **快捷暫停開關**：支援一鍵暫停阻擋 5 分鐘或 1 小時，倒數計時結束自動恢復，方便排查誤擋。
* **即時網域模擬測試**：直接在介面上輸入網域名稱，即時檢視二分搜尋與多層子網域比對路徑。
* **自訂黑白名單**：支援手動增刪自訂網域（自訂白名單具有最高優先覆蓋權）。

---

## 三、快速上手與使用方式 (Quick Start & Usage)

### 0. 取得專案原始碼與執行檔
```bash
git clone https://github.com/suerwin1104/win-adblock.git
cd win-adblock
```

### 1. 啟動 WinAdBlock 服務

> **重要說明**：DNS 服務預設使用 UDP 連接埠 `53`。在 Windows 系統中，綁定 1024 以下的特權連接埠需要**「系統管理員權限」**。

我們提供了兩種全自動處理提權的啟動腳本：

#### 方式 A：直接執行批次檔（最推薦，支援自動提權）
在檔案總管中直接雙擊，或於終端機執行：
```cmd
cd c:\Users\USER\LazyBridge\tools\win-adblock
run.bat
```
*(若彈出 Windows UAC 使用者帳戶控制確認視窗，請點擊「是」)*

#### 方式 B：透過 PowerShell 啟動
以 PowerShell 執行：
```powershell
cd c:\Users\USER\LazyBridge\tools\win-adblock
.\run.ps1
```

#### 方式 C：以命令提示字元直接執行 EXE（自訂參數）
以系統管理員身分開啟 CMD 執行：
```cmd
cd c:\Users\USER\LazyBridge\tools\win-adblock
win-adblock.exe -listen 0.0.0.0 -port 53 -web 127.0.0.1:8080 -update-interval 24
```

---

### 2. 將 Windows 網路卡 DNS 指向本機

服務啟動後，需將 Windows 網路連線的 DNS 伺服器指向 `127.0.0.1` 才能使整台電腦生效。我們內附了便利的切換腳本：

以系統管理員身分執行 PowerShell：
```powershell
cd c:\Users\USER\LazyBridge\tools\win-adblock

# 1. 啟用本機阻擋 (將活動中網路卡的 DNS 指向 127.0.0.1)
.\setup_dns.ps1 enable

# 2. 檢視目前網路卡 DNS 設定狀態
.\setup_dns.ps1 status

# 3. 停止使用時，隨時一鍵還原為 DHCP 自動取得
.\setup_dns.ps1 disable
```

---

### 3. 透過 Web 控制儀表板管理

打開瀏覽器訪問：**[http://127.0.0.1:8080](http://127.0.0.1:8080)**

* **立即更新知名組織名單**：點擊首頁按鈕 **「🔄 立即自知名組織下載並更新黑名單」**，系統將在背景從 StevenBlack、Hagezi 與 URLHaus 抓取最新名單並熱載入。
* **臨時暫停阻擋**：點擊 **「⏸ 暫停阻擋 5 分鐘」** 或 **「⏸ 暫停阻擋 1 小時」**。
* **測試網域**：在「即時網域阻擋測試」欄位輸入 `pagead2.googlesyndication.com`，即時反饋命中結果。

---

### 4. 驗證阻擋效果

可使用 Windows 內建工具測試解析：

```cmd
:: 測試廣告追蹤網域 (應回覆 0.0.0.0)
nslookup pagead2.googlesyndication.com 127.0.0.1

:: 測試正常網站 (應透過上游 Quad9 正常解析真實 IP)
nslookup github.com 127.0.0.1
```

---

## 四、命令列參數說明 (CLI Flags)

`win-adblock.exe` 支援以下命令列旗標：

| 參數 | 預設值 | 說明 |
| :--- | :--- | :--- |
| `-listen` | `127.0.0.1` | DNS 監聽位址（設為 `0.0.0.0` 可供局域網內手機、電視盒等裝置使用） |
| `-port` | `53` | DNS UDP 監聽埠號（若 53 埠衝突，可指定為 `1053` 或 `5300` 進行測試） |
| `-web` | `127.0.0.1:8080` | Web 儀表板與 REST API 監聽位址 |
| `-upstream` | `9.9.9.9:53` | 上游 DNS 解析伺服器位址（例如 Quad9 `9.9.9.9:53` 或 Cloudflare `1.1.1.1:53`） |
| `-cache` | `blocklist.bin` | 本地 40-bit 雜湊二進位快取檔路徑（初次更新後會自動快取，重啟時可離線秒載入） |
| `-update-now` | `false` | 啟動時強制立即自知名組織線上拉取最新黑名單 |
| `-update-interval`| `24` | 定時自動更新排程間隔（單位：小時，設為 `0` 則不啟用自動更新） |

---

## 五、實務注意事項與故障排除 (Notes & Troubleshooting)

### 1. UDP 53 連接埠被佔用或權限不足
* **現象**：啟動時出現 `bind: An attempt was made to access a socket in a way forbidden by its access permissions.`。
* **原因與處置**：
  1. 請務必確認以**系統管理員身分**執行程式。
  2. Windows 部分內建服務（如 **網際網路連線共用 ICS**、**Hyper-V 虛擬網路介面卡**、某些第三方 VPN 或安全軟體）可能會占用 53 埠。
  3. 可透過 CMD 查詢佔用行程：
     ```cmd
     netstat -ano | findstr :53
     ```
  4. 若無法釋放 53 埠，可透過命令列參數改用自訂連接埠執行：
     ```cmd
     win-adblock.exe -listen 127.0.0.1 -port 1053 -web 127.0.0.1:8080
     ```

### 2. 關閉服務時務必記得還原網路卡 DNS
* **重要提醒**：當您停止執行 `win-adblock.exe` 時，若電腦網路卡的 DNS 依然設定為 `127.0.0.1`，整台電腦將暫時無法解析任何網域（出現網頁無法連線）。
* **復原方式**：請執行 `.\setup_dns.ps1 disable` 將網路卡 DNS 設回自動取得（DHCP）。

### 3. Windows 防火牆提示
* 首次執行時，Windows Defender 防火牆可能會跳出「Windows 安全性警訊」，詢問是否允許公用/私人網路存取。請勾選並點擊**「允許存取」**，以利 UDP 封包正常收發。

### 4. DNS 阻擋的邊界與侷限性
* **DNS 阻擋的本質**：WinAdBlock 是在網域解析階段進行阻擋（Domain-level Blocking）。
* **無法阻擋的類型**：對於與正常內容共用同一網域的廣告（例如 YouTube 影片內插播串流廣告、Facebook 動態時報贊助廣告等），由於其廣告媒體檔與主體影片均位於相同的主機網域下，DNS 阻擋器無法在不破壞主要功能的前提下將其分離。此類廣告需搭配瀏覽器擴充功能（如 uBlock Origin）處理。

---

## 六、開源授權與免責聲明 (License & Disclaimer)

### 1. 開源授權 (License)
本專案採用 **[MIT License](LICENSE)** 釋出，您可以自由地使用、修改、整合、分發本軟體於個人或商業用途，惟需保留原始著作權宣告與許可聲明。

### 2. 上游專案授權聲明 (Third-Party Licenses)
* 本專案借鑑之核心演算法原創專案 **[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)** 同樣基於 **MIT License** 授權。
* **[StevenBlack/hosts](https://github.com/StevenBlack/hosts)** 採用 **MIT License** 授權。
* **[HaGeZi/dns-blocklists](https://github.com/hagezi/dns-blocklists)** 採用 **GPL-3.0 / Creative Commons** 授權。
* 各黑名單資料之著作權與智慧財產權分別歸屬於各該組織與維護團隊。

### 3. 免責聲明 (Disclaimer)
* 本軟體依「現狀（AS-IS）」提供，不附帶任何明示或暗示之保證。
* 使用者應自行承擔網路組態設定之風險。因修改 DNS 伺服器設定、網路中斷、或特定網站被黑名單規則攔截所造成之任何直接或間接損失，專案作者與貢獻者概不承擔任何法律與損害賠償責任。
* 請勿將本軟體用於阻斷未經授權之他人網路或惡意網路攻擊行為。
