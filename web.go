package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// WebServer provides the HTTP dashboard and management API.
type WebServer struct {
	ListenAddr string
	Engine     *DNSServer
	Sources    []BlocklistSource
	BinPath    string

	updateMu   sync.Mutex
	isUpdating bool
	lastError  string
}

// NewWebServer creates a new WebServer instance.
func NewWebServer(addr string, dns *DNSServer, sources []BlocklistSource, binPath string) *WebServer {
	return &WebServer{
		ListenAddr: addr,
		Engine:     dns,
		Sources:    sources,
		BinPath:    binPath,
	}
}

// Start launches the HTTP service.
func (ws *WebServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/api/stats", ws.handleStats)
	mux.HandleFunc("/api/update", ws.handleUpdate)
	mux.HandleFunc("/api/pause", ws.handlePause)
	mux.HandleFunc("/api/resume", ws.handleResume)
	mux.HandleFunc("/api/custom", ws.handleCustom)
	mux.HandleFunc("/api/test", ws.handleTest)

	log.Printf("[Web] 儀表板管理介面啟動於: http://%s", ws.ListenAddr)
	return http.ListenAndServe(ws.ListenAddr, mux)
}

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(dashboardHTML))
}

func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	totalDom, updatedAt, srcStats, custBlock, custAllow := ws.Engine.Blocklist.Stats()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	totalQ := ws.Engine.TotalQueries
	totalB := ws.Engine.TotalBlocked
	totalA := ws.Engine.TotalAllowed

	ratio := 0.0
	if totalQ > 0 {
		ratio = float64(totalB) / float64(totalQ) * 100.0
	}

	resumeIn := 0
	if !ws.Engine.BlockingEnabled.Load() && !ws.Engine.ResumeAt.IsZero() {
		remain := time.Until(ws.Engine.ResumeAt)
		if remain > 0 {
			resumeIn = int(remain.Seconds())
		}
	}

	ws.updateMu.Lock()
	updating := ws.isUpdating
	lastErr := ws.lastError
	ws.updateMu.Unlock()

	data := map[string]interface{}{
		"total_queries":    totalQ,
		"total_blocked":    totalB,
		"total_allowed":    totalA,
		"block_ratio":      fmt.Sprintf("%.1f%%", ratio),
		"total_domains":    totalDom,
		"updated_at":       updatedAt,
		"sources_stats":    srcStats,
		"blocking_enabled": ws.Engine.BlockingEnabled.Load(),
		"resume_in":        resumeIn,
		"is_updating":      updating,
		"last_error":       lastErr,
		"custom_blocks":    custBlock,
		"custom_allows":    custAllow,
		"memory_alloc_mb":  fmt.Sprintf("%.2f MB", float64(m.Alloc)/(1024*1024)),
		"goroutines":       runtime.NumGoroutine(),
		"logs":             ws.Engine.GetLogs(),
	}

	_ = json.NewEncoder(w).Encode(data)
}

func (ws *WebServer) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ws.updateMu.Lock()
	if ws.isUpdating {
		ws.updateMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "更新程序已在背景執行中，請稍候...",
		})
		return
	}
	ws.isUpdating = true
	ws.lastError = ""
	ws.updateMu.Unlock()

	go func() {
		defer func() {
			ws.updateMu.Lock()
			ws.isUpdating = false
			ws.updateMu.Unlock()
		}()

		err := ws.Engine.Blocklist.FetchAndBuild(ws.Sources, ws.BinPath)
		ws.updateMu.Lock()
		if err != nil {
			ws.lastError = err.Error()
		} else {
			ws.lastError = ""
		}
		ws.updateMu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "已觸發即時更新，系統正在背景平行下載與重新索引...",
	})
}

func (ws *WebServer) handlePause(w http.ResponseWriter, r *http.Request) {
	secStr := r.URL.Query().Get("seconds")
	seconds, _ := strconv.Atoi(secStr)
	if seconds <= 0 {
		seconds = 300 // default 5 minutes
	}
	ws.Engine.PauseBlocking(seconds)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("已暫停阻擋 %d 秒", seconds),
	})
}

func (ws *WebServer) handleResume(w http.ResponseWriter, r *http.Request) {
	ws.Engine.ResumeBlocking()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "已恢復阻擋",
	})
}

func (ws *WebServer) handleCustom(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Action string `json:"action"` // "block" or "allow"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		if req.Action == "allow" {
			ws.Engine.Blocklist.AddCustomAllow(req.Domain)
		} else {
			ws.Engine.Blocklist.AddCustomBlock(req.Domain)
		}
	} else if r.Method == http.MethodDelete {
		if req.Action == "allow" {
			ws.Engine.Blocklist.RemoveCustomAllow(req.Domain)
		} else {
			ws.Engine.Blocklist.RemoveCustomBlock(req.Domain)
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (ws *WebServer) handleTest(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing domain", http.StatusBadRequest)
		return
	}

	blocked, reason := ws.Engine.Blocklist.IsBlocked(domain)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":  domain,
		"blocked": blocked,
		"reason":  reason,
	})
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="zh-Hant">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WinAdBlock — 40-bit FNV-1a DNS 阻擋中樞</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0284c7;
      --danger: #ef4444;
      --success: #10b981;
      --warning: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; }
    body { background-color: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--card-border); }
    h1 { font-size: 24px; display: flex; align-items: center; gap: 10px; }
    .badge { font-size: 12px; background: rgba(56, 189, 248, 0.15); color: var(--accent); padding: 4px 10px; border-radius: 9999px; border: 1px solid rgba(56, 189, 248, 0.3); }
    .badge-status { font-weight: bold; }
    .status-active { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }
    .status-paused { background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }
    
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 18px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2); }
    .card-title { font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
    .card-value { font-size: 28px; font-weight: 700; color: #fff; }
    .card-sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

    .action-panel { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 24px; }
    button { background: var(--accent); color: #000; border: none; padding: 10px 18px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; font-size: 14px; }
    button:hover { background: var(--accent-hover); color: #fff; }
    button.btn-danger { background: var(--danger); color: #fff; }
    button.btn-warning { background: var(--warning); color: #000; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }

    .section-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
    @media (max-width: 900px) { .section-grid { grid-template-columns: 1fr; } }

    .input-group { display: flex; gap: 8px; margin-top: 10px; }
    input[type="text"] { flex: 1; background: #0b1120; border: 1px solid var(--card-border); color: #fff; padding: 9px 14px; border-radius: 8px; outline: none; }
    input[type="text"]:focus { border-color: var(--accent); }

    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--card-border); }
    th { color: var(--text-muted); font-weight: 600; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .tag-blocked { color: var(--danger); font-weight: 600; }
    .tag-allowed { color: var(--success); font-weight: 600; }

    .toast { display: none; padding: 12px 18px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
    .toast-info { background: rgba(56, 189, 248, 0.2); border: 1px solid var(--accent); color: var(--accent); }
    .toast-error { background: rgba(239, 68, 68, 0.2); border: 1px solid var(--danger); color: var(--danger); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>WinAdBlock <span class="badge">Windows Native 40-bit Core</span></h1>
        <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
          基於 M-Abozaid/esp32-c3-adblock 思想之超輕量原生 DNS Sinkhole
        </div>
      </div>
      <div>
        <span id="status-badge" class="badge badge-status status-active">運作中</span>
      </div>
    </header>

    <div id="toast" class="toast"></div>

    <!-- 統計卡片 -->
    <div class="stats-grid">
      <div class="card">
        <div class="card-title">總查詢次數</div>
        <div class="card-value" id="total-queries">-</div>
        <div class="card-sub">攔截率: <span id="block-ratio" style="color:var(--accent); font-weight:bold;">0%</span></div>
      </div>
      <div class="card">
        <div class="card-title">已成功攔截 (Sinkhole)</div>
        <div class="card-value" id="total-blocked" style="color:var(--danger);">-</div>
        <div class="card-sub">回應 0.0.0.0 / ::</div>
      </div>
      <div class="card">
        <div class="card-title">正常放行查詢</div>
        <div class="card-value" id="total-allowed" style="color:var(--success);">-</div>
        <div class="card-sub">轉發 Quad9 (9.9.9.9)</div>
      </div>
      <div class="card">
        <div class="card-title">已載入 40-bit 網域規則</div>
        <div class="card-value" id="total-domains" style="color:var(--accent);">-</div>
        <div class="card-sub" id="updated-at">更新時間: -</div>
      </div>
    </div>

    <!-- 控制面版 -->
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">阻擋控制與知名組織名單更新</div>
      <div class="action-panel" style="margin-top: 10px;">
        <button id="btn-update" onclick="triggerUpdate()">
          🔄 立即自知名組織下載並更新黑名單
        </button>
        <button id="btn-pause-5" class="btn-warning" onclick="pauseBlocking(300)">
          ⏸ 暫停阻擋 5 分鐘
        </button>
        <button id="btn-pause-60" class="btn-warning" onclick="pauseBlocking(3600)">
          ⏸ 暫停阻擋 1 小時
        </button>
        <button id="btn-resume" class="btn-danger" style="display:none;" onclick="resumeBlocking()">
          ▶ 立即恢復阻擋
        </button>
      </div>
      <div id="update-status" style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
        支援來源：StevenBlack Hosts、Hagezi Light DNS、URLHaus Abuse.ch 等。
      </div>
    </div>

    <!-- 兩欄：測試網域與自訂名單 -->
    <div class="section-grid">
      <!-- 測試網域 -->
      <div class="card">
        <div class="card-title">即時網域阻擋測試 (FNV40 模擬)</div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          輸入網域名稱，即刻驗證二分搜尋與多層子網域後綴比對結果。
        </div>
        <div class="input-group">
          <input type="text" id="test-input" placeholder="例如: pagead2.googlesyndication.com" onkeydown="if(event.key==='Enter') testDomain();">
          <button onclick="testDomain()">測試</button>
        </div>
        <div id="test-result" style="margin-top: 14px; font-size: 14px; min-height: 24px;"></div>
      </div>

      <!-- 自訂黑白名單 -->
      <div class="card">
        <div class="card-title">手動快速增刪規則</div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          優先權：自訂白名單 > 自訂黑名單 > 40-bit 雜湊資料庫。
        </div>
        <div class="input-group">
          <input type="text" id="custom-input" placeholder="例如: bad-site.com 或 allow-site.com">
          <button class="btn-danger" onclick="addCustom('block')">加黑名單</button>
          <button style="background:var(--success); color:#fff;" onclick="addCustom('allow')">加白名單</button>
        </div>
      </div>
    </div>

    <!-- 即時 DNS 查詢紀錄 -->
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div class="card-title">即時 DNS 查詢日誌 (最近 100 筆)</div>
        <div style="font-size: 12px; color: var(--text-muted);">自動每 2 秒更新</div>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>時間</th>
              <th>用戶端 IP</th>
              <th>查詢網域</th>
              <th>類型</th>
              <th>動作</th>
              <th>比對規則 / 原因</th>
            </tr>
          </thead>
          <tbody id="logs-body">
            <tr><td colspan="6" style="text-align:center; color:var(--text-muted);">尚無查詢紀錄</td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <script>
    function showToast(msg, isError) {
      const t = document.getElementById('toast');
      t.innerText = msg;
      t.className = 'toast ' + (isError ? 'toast-error' : 'toast-info');
      t.style.display = 'block';
      setTimeout(() => { t.style.display = 'none'; }, 4000);
    }

    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('total-queries').innerText = Number(data.total_queries).toLocaleString();
        document.getElementById('total-blocked').innerText = Number(data.total_blocked).toLocaleString();
        document.getElementById('total-allowed').innerText = Number(data.total_allowed).toLocaleString();
        document.getElementById('block-ratio').innerText = data.block_ratio;
        document.getElementById('total-domains').innerText = Number(data.total_domains).toLocaleString();
        document.getElementById('updated-at').innerText = '最後更新: ' + data.updated_at;

        const badge = document.getElementById('status-badge');
        const btnResume = document.getElementById('btn-resume');
        const btnP5 = document.getElementById('btn-pause-5');
        const btnP60 = document.getElementById('btn-pause-60');

        if (data.blocking_enabled) {
          badge.className = 'badge badge-status status-active';
          badge.innerText = '阻擋中 (Active)';
          btnResume.style.display = 'none';
          btnP5.style.display = 'inline-block';
          btnP60.style.display = 'inline-block';
        } else {
          badge.className = 'badge badge-status status-paused';
          badge.innerText = data.resume_in > 0 ? '暫停中 (剩餘 ' + data.resume_in + ' 秒)' : '已手動暫停';
          btnResume.style.display = 'inline-block';
          btnP5.style.display = 'none';
          btnP60.style.display = 'none';
        }

        const btnUpdate = document.getElementById('btn-update');
        if (data.is_updating) {
          btnUpdate.disabled = true;
          btnUpdate.innerText = '⏳ 正在自網路下載與更新中...';
        } else {
          btnUpdate.disabled = false;
          btnUpdate.innerText = '🔄 立即自知名組織下載並更新黑名單';
        }

        if (data.last_error) {
          document.getElementById('update-status').innerText = '上次更新警告: ' + data.last_error;
          document.getElementById('update-status').style.color = 'var(--danger)';
        }

        // Render Logs
        const tbody = document.getElementById('logs-body');
        if (data.logs && data.logs.length > 0) {
          let rows = '';
          for (let i = data.logs.length - 1; i >= 0; i--) {
            const l = data.logs[i];
            const tag = l.blocked ? '<span class="tag-blocked">阻擋 (Sinkhole)</span>' : '<span class="tag-allowed">放行 (Pass)</span>';
            rows += '<tr>' +
              '<td>' + l.timestamp + '</td>' +
              '<td>' + l.client_ip + '</td>' +
              '<td style="word-break:break-all;">' + l.domain + '</td>' +
              '<td><span class="badge">' + l.qtype + '</span></td>' +
              '<td>' + tag + '</td>' +
              '<td>' + (l.reason || '-') + '</td>' +
            '</tr>';
          }
          tbody.innerHTML = rows;
        }
      } catch (e) {
        console.error("fetchStats error:", e);
      }
    }

    async function triggerUpdate() {
      try {
        const res = await fetch('/api/update', { method: 'POST' });
        const data = await res.json();
        showToast(data.message, !data.success);
        fetchStats();
      } catch (e) {
        showToast('觸發更新失敗: ' + e, true);
      }
    }

    async function pauseBlocking(sec) {
      await fetch('/api/pause?seconds=' + sec, { method: 'POST' });
      fetchStats();
    }

    async function resumeBlocking() {
      await fetch('/api/resume', { method: 'POST' });
      fetchStats();
    }

    async function testDomain() {
      const input = document.getElementById('test-input');
      const val = input.value.trim();
      if (!val) return;
      const res = await fetch('/api/test?domain=' + encodeURIComponent(val));
      const data = await res.json();
      const div = document.getElementById('test-result');
      if (data.blocked) {
        div.innerHTML = '<span style="color:var(--danger); font-weight:bold;">🚫 已攔截！</span> 命中規則後綴: <code>' + data.reason + '</code>';
      } else {
        div.innerHTML = '<span style="color:var(--success); font-weight:bold;">✅ 放行</span> (不在阻擋清單中)';
      }
    }

    async function addCustom(action) {
      const input = document.getElementById('custom-input');
      const val = input.value.trim();
      if (!val) return;
      await fetch('/api/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: val, action: action })
      });
      showToast('已將 ' + val + ' 加入自訂' + (action === 'allow' ? '白名單' : '黑名單'), false);
      input.value = '';
      fetchStats();
    }

    setInterval(fetchStats, 2000);
    fetchStats();
  </script>
</body>
</html>`
