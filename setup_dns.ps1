# setup_dns.ps1 - Windows Adapter DNS Switcher
# Please run with Administrator privileges

param (
    [Parameter(Position=0)]
    [ValidateSet("enable", "disable", "status")]
    [string]$Action = "status"
)

function Get-ActiveAdapter {
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|Hyper-V|TAP|VPN|Loopback' } | Select-Object -First 1
}

$adapter = Get-ActiveAdapter

if (-not $adapter) {
    Write-Warning "[!] No active physical network adapter found!"
    exit 1
}

Write-Host "[*] Active Network Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Cyan

switch ($Action) {
    "enable" {
        Write-Host "[*] Pointing DNS server to localhost (127.0.0.1)..." -ForegroundColor Yellow
        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("127.0.0.1")
        Write-Host "[+] SUCCESS: All DNS queries will now pass through WinAdBlock." -ForegroundColor Green
    }
    "disable" {
        Write-Host "[*] Restoring DNS server to automatic (DHCP)..." -ForegroundColor Yellow
        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
        Write-Host "[+] SUCCESS: DNS settings restored to default." -ForegroundColor Green
    }
    "status" {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4
        Write-Host "[*] Current IPv4 DNS Server(s): $($dns.ServerAddresses -join ', ')" -ForegroundColor White
        Write-Host ""
        Write-Host "Usage:" -ForegroundColor DarkGray
        Write-Host "  Enable WinAdBlock Sinkhole:  .\setup_dns.ps1 enable"
        Write-Host "  Restore Default DNS:         .\setup_dns.ps1 disable"
    }
}
