param ($InterfaceName = "Ethernet")
$ErrorActionPreference = "Stop"

$ifaceid = (Get-WmiObject -Class "Win32_NetworkAdapter" -Property @("Index", "NetConnectionID") | Where-Object {$_.NetConnectionID -eq $InterfaceName}).Index
$ifconf = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" | Where-Object {$_.Index -eq $ifaceid}
$address = ($ifconf.IPAddress | ForEach-Object {[System.Net.IPAddress]$_} | Where-Object {$_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork})[0]
$dhcpsvr = $ifconf.DHCPServer
$primarydns = $ifconf.DNSServerSearchOrder[0]
Write-Host $address
Write-Host $dhcpsvr
Write-Host $primarydns
