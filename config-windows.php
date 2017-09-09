<?php
// this file should make $config->key availiable

$config = new stdClass;

// will send challenge to 202.1.1.1, 1.1.1.1, 192.168.255.251 if not set
// not guranteed availiable (especially on multihome system)
$config->server = "";
$config->username="drcomfucker";
$config->password="114514";
$config->CONTROLCHECKSTATUS = "\x20";
$config->ADAPTERNUM = "\x01";
// socket will bind to host_ip
$config->host_ip = "";
$config->IPDOG = "\x01";
$config->host_name = "Sprite";
$config->PRIMARY_DNS = "0.0.0.0";
// use auth server if not set
$config->dhcp_server = "";
$config->AUTH_VERSION = "\x2a\x00";
$config->mac = hex2bin('114514191981');
$config->host_os = "2.6.32";
$config->KEEP_ALIVE_VERSION = "\xd8\x02";
$config->ror_version = true;

// will bind to specified interface if set
$config->iface = "";

$config->iface = "Ethernet";

logger("getting network configuration from WMI");

$indexquery = shell_exec('wmic path Win32_NetworkAdapter get Index,NetConnectionID /format:rawxml');
$sx = simplexml_load_string($indexquery);
$ncindex = NULL;

foreach($sx->xpath('RESULTS/CIM/INSTANCE') as $inst) {
    $ncid = $inst->xpath('PROPERTY[@NAME="NetConnectionID"]/VALUE');
    if(count($ncid) === 0) continue;
    $ncid = (string)$ncid[0];
    if($ncid === $config->iface) {
        $ncindex = (string)$inst->xpath('PROPERTY[@NAME="Index"]/VALUE')[0];
        break;
    }
}

if($ncindex === NULL) {
    logger("can't find interface {$config->iface}\n");
    exit(1);
}
logger('found interface %s with ID %s', $config->iface, $ncindex);

$indexquery = shell_exec('wmic path Win32_NetworkAdapterConfiguration where "Index=' . $ncindex . '" get IPAddress,DHCPServer,DNSServerSearchOrder /format:rawxml');
$sx = simplexml_load_string($indexquery);
function str($x) { return (string)$x; }
$ipaddrs = array_map('str', $sx->xpath('RESULTS/CIM/INSTANCE/PROPERTY.ARRAY[@NAME="IPAddress"]/VALUE.ARRAY/VALUE'));
$dnsservers = array_map('str', $sx->xpath('RESULTS/CIM/INSTANCE/PROPERTY.ARRAY[@NAME="DNSServerSearchOrder"]/VALUE.ARRAY/VALUE'));
$fltrv4 = function($x) { return strpos($x, ':') === false; };
$v4addrs = array_filter($ipaddrs, $fltrv4);
$v4dnsservers = array_filter($dnsservers, $fltrv4);

if(count($v4addrs)!==1) {
    logger("can't find unique IPv4 address on interface $config->iface");
    exit(1);
}
$config->host_ip = $v4addrs[0];
$config->dhcp_server = (string)$sx->xpath('RESULTS/CIM/INSTANCE/PROPERTY[@NAME="DHCPServer"]/VALUE')[0] ? : '0.0.0.0';
$config->PRIMARY_DNS = count($v4dnsservers) ? $v4dnsservers[0] : '0.0.0.0';
logger('using host_ip %s, dhcp_server %s, PRIMARY_DNS %s', $config->host_ip, $config->dhcp_server, $config->PRIMARY_DNS);
