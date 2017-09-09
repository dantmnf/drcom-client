<?php
function drcomfucker_get_config() {
    $config = new stdClass;

    $config->username="drcomfucker";
    $config->password="114514";

    // Windows network adapter name
    $config->iface = "Ethernet1";

    // will send challenge to 202.1.1.1, 1.1.1.1, 192.168.255.251 if not set
    // not guranteed availiable (especially on multihome system)
    $config->server = "";
    $config->CONTROLCHECKSTATUS = "\x20";
    $config->ADAPTERNUM = "\x01";
    $config->IPDOG = "\x01";
    $config->AUTH_VERSION = "\x2d\x00";
    $config->KEEP_ALIVE_VERSION = "\xd8\x02";
    $config->ror_version = true;

    // socket will bind to host_ip
    $config->host_ip = "";
    $config->PRIMARY_DNS = "0.0.0.0";
    // use auth server if not set
    $config->dhcp_server = "";
    $config->mac = hex2bin('010203040506');


    $config->host_name = "Sprite";
    $config->host_os = "DrCOM\x00\xbd\x00\x2a\x00" .
                    str_repeat("\x00", 54) .
                    "e8fdd1bbb9c96f285be0e883b482db8faeb69af0" .
                    str_repeat("\x00", 24);

    logger("getting network configuration with WMI");

    $query = shell_exec('wmic path Win32_NetworkAdapter get Index,NetConnectionID,MACAddress /format:rawxml');
    $sx = simplexml_load_string($query);
    $ncindex = NULL;
    $mac = NULL;
    foreach($sx->xpath('RESULTS/CIM/INSTANCE') as $inst) {
        $ncid = $inst->xpath('PROPERTY[@NAME="NetConnectionID"]/VALUE');
        if(count($ncid) === 0) continue;
        $ncid = (string)$ncid[0];
        if($ncid === $config->iface) {
            $ncindex = (string)$inst->xpath('PROPERTY[@NAME="Index"]/VALUE')[0];
            $mac = (string)$inst->xpath('PROPERTY[@NAME="MACAddress"]/VALUE')[0];
            break;
        }
    }

    if($ncindex === NULL || $mac === NULL) {
        logger("can't find interface {$config->iface}\n");
        exit(1);
    }
    logger('found interface %s with ID %s, MAC %s', $config->iface, $ncindex, $mac);

    $query = shell_exec("wmic path Win32_NetworkAdapterConfiguration where \"Index=$ncindex\" get IPAddress,DHCPServer,DNSServerSearchOrder /format:rawxml");
    $sx = simplexml_load_string($query);
    $tostring = function ($x) { return (string)$x; };
    $ipaddrs = array_map($tostring, $sx->xpath('RESULTS/CIM/INSTANCE/PROPERTY.ARRAY[@NAME="IPAddress"]/VALUE.ARRAY/VALUE'));
    $dnsservers = array_map($tostring, $sx->xpath('RESULTS/CIM/INSTANCE/PROPERTY.ARRAY[@NAME="DNSServerSearchOrder"]/VALUE.ARRAY/VALUE'));
    $fltrv4 = function($x) { return strpos($x, ':') === false; };
    $v4addrs = array_filter($ipaddrs, $fltrv4);
    $v4dnsservers = array_filter($dnsservers, $fltrv4);

    if(count($v4addrs)!==1) {
        logger("can't find unique IPv4 address on interface {$config->iface}");
        exit(1);
    }

    $config->host_ip = $v4addrs[0];
    $config->dhcp_server = (string)($sx->xpath('RESULTS/CIM/INSTANCE/PROPERTY[@NAME="DHCPServer"]/VALUE') ? : [""])[0];
    $config->PRIMARY_DNS = count($v4dnsservers) ? $v4dnsservers[0] : '0.0.0.0';
    $config->mac = hex2bin(str_replace(':', '', $mac));
    logger('using host_ip %s, dhcp_server %s, PRIMARY_DNS %s', $config->host_ip, $config->dhcp_server ? : "[auto]", $config->PRIMARY_DNS);
    return $config;
}
