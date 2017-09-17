<?php
function drcomfucker_get_config() {
    $config = new stdClass;

    $config->username="drcomfucker";
    $config->password="114514";

    // Windows network adapter name
    $config->iface = "Ethernet1";

    // will send challenge to 202.1.1.1, 1.1.1.1, 192.168.255.251 if not set
    // not guranteed availiable
    $config->server = "";
    $config->CONTROLCHECKSTATUS = "\x20";
    $config->ADAPTERNUM = "\x01";
    $config->IPDOG = "\x01";
    $config->AUTH_VERSION = "\x2d\x00";
    $config->KEEP_ALIVE_VERSION = "\xd8\x02";
    $config->ror_version = true;

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

    $wbemLocator = new COM("WbemScripting.SWbemLocator");
    $wbemServices = $wbemLocator->ConnectServer(".", 'root\cimv2');

    $escapedname = addslashes($config->iface);
    $nics = $wbemServices->ExecQuery("select Index,MACAddress from Win32_NetworkAdapter where NetConnectionID='$escapedname'");
    if ($nics->Count !== 1) {
        logger("can't find unique interface $config->iface\n");
        exit(1);
    }
    $nicindex = $nics->ItemIndex(0)->Properties_->Item("Index")->Value;
    $mac = $nics->ItemIndex(0)->Properties_->Item("MACAddress")->Value;
    logger('found interface %s with ID %s, MAC %s', $config->iface, $nicindex, $mac);
    $nics = null;

    $safearray = function ($x) {
        $result = [];
        if ($x === null || variant_get_type($x) & VT_ARRAY !== VT_ARRAY) {
            return $result;
        }
        foreach ($x as $key => $value) {
            $result[$key] = $value;
        }
        return $result;
    };

    $niccfg = $wbemServices->ExecQuery("select IPAddress,DHCPServer,DNSServerSearchOrder from Win32_NetworkAdapterConfiguration where Index=$nicindex");
    $ipaddrs = $safearray($niccfg->ItemIndex(0)->Properties_->Item("IPAddress")->Value);
    $dnsservers = $safearray($niccfg->ItemIndex(0)->Properties_->Item("DNSServerSearchOrder")->Value);
    $fltrv4 = function($x) { return strpos($x, ':') === false; };
    $v4addrs = array_filter($ipaddrs, $fltrv4);
    $v4dnsservers = array_filter($dnsservers, $fltrv4);

    if(count($v4addrs)!==1) {
        logger("can't find unique IPv4 address on interface {$config->iface}");
        exit(1);
    }

    $config->host_ip = $v4addrs[0];
    $config->dhcp_server = (string)($niccfg->ItemIndex(0)->Properties_->Item("DHCPServer")->Value);
    $config->PRIMARY_DNS = count($v4dnsservers) !== 0 ? $v4dnsservers[0] : '0.0.0.0';
    $config->mac = hex2bin(str_replace(':', '', $mac));
    logger('using host_ip %s, dhcp_server %s, PRIMARY_DNS %s', $config->host_ip, $config->dhcp_server ? : "[auto]", $config->PRIMARY_DNS);

    $niccfg = null;
    $wbemServices = null;
    $wbemLocator = null;

    return $config;
}
