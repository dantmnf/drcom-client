<?php
// this file should make $config->key availiable
function drcomfucker_get_config() {
    $config = new stdClass;

    $config->username="drcomfucker";
    $config->password="114514";

    // OpenWrt (UCI) interface name
    // NOT Linux device name (e.g. eth*)
    $uci_interface = "wan";

    // will send challenge to 202.1.1.1, 1.1.1.1, 192.168.255.251 if not set
    // not guranteed availiable
    $config->server = "";
    $config->CONTROLCHECKSTATUS = "\x20";
    $config->ADAPTERNUM = "\x01";
    $config->IPDOG = "\x01";
    $config->AUTH_VERSION = "\x2d\x00";
    $config->KEEP_ALIVE_VERSION = "\xd8\x02";
    $config->ror_version = true;

    // OpenWrt doesn't provide us DHCP server address
    // leave it blank will use auth server
    $config->dhcp_server = "";

    // socket will bind to host_ip
    $config->host_ip = "";
    $config->PRIMARY_DNS = "0.0.0.0";
    $config->mac = hex2bin('010203040506');


    $config->host_name = "Sprite";
    $config->host_os = "DrCOM\x00\xbd\x00\x2a\x00" .
                    str_repeat("\x00", 54) .
                    "e8fdd1bbb9c96f285be0e883b482db8faeb69af0" .
                    str_repeat("\x00", 24);

    logger("getting network configuration from OpenWrt");

    $json = shell_exec("ifstatus $uci_interface");
    $ifstatus = json_decode($json);

    if($ifstatus === NULL) {
        logger("JSON decode failed");
        exit(1);
    }

    if(property_exists($ifstatus, "device") !== TRUE) {
        logger("UCI interface $uci_interface has no associated Linux interface");
        exit(1);
    }

    if($ifstatus->up !== TRUE) {
        logger("interface $uci_interface is down");
        exit(1);
    }

    $config->iface = $ifstatus->device;
    $mac = trim(file_get_contents("/sys/class/net/$config->iface/address"));

    logger('found interface %s with MAC %s', $config->iface, $mac);

    $config->host_ip = $ifstatus->{'ipv4-address'}[0]->address;
    $config->PRIMARY_DNS = $ifstatus->{'dns-server'}[0];
    $config->mac = hex2bin(str_replace(':', '', $mac));

    logger('using host_ip %s, PRIMARY_DNS %s', $config->host_ip, $config->PRIMARY_DNS);

    return $config;
}
