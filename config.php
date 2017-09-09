<?php
// this file should make $config->key availiable
function drcomfucker_get_config() {
    $config = new stdClass;

    // will send challenge to 202.1.1.1, 1.1.1.1, 192.168.255.251 if not set
    // not guranteed availiable
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
    $config->AUTH_VERSION = "\x2d\x00";
    $config->mac = hex2bin("000000000000");
    $config->host_os = "DrCOM\x00\xbd\x00\x2a\x00" .
                    str_repeat("\x00", 54) .
                    "e8fdd1bbb9c96f285be0e883b482db8faeb69af0" .
                    str_repeat("\x00", 24);
    $config->KEEP_ALIVE_VERSION = "\xd8\x02";
    $config->ror_version = true;

    // will bind to specified interface if set and OS supported
    $config->iface = "";

    return $config;
}