<?php
// this file should make $config->key availiable
function drcomfucker_get_config() {
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
    $config->mac = hex2bin("000000000000");
    $config->host_os = "2.6.32";
    $config->KEEP_ALIVE_VERSION = "\xd8\x02";
    $config->ror_version = true;

    // will bind to specified interface if set
    $config->iface = "";

    return $config;
}