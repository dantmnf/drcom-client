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
$config->mac = "\x00\x00\x00\x00\x00\x00";
$config->host_os = "2.6.32";
$config->KEEP_ALIVE_VERSION = "\xd8\x02";
$config->ror_version = true;

// will bind to specified interface if set
$config->iface = "";


$openwrt_iface = "wan"; // !!! not Linux interface name


echo("getting network configuration from OpenWrt\n");
$fd = popen("ifstatus \"$openwrt_iface\"", "r");
$json = '';
do {
    $json .= fread($fd, 4096);
} while(!feof($fd));
pclose($fd);

if(!function_exists("json_decode")) {
    die("ERROR: json extension is required\n");
}

$jdoc = json_decode($json);

if($jdoc->up) {
    $config->host_ip = $jdoc->{'ipv4-address'}[0]->address;
    $config->PRIMARY_DNS = $jdoc->{'dns-server'}[0];
    $config->iface = $jdoc->device;
} else {
    die("failed to get network configuration\n");
}