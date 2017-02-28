<?php

/*****************************************************************************

                                  FUCK PHP

    you may get corrupted string while using
        $result = <blah1> . <blah2> . blah3(blah4) . $blah5 . ...;

    always use
        $result = <blah1>;
        $result .= <blah2>;
        $result .= blah3(blah4);
        $result .= $blah5;
        $result .= ...;
    to avoid some weird issues.
    
    (c) dantmnf 2017
    Licensed under AGPLv3
    (infected by https://github.com/drcoms/drcom-generic )

 *****************************************************************************/


function ip2bin($ip) {
    return pack("N", ip2long($ip));
}
function checksum($s) {
    $result = 1234;
    foreach(str_split($s, 4) as $i) {
        $result ^= unpack("V", $i . "\0\0\0\0")[1];
    }
    $result2  = $result << 10;
    $result2 += $result << 9;
    $result2 += $result << 8;
    $result2 += $result << 7;
    $result2 += $result << 5;
    $result2 += $result << 4;
    $result2 &= 0xFFFFFFFF;
    // $result2 = (1968 * $result) & 0xFFFFFFFF;
    return pack("V", $result2);
}

function ror($md5, $pwd) {
    $result = $pwd ^ substr($md5, 0, strlen($pwd));
    $len = strlen($pwd);
    for($i = 0; $i < $len; $i++) {
        $x = ord($result[$i]);
        $result[$i] = chr((($x<<3) & 0xFF) + ($x>>5));
    }
    return $result;
}


function build_challenge_message() {
    $seed = time() & 0xFFFF;
    $message =  "\x01\x02" . pack("v", $seed) . "\x09" . "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    return $message;
}

function build_login_message($config, $challenge) {
    $usr = $config->username;
    $pwd = $config->password;
    $mac = $config->mac;
    $dhcp_server = $config->dhcp_server == "" ? $config->server : $config->dhcp_server;
    $sum1 = md5("\x03\x01" . $challenge . $pwd, true);
    $sum2 = md5("\x01" . $pwd . $challenge . "\x00\x00\x00\x00", true);
                                                                       /* struct LoginMessage */
    $data = b"\x03\x01\x00" . chr(strlen($usr)+20)                     /* header */
          . $sum1;                                                     /* byte MD5sum1[16] */

    $data .= str_pad($usr, 36, "\x00", STR_PAD_RIGHT);                 /* byte username[36] */

    $data .= $config->CONTROLCHECKSTATUS;                              /* byte ControlCheckStatus */
    $data .= $config->ADAPTERNUM;                                      /* byte adapterNum */
    $data .=  substr($sum1, 0, 6) ^ $mac;                              /* byte MacXorSum1[6] */

    $data .= $sum2                                                     /* byte MD5sum2[16] */
          . "\x01";                                                    /* byte nicCount */

    $data .= ip2bin($config->host_ip);                                 /* uint32be ip[0] */
    $data .= ip2bin("0.0.0.0");                                        /* uint32be ip[1] */
    $data .= ip2bin("0.0.0.0");                                        /* uint32be ip[2] */
    $data .= ip2bin("0.0.0.0");                                        /* uint32be ip[3] */

    $sum3 = substr(md5($data . "\x14\x00\x07\x0b", true), 0, 8);
    $data .= $sum3;                                                    /* byte MD5sum3[8] */
    $data .=  $config->IPDOG                                           /* byte dogFlag */
          .  "\x00\x00\x00\x00"                                        /* uint32 unknown1 */
          .  str_pad($config->host_name, 32, "\x00")                   /* byte hostname[32] */
          .  ip2bin($config->PRIMARY_DNS)                              /* uint32be nameserver1 */
          .  ip2bin($dhcp_server)                                      /* uint32be dhcpServer */
          .  ip2bin("0.0.0.0")                                         /* uint32be nameserver2 */
          .  "\x00\x00\x00\x00"                                        /* uint32be WINSServer1 */
          .  "\x00\x00\x00\x00"                                        /* uint32be WINSServer2 */
                                                                       /* struct VERSIONINFO */
          .  "\x94\x00\x00\x00"                                        /*   uint32le dwOSVersionInfoSize */
          .  "\x05\x00\x00\x00"                                        /*   uint32le dwMajorVersion */
          .  "\x01\x00\x00\x00"                                        /*   uint32le dwMinorVersion */
          .  "\x28\x0a\x00\x00"                                        /*   uint32le dwBuildNumber */
          .  "\x02\x00\x00\x00"                                        /*   uint32le dwPlatformId */
          .  str_pad($config->host_os, 128, "\x00");                   /*   byte szCSDVersion[128] */
    $data .=  $config->AUTH_VERSION;                                   /* byte ClientVerInfoAndInternetMode; byte DogVersion */
    
	if($config->ror_version) {                                         /* struct LDAPAuth */
        $data = $data
			  . "\x00"                                                 /*   byte code */
              .  chr(strlen($pwd));                                    /*   byte len */
        $data .= ror(md5("\x03\x01" . $challenge . $pwd, true), $pwd); /*   byte password[len] */
    }
                                                                       /* struct DrcomAuthExtData */
    $data .= "\x02\x0c";                                               /*   byte code; byte len */
    $sum4 =  checksum($data . "\x01\x26\x07\x11\x00\x00" . $mac);
    $data .= $sum4;                                                    /*   uint32le checksum */
    $data .= "\x00\x00";                                               /*   uint16 options */
    $data .= $mac;                                                     /*   byte mac[6] */
    $data .= "\x00"                                                    /* byte autoLogout */
          .  "\x00"                                                    /* byte broadcastMode */
          .  "\xe9\x13";                                               /* uint16 unknown */
    return $data;

}

function build_logout_message($config, $challenge_salt, $session_cookie) {
    $hash1 = md5("\x03\x01" . $challenge_salt . $config->password, true);
    $message = "\x06\x01\x00" . chr(strlen($config->username) + 20);
    $message .= $hash1;
    $message .= str_pad($config->username, 36, "\x00", STR_PAD_RIGHT);
    $message .= $config->CONTROLCHECKSTATUS;
    $message .= $config->ADAPTERNUM;
    $message .= substr($hash1, 0, 6) ^ $config->mac;
    $message .= $session_cookie;
    return $message;
}

function build_keepalive_message_type1($config, $challenge_salt, $session_cookie) {
    $message =  "\xFF";
    $message .= md5("\x03\x01" . $challenge_salt . $config->password, true);
    $message .= "\0\0\0";
    $message .= $session_cookie;
    $message .= pack('n', time()&0xFFFF);
    $message .= "\0\0\0\0";
    return $message;
}

function build_keepalive_message_type2($config, $seq, $keepalive_cookie, $subtype, $first=false) {
    $msg = "\x07";
    $msg .= chr($seq&0xFF);
    $msg .= "\x28\x00\x0b";
    $msg .= chr($subtype);
    if($first)
        $msg .= "\x0f\x27";
    else
        $msg .= $config->KEEP_ALIVE_VERSION;
    $msg .= "\x2f\x12\0\0\0\0\0\0";
    $msg .= $keepalive_cookie;
    $msg .= "\x00\x00\x00\x00";
    if($subtype === 3) {
        $msg .= "\0\0\0\0";
        $msg .= ip2bin($config->host_ip);
        $msg .= "\0\0\0\0\0\0\0\0";
    } else {
        $msg .= "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    }
    return $msg;
}

