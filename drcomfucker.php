<?php

/*****************************************************************************

    (c) dantmnf 2017
    Licensed under AGPLv3
    (infected by https://github.com/drcoms/drcom-generic )

 *****************************************************************************/

require("message_builder.php");

date_default_timezone_set("Asia/Shanghai");

$logging_levels = ["INFO", "WARN", "ERROR", "FATAL"];

function logger2($level, ...$args) {
    global $logging_levels;
    if(!in_array($level, $logging_levels)) return;

    $message = count($args) <= 1 ? (string)$args[0] : sprintf(...$args);
    $lines = explode("\n", $message);
    $t = strftime('%T', time());

    $use_colors = PHP_OS !== "WINNT";
    $bold = $use_colors ? "\e[1m" : "";
    $unbold = $use_colors ? "\e[22m" : "";
    $red = $use_colors ? "\e[31m" : "";
    $green = $use_colors ? "\e[32m" : "";
    $yellow = $use_colors ? "\e[33m" : "";
    $magenta = $use_colors ? "\e[35m" : "";
    $white = $use_colors ? "\e[37m" : "";
    $reset = $use_colors ? "\e[0m" : "";
    $level_to_color = [
        "INFO" => $green,
        "WARN" => $yellow,
        "ERROR" => $magenta,
        "FATAL" => $red,
        "DEBUG" => "",
        "DUMP" => "",
    ];

    $out = $level === "DEBUG" || $level === "DUMP" ? STDERR : STDOUT;
    foreach($lines as $line) {
        $use_color = $level_to_color[$level];
        fwrite($out, "${use_color}[$t] $level: $line$reset\n");
    }
}

function logger(...$args) {
    logger2("INFO", ...$args);
}

function dump_traffic($direction, $message) {
    logger2("DUMP", "$direction " . bin2hex($message));
}

class RetryException extends Exception {}

class DrcomFucker {

    private $state = "new";
    private $challenge_salt = null;
    private $session_cookie = null;
    private $keepalive_cookie = null;
    private $keepalive_counter = 0;
    private $keepalive_timeout_count = 0;
    
    private $server;
    private $socket;

    private $logged_in = false;

    public $config;

    public function __construct($config) {
        $this->config = $config;
        $this->server = $config->server;
    }

    function send($data) {
        dump_traffic("sendto $this->server:61440", $data);
        socket_sendto($this->socket, $data, strlen($data), 0, $this->server, 61440);
    }



    function init_socket() {
        $this->socket = socket_create(AF_INET, SOCK_DGRAM, 0);
        if(!$this->socket) {
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);
            throw new Exception("Couldn't create socket: [$errorcode] $errormsg \n");
        }
        if(defined("SO_BINDTODEVICE") && $this->config->iface !== "") {
            $iface = $this->config->iface;
            logger2("DEBUG", "trying to bind to interface $iface");
            if(@socket_set_option($this->socket, SOL_SOCKET, SO_BINDTODEVICE, $iface) !== false) {
                logger2("INFO", "bound to interface $iface");
            } else {
                logger2("WARN", "failed to bind socket to interface");
            }
        }
        if(socket_bind($this->socket, $this->config->host_ip, 61440) !== false) {
            $ip = $this->config->host_ip;
            logger2("INFO", "bound to address $ip");
        } else {
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);
            throw new Exception("Couldn't bind socket: [$errorcode] $errormsg\n");
        }
        socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, array("sec"=>5,"usec"=>0));
    }

    function find_server() {
        if($this->server === "") {
            $message = build_challenge_message();
            logger2("INFO", "looking for server");
            $targets = array("202.1.1.1", "1.1.1.1", "192.168.255.251");
            
            foreach($targets as $target) {
                logger2("DEBUG", "trying $target");
                socket_sendto($this->socket, $message, strlen($message), 0, $target, 61440);
                dump_traffic("sendto $target:61440", $message);
                $result = @socket_recvfrom($this->socket, $recvdata, 4096, 0, $srcaddr, $srcport);
                pcntl_signal_dispatch();
                if($result !== false) {
                    dump_traffic("recvfrom $srcaddr:$srcport", $message);
                    $this->server = $srcaddr;
                    logger2("INFO", "found server $this->server");
                    break;
                }
                if($this->state === "stop") {
                    break;
                }
            }
        } else {
            logger2("INFO", "using server $this->server");
        }
    }

    function message_loop() {
        while($this->state !== "stop") {
            $len = @socket_recvfrom($this->socket, $recvdata, 4096, 0, $from, $srcport);
            pcntl_signal_dispatch();
            // state may be changed by signal handler
            if($this->state === "stop") break;
            if($len === false) {
                // error
                if($this->logged_in) {
                    logger2("WARN", "keepalive timed out");
                    $this->keepalive_timeout_count++;
                    if($this->keepalive_timeout_count < 3) {
                        $this->restart_keepalive();
                    } else {
                        throw new RetryException("too many keepalive timeouts");
                    }
                } else {
                    throw new RetryException("timed out");
                }
            } 
            dump_traffic("recvfrom $from:$srcport", $recvdata);
            if($from === $this->server && $srcport === 61440) {
                $funcname = "on_message_" . $this->state;
                if(method_exists($this, $funcname)) {
                    $this->$funcname($recvdata);
                }
            }
        }
    }

    function send_challenge() {
        $message = build_challenge_message();
        logger2("DEBUG", "send challenge");
        $this->send($message);
    }

    function on_message_login_challenge_sent($message) {
        logger2("DEBUG", "DrcomAuthLoginingHandle@on_message_login_challenge_sent");
        if($message[0] === "\x02") {
            $challenge_salt = substr($message, 4, 4);
            $this->state = "login_challenge_received";
            logger2("INFO", "DrcomAuthSendNameAndPassword");
            $response = build_login_message($this->config, $challenge_salt);
            $this->send($response);
            $this->state = "login_request_sent";
        } else {
            logger2("DEBUG", "received unexpected data on $this->state");
        }
    }

    function on_message_login_request_sent($message) {
        logger2("DEBUG", "DrcomAuthLoginingHandle@on_message_login_request_sent");
        if($message[0] === "\x04") {
            $this->state = "login_response_received";
            $this->session_cookie = substr($message, 23, 16);
            logger2("INFO", "login success");
            $this->logged_in = true;

            // empty buffer
            $r = [$this->socket];
            $w = NULL;
            $e = NULL;
            $count = socket_select($r, $w, $e, 0);
            if($count === 1) {
                socket_recvfrom($this->socket, $fuckingbuffer, 65536, 0, $fuckedhost, $fuckedport);
                dump_traffic("recvfrom $fuckedhost:$fuckedport", $fuckingbuffer);
            }
            
            $this->restart_keepalive();

        } else if ($message[0] == "\x05") {
            $this->state = "login_response_received";
            $this->on_login_error($message);
            throw new RetryException("login failed");
        } else {
            logger2("DEBUG", "received unexpected data on $this->state");
        }
    }

    function on_login_error($msg) {
        $len = strlen($msg);
        $code = ord($msg[4]);
        $desc = '';
        $simple_descs = array(
            1 => "account in use",
            2 => "server busy",
            3 => "wrong credential",
            4 => "limit exceeded",
            5 => "account suspended",
            7 => "IP mismatch",
            11 => "IP/MAC mismatch",
            20 => "too many concurrent login",
            22 => "IP/MAC mismatch",
            23 => "DHCP required",
        );
        if(array_key_exists($code, $simple_descs)) {
            $desc = $simple_descs[$code];
        }
        if(($code === 7 && $len > 8) || $code === 1) {
            $usingip  = long2ip(unpack('N', substr($msg, 5, 4))[1]);
            $desc .= " IP: $usingip";
        }
        if(($code === 11 && $len > 10) || $code === 1) {
            $usingmac = bin2hex(substr($msg, 9, 6));
            $desc .= " MAC: $usingmac";
        }
        if ($code === 4 && $len > 9) {
            $desc .= " (no credit)";
        } else if($code === 21) {
            if($len < 20) {
                $desc = "unsupported client";
            } else {
                if($msg[20] !== "\0") {
                    $desc = substr($msg, 20);
                }
            }
        }
        $desc = mb_convert_encoding($desc, "UTF-8", "GBK, UTF-8");
        logger2("ERROR", "[0x%02X] server sent message: %s", $code, $desc);
    }

    function restart_keepalive() {
        logger2("INFO", "starting keep alive");
        $this->keepalive_counter = 0;
        $this->keepalive_timeout_count = 0;
        $this->send(build_keepalive_message_type1($this->config, $this->challenge_salt, $this->session_cookie));
        $this->state = "keepalive_p1";
    }

    function on_message_keepalive_p1($message) {
        logger2("DEBUG", "DrcomAuthSvrReturnDataHandler@on_message_keepalive_p1");
        if($message[0] === "\x07") {
            // received type1()
            $this->keepalive_counter = 0;
            $this->keepalive_cookie = "\0\0\0\0";
            $this->on_received_keepalive1_response($message);
            $this->send(build_keepalive_message_type2($this->config, $this->keepalive_counter, $this->keepalive_cookie, 1, true));
            $this->state = "keepalive_p2";
        } else {
            logger2("DEBUG", "received unexpected data on $this->state");
            $this->restart_keepalive();
        }
    }

    function on_received_keepalive1_response($message) {
        $arr = unpack("V*", substr($message, 32, 20));
        logger2("DEBUG", "[SendRealTimeOnlineStatus] session %us; up %uKB; down %uKB; used %umin, %uKB", ...$arr);
    }

    function on_message_keepalive_p2($message) {
        logger2("DEBUG", "DrcomAuthSvrReturnDataHandler@on_message_keepalive_p2");
        // received type2(1, true)
        if(strncmp($message, "\x07\x00\x28\x00", 4) === 0 || strncmp($message, "\x07" . chr($this->keepalive_counter & 0xFF)  . "\x28\x00", 4) === 0) {
            // continue
            $this->send(build_keepalive_message_type2($this->config, $this->keepalive_counter, $this->keepalive_cookie, 1, false));
            $this->state = "keepalive_p3";
        } else if ($message[0] === "\x07" && $message[2] === "\x10") {
            // file
            $this->keepalive_counter++;
            $this->send(build_keepalive_message_type2($this->config, $this->keepalive_counter, $this->keepalive_cookie, 1, false));
            $this->state = "keepalive_p3";
        } else {
            logger2("DEBUG", "received unexpected data on $this->state");
            $this->restart_keepalive();
        }
    }

    function on_message_keepalive_p3($message) {
        logger2("DEBUG", "DrcomAuthSvrReturnDataHandler@on_message_keepalive_p3");
        if ($message[0] === "\x07") {
            // received type2(1, false)
            $this->keepalive_counter++;
            $this->keepalive_cookie = substr($message, 16, 4);
            $this->send(build_keepalive_message_type2($this->config, $this->keepalive_counter, $this->keepalive_cookie, 3, false));
            $this->state = "keepalive_p4";
        } else {
            logger2("DEBUG", "received unexpected data on $this->state");
            $this->restart_keepalive();
        }
    }

    function on_message_keepalive_p4($message) {
        logger2("DEBUG", "DrcomAuthSvrReturnDataHandler@on_message_keepalive_p4");
        if ($message[0] === "\x07") {
            // received type2(3, false)
            $this->keepalive_cookie = substr($message, 16, 4);
            // most likely to get SIGINT here, signal handler will change state
            logger2("DEBUG", "sleep 20");
            sleep(20);
            pcntl_signal_dispatch();
            if($this->state === "keepalive_p4") {
                $this->send(build_keepalive_message_type1($this->config, $this->challenge_salt, $this->session_cookie));
                $this->state = "keepalive_p5";
            }
        } else {
            logger2("DEBUG", "received unexpected data on $this->state");
            $this->restart_keepalive();
        }
    }

    function on_message_keepalive_p5($message) {
        logger2("DEBUG", "DrcomAuthSvrReturnDataHandler@on_message_keepalive_p5");
        if($message[0] === "\x07") {
            // received type1()
            $this->on_received_keepalive1_response($message);
            $this->keepalive_counter++;
            $this->send(build_keepalive_message_type2($this->config, $this->keepalive_counter, $this->session_cookie, 1, false));
            $this->state = "keepalive_p3";
        } else {
            logger2("DEBUG", "received unexpected data on $this->state");
            $this->restart_keepalive();
        }
    }

    function on_message_logout_challenge_sent($message) {
        logger2("DEBUG", "DrcomAuthLogoutingHandle@on_message_logout_challenge_sent");
        if($message[0] === "\x02") {
            $challenge_salt = substr($message, 4, 4);
            $this->state = "logout_challenge_received";
            logger2("INFO", "DrcomAuthSendLogoutData");
            $response = build_logout_message($this->config, $this->challenge_salt, $this->session_cookie);
            $this->send($response);
            $this->state = "logout_request_sent";
        } else {
            logger2("DEBUG", "received unexpected data on $this->state");
        }
    }

    function on_message_logout_request_sent($message) {
        logger2("DEBUG", "DrcomAuthLogoutingHandle@on_message_logout_request_sent");
        if($message[0] == "\x04") {
            $this->state = "stop";
            logger2("INFO", "logout success");
        }
    }

    public function fuck() {
        if($this->config->host_ip === "") {
            logger2("FATAL", "host_ip not set");
            return;
        }
        $this->init_socket();
        $this->find_server();
        if($this->state === "stop") {
            return;
        }
        if($this->server === "") {
            logger2("FATAL", "unable to find server");
            return;
        }
        while($this->state !== "stop") {
            try {
                $this->send_challenge();
                $this->state = "login_challenge_sent";
                $this->message_loop();
                break;
            } catch (RetryException $e) {
                logger2("ERROR", "Exception: %s", $e->getMessage());
                logger2("ERROR", "retry in 5s.");
                sleep(5);
            } catch (Exception $e) {
                logger2("FATAL", "Exception: %s", $e->getMessage());
                logger2("FATAL", "%s", $e->getTraceAsString());
                logger2("FATAL", "stopping");
                break;
            }
        }
    }

    public function unfuck() {
        logger2("DEBUG", "unfuck in $this->state");
        if($this->logged_in) {
            $this->send_challenge();
            $this->state = "logout_challenge_sent";
        } else {
            $this->state = "stop";
        }
    }
}

function main() {
    global $fucker;
    global $logging_levels;
    $opts = getopt("c:hdD", ["config:", "help", "debug", "dump-traffic", "loglevels:"]);
    if(array_key_exists("h", $opts) || array_key_exists("help", $opts)) {
?>usage: drcomfucker.php [OPTIONS]
Options:
  -c, --config=config.php               use config file config.php (default)
  -d, --debug                           output debug messages
  -D, --dump-traffic                    dump UDP traffic
      --loglevels=INFO,WARN,ERROR,FATAL filter logs
                                          available levels:
                                            INFO,WARN,ERROR,FATAL,DEBUG,DUMP
  -h, --help                            show this message and exit

<?php
        exit(0);
    }
    if(array_key_exists("d", $opts) || array_key_exists("debug", $opts)) {
        $logging_levels[] = "DEBUG";
    }
    if(array_key_exists("D", $opts) || array_key_exists("dump-traffic", $opts)) {
        $logging_levels[] = "DUMP";
    }
    if(array_key_exists("loglevels", $opts)) {
        $logging_levels = explode(",", $opts["loglevels"]);
    }
    if(array_key_exists("c", $opts)) {
        $configfile = $opts["c"];
    } else if(array_key_exists("config", $opts)) {
        $configfile = $opts["config"];
    } else {
        $configfile = "config.php";
    }
    require($configfile);

    if(!function_exists("drcomfucker_get_config")) {
        logger2("FATAL", "function drcomfucker_get_config() not defined");
        logger2("FATAL", "define it in config file");
        exit(1);
    }

    $config = drcomfucker_get_config();

    $fucker = new DrcomFucker($config);

    if(function_exists("pcntl_signal")) {
        logger2("INFO", "press Ctrl-C to logout");
        if(!function_exists("pcntl_signal_dispatch")) {
            declare(ticks=1);
            function pcntl_signal_dispatch() {}
        }
        $on_signal = function ($sig, $siginfo=null) {
            global $fucker;
            printf("\n");
            logger2("DEBUG", "received SIGINT");
            pcntl_signal(SIGINT, SIG_DFL);
            $fucker->unfuck();
        };
        pcntl_signal(SIGINT, $on_signal, false);
    } else {
        function pcntl_signal_dispatch() {}
    }

    $fucker->fuck();
}

main();