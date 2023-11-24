import "math"
// only needed for debugging of module math:
//import "console"

/*

Webshell rules by Arnim Rupp (https://github.com/ruppde), Version 2

Rationale behind the rules:
1. a webshell must always execute some kind of payload (in $payload*). the payload is either:
-- direct php function like exec, file write, sql, ...
-- indirect via eval, self defined functions, callbacks, reflection, ...
2. a webshell must always have some way to get the attackers input, e.g. for PHP in $_GET, php://input or $_SERVER (HTTP for headers).

The input may be hidden in obfuscated code, so we look for either:
a) payload + input
b) eval-style-payloads + obfuscation
c) includers (webshell is split in 2+ files)
d) unique strings, if the coder doesn't even intend to hide

Additional conditions will be added to reduce false positves. Check all findings for unintentional webshells aka vulnerabilities ;)

The rules named "suspicious_" are commented by default. uncomment them to find more potentially malicious files at the price of more false positives. if that finds too many results to manually check, you can compare the hashes to virustotal with e.g. https://github.com/Neo23x0/munin

Some samples in the collection were UTF-16 and at least PHP and Java support it, so I use "wide ascii" for all strings. The performance impact is 1%. See also https://thibaud-robin.fr/articles/bypass-filter-upload/

Rules tested on the following webshell repos and collections:
    https://github.com/sensepost/reGeorg
    https://github.com/WhiteWinterWolf/wwwolf-php-webshell
    https://github.com/k8gege/Ladon
    https://github.com/x-o-r-r-o/PHP-Webshells-Collection
    https://github.com/mIcHyAmRaNe/wso-webshell
    https://github.com/LandGrey/webshell-detect-bypass
    https://github.com/threedr3am/JSP-Webshells
    https://github.com/02bx/webshell-venom
    https://github.com/pureqh/webshell
    https://github.com/secwiki/webshell-2
    https://github.com/zhaojh329/rtty
    https://github.com/modux/ShortShells
    https://github.com/epinna/weevely3
    https://github.com/chrisallenlane/novahot
    https://github.com/malwares/WebShell
    https://github.com/tanjiti/webshellSample
    https://github.com/L-codes/Neo-reGeorg
    https://github.com/bayufedra/Tiny-PHP-Webshell
    https://github.com/b374k/b374k
    https://github.com/wireghoul/htshells
    https://github.com/securityriskadvisors/cmd.jsp
    https://github.com/WangYihang/Webshell-Sniper
    https://github.com/Macr0phag3/WebShells
    https://github.com/s0md3v/nano
    https://github.com/JohnTroony/php-webshells
    https://github.com/linuxsec/indoxploit-shell
    https://github.com/hayasec/reGeorg-Weblogic
    https://github.com/nil0x42/phpsploit
    https://github.com/mperlet/pomsky
    https://github.com/FunnyWolf/pystinger
    https://github.com/tanjiti/webshellsample
    https://github.com/lcatro/php-webshell-bypass-waf
    https://github.com/zhzyker/exphub
    https://github.com/dotcppfile/daws
    https://github.com/lcatro/PHP-WebShell-Bypass-WAF
    https://github.com/ysrc/webshell-sample
    https://github.com/JoyChou93/webshell
    https://github.com/k4mpr3t/b4tm4n
    https://github.com/mas1337/webshell
    https://github.com/tengzhangchao/pycmd
    https://github.com/bartblaze/PHP-backdoors
    https://github.com/antonioCoco/SharPyShell
    https://github.com/xl7dev/WebShell
    https://github.com/BlackArch/webshells
    https://github.com/sqlmapproject/sqlmap
    https://github.com/Smaash/quasibot
    https://github.com/tennc/webshell

Webshells in these repos after fdupes run: 4722
Old signature-base rules found: 1315
This rules found: 3286
False positives in 8gb of common webapps plus yara-ci: 2

*/

rule WEBSHELL_PHP_Generic
{
    meta:
        description = "php webshell having some kind of input and some kind of payload. restricted to small files or big ones inclusing suspicious strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/14"
        modified = "2023-09-18"
        hash = "bee1b76b1455105d4bfe2f45191071cf05e83a309ae9defcf759248ca9bceddd"
        hash = "6bf351900a408120bee3fc6ea39905c6a35fe6efcf35d0a783ee92062e63a854"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "00813155bf7f5eb441e1619616a5f6b21ae31afc99caa000c4aafd54b46c3597"
        hash = "e31788042d9cdeffcb279533b5a7359b3beb1144f39bacdd3acdef6e9b4aff25"
        hash = "36b91575a08cf40d4782e5aebcec2894144f1e236a102edda2416bc75cbac8dd"
        hash = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
        hash = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
        hash = "9a8ab3c225076a26309230d7eac7681f85b271d2db22bf5a190adbf66faca2e6"
        hash = "0d3ee83adc9ebf8fb1a8c449eed5547ee5e67e9a416cce25592e80963198ae23"
        hash = "3d8708609562a27634df5094713154d8ca784dbe89738e63951e12184ff07ad6"
        hash = "70d64d987f0d9ab46514abcc868505d95dbf458387f858b0d7580e4ee8573786"
        hash = "259b3828694b4d256764d7d01b0f0f36ca0526d5ee75e134c6a754d2ab0d1caa"
        hash = "04d139b48d59fa2ef24fb9347b74fa317cb05bd8b7389aeb0a4d458c49ea7540"
        hash = "58d0e2ff61301fe0c176b51430850239d3278c7caf56310d202e0cdbdde9ac3f"
        hash = "731f36a08b0e63c63b3a2a457667dfc34aa7ff3a2aee24e60a8d16b83ad44ce2"
        hash = "e4ffd4ec67762fe00bb8bd9fbff78cffefdb96c16fe7551b5505d319a90fa18f"
        hash = "fa00ee25bfb3908808a7c6e8b2423c681d7c52de2deb30cbaea2ee09a635b7d4"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "e9423ad8e51895db0e8422750c61ef4897b3be4292b36dba67d42de99e714bff"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "3de8c04bfdb24185a07f198464fcdd56bb643e1d08199a26acee51435ff0a99f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
        hash = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"

    strings:
        $wfp_tiny1 = "escapeshellarg" fullword
        $wfp_tiny2 = "addslashes" fullword

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii
        $inp20 = "TSOP_" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus75 = "uploaded" fullword wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "str_rot13" fullword wide ascii

        $gif = { 47 49 46 38 }


        //strings from private rule capa_php_payload_multiple
        // \([^)] to avoid matching on e.g. eval() in comments
        $cmpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
        $cmpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
        $cmpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
        $cmpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
        $cmpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
        $cmpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
        $cmpayload10 = /\bpreg_replace[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload11 = /\bpreg_filter[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cmpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
        $cmpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "{@see TFileUpload} for further details." ascii
    condition:
        //any of them or
        not (
            any of ( $gfp_tiny* )
            or 1 of ($fp*)
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( filesize < 1000 and not any of ( $wfp_tiny* ) ) or
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        and
        ( filesize > 5KB or not any of ( $wfp_tiny* ) ) ) or
        ( filesize < 500KB and (
            4 of ( $cmpayload* )
        )
        ) )
}

rule WEBSHELL_ASP_OBFUSC
{
    meta:
        description = "ASP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "ad597eee256de51ffb36518cd5f0f4aa0f254f27517d28fb7543ae313b15e112"
        hash = "e0d21fdc16e0010b88d0197ebf619faa4aeca65243f545c18e10859469c1805a"
        hash = "54a5620d4ea42e41beac08d8b1240b642dd6fd7c"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
        hash = "be2fedc38fc0c3d1f925310d5156ccf3d80f1432"
        hash = "3175ee00fc66921ebec2e7ece8aa3296d4275cb5"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

    strings:
        $asp_obf1 = "/*-/*-*/" wide ascii
        $asp_obf2 = "u\"+\"n\"+\"s" wide ascii
        $asp_obf3 = "\"e\"+\"v" wide ascii
        $asp_obf4 = "a\"+\"l\"" wide ascii
        $asp_obf5 = "\"+\"(\"+\"" wide ascii
        $asp_obf6 = "q\"+\"u\"" wide ascii
        $asp_obf7 = "\"u\"+\"e" wide ascii
        $asp_obf8 = "/*//*/" wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_obfuscation_multi
        // many Chr or few and a loop????
        //$loop1 = "For "
        //$o1 = "chr(" nocase wide ascii
        //$o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o4 = "\\x8" wide ascii
        $o5 = "\\x9" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        //$o10 = " & \"" wide ascii
        //$o11 = " += \"" wide ascii
        // used for e.g. "scr"&"ipt"

        $m_multi_one1 = "Replace(" wide ascii
        $m_multi_one2 = "Len(" wide ascii
        $m_multi_one3 = "Mid(" wide ascii
        $m_multi_one4 = "mid(" wide ascii
        $m_multi_one5 = ".ToString(" wide ascii

        /*
        $m_multi_one5 = "InStr(" wide ascii
        $m_multi_one6 = "Function" wide ascii

        $m_multi_two1 = "for each" wide ascii
        $m_multi_two2 = "split(" wide ascii
        $m_multi_two3 = " & chr(" wide ascii
        $m_multi_two4 = " & Chr(" wide ascii
        $m_multi_two5 = " & Chr (" wide ascii

        $m_multi_three1 = "foreach" fullword wide ascii
        $m_multi_three2 = "(char" wide ascii

        $m_multi_four1 = "FromBase64String(" wide ascii
        $m_multi_four2 = ".Replace(" wide ascii
        $m_multi_five1 = "String.Join(\"\"," wide ascii
        $m_multi_five2 = ".Trim(" wide ascii
        $m_any1 = " & \"2" wide ascii
        $m_any2 = " += \"2" wide ascii
        */

        $m_fp1 = "Author: Andre Teixeira - andret@microsoft.com" /* FPs with 0227f4c366c07c45628b02bae6b4ad01 */
        $m_fp2 = "DataBinder.Eval(Container.DataItem" ascii wide


        //strings from private rule capa_asp_obfuscation_obviously
        $oo1 = /\w\"&\"\w/ wide ascii
        $oo2 = "*/\").Replace(\"/*" wide ascii

    condition:
        filesize < 100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and
        ( (
        (
            filesize < 100KB and
            (
                //( #o1+#o2 ) > 50 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
            )
        ) or (
            filesize < 5KB and
            (
                //( #o1+#o2 ) > 10 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 5 or
                (
                    //( #o1+#o2 ) > 1 and
                    ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 3
                )

            )
        ) or (
            filesize < 700 and
            (
                //( #o1+#o2 ) > 1 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 3 or
                ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 2
            )
        )
        )
        or any of ( $asp_obf* ) ) or (
        (
            filesize < 100KB and
            (
                ( #oo1 ) > 2 or
                $oo2
            )
        ) or (
            filesize < 25KB and
            (
                ( #oo1 ) > 1
            )
        ) or (
            filesize < 1KB and
            (
                ( #oo1 ) > 0
            )
        )
        )
        )
        and not any of ( $m_fp* )
}

