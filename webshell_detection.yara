/*
    WEBSHELL DETECTION RULES

    This file contains YARA rules to detect web-based shells (PHP, ASP, JSP).
    Covers obfuscated shells, well-known public shells, and behavioral patterns.

    Author: Leonardo Moutinho
    Date: June 2026
    MITRE ATT&CK: T1505 (Server Software Component), T1190 (Exploit Public-Facing Application)
*/

rule Webshell_PHP_CommandExecution {
    meta:
        description = "Detects PHP webshells using system command execution"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1505 - Server Software Component"
        severity = "critical"

        // Common detection on: joomla exploits, WordPress compromises, open CMS installations
        // Real-world samples: C99 shell, r57 shell, Adminer

    strings:
        // Direct PHP-to-system communication
        $exec1 = "system($_" nocase
        $exec2 = "passthru($_" nocase
        $exec3 = "shell_exec($_" nocase
        $exec4 = "exec($_" nocase
        $exec5 = "eval($_" nocase

        // Obfuscated command execution (base64, gzinflate)
        $obf1 = "base64_decode" nocase
        $obf2 = "gzinflate" nocase
        $obf3 = "gzuncompress" nocase
        $obf4 = "assert" nocase

        // HTTP parameter handling
        $http1 = "$_REQUEST" nocase
        $http2 = "$_GET" nocase
        $http3 = "$_POST" nocase

    condition:
        (any of ($exec*)) and
        (any of ($http*) or any of ($obf*))
}

rule Webshell_PHP_FileWrite {
    meta:
        description = "Detects PHP webshells that write files to filesystem"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1505 - Server Software Component"
        severity = "critical"

    strings:
        // File write operations
        $write1 = "fwrite(" nocase
        $write2 = "file_put_contents(" nocase
        $write3 = "fopen(" nocase
        $write4 = "file_get_contents($_" nocase

        // Upload handling
        $upload1 = "move_uploaded_file(" nocase
        $upload2 = "copy($_FILES" nocase
        $upload3 = "$_FILES" nocase

        // Common shell patterns
        $shell1 = "chmod(" nocase
        $shell2 = "mkdir(" nocase

    condition:
        any of ($write*) and
        (any of ($upload*) or any of ($shell*))
}

rule Webshell_ASP_ExecuteCommand {
    meta:
        description = "Detects ASP/ASP.NET webshells with command execution capability"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1505 - Server Software Component"
        severity = "critical"

    strings:
        // ASP/VBScript command execution
        $asp1 = "CreateObject(\"WScript.Shell\")" nocase
        $asp2 = "WScript.Shell" nocase
        $asp3 = "cmd.exe /c" nocase

        // ASP.NET dangerous methods
        $aspnet1 = "System.Diagnostics.Process" nocase
        $aspnet2 = "ProcessStartInfo" nocase
        $aspnet3 = "Start()" nocase

        // ASP form parameters
        $form1 = "Request.Form" nocase
        $form2 = "Request.QueryString" nocase
        $form3 = "Request(\"" nocase

    condition:
        ((any of ($asp*)) or (all of ($aspnet*))) and
        (any of ($form*))
}

rule Webshell_JSP_ReverseShell {
    meta:
        description = "Detects JSP webshells with reverse shell or command execution"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1505 - Server Software Component"
        severity = "critical"

    strings:
        // Java command execution
        $java1 = "Runtime.getRuntime().exec(" nocase
        $java2 = "ProcessBuilder" nocase
        $java3 = "java.lang.Process" nocase

        // JSP parameter handling
        $jsp1 = "request.getParameter(" nocase
        $jsp2 = "<%@ page import=" nocase

        // Common reverse shell patterns
        $rev1 = "socket(" nocase
        $rev2 = "connect(" nocase
        $rev3 = "/bin/bash" nocase
        $rev4 = "/bin/sh" nocase

    condition:
        (any of ($java*)) and
        (any of ($jsp*) or any of ($rev*))
}

rule Webshell_Generic_SuspiciousFunctions {
    meta:
        description = "Generic detection of suspicious function patterns across web shells"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1505 - Server Software Component"
        severity = "high"

    strings:
        // Create callable functions from strings
        $var1 = "($" nocase
        $var2 = "$ " nocase

        // Common variable variable patterns (indirect calls)
        $func1 = "variable_variables" nocase

        // Connection strings (SQL injection shells)
        $sql1 = "mysql_connect" nocase
        $sql2 = "mysqli" nocase
        $sql3 = "PDO(" nocase

        // Registry/config file access (privilege escalation)
        $priv1 = "get_magic_quotes_gpc" nocase
        $priv2 = "php_uname" nocase
        $priv3 = "phpinfo()" nocase

    condition:
        (any of ($func*, $var*)) and
        (any of ($sql*, $priv*))
}

rule Webshell_Known_Shells {
    meta:
        description = "Detects known public webshell samples by unique signatures"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1505 - Server Software Component"
        severity = "critical"

    strings:
        // C99 Shell signature
        $c99 = "C99 Shell" nocase
        $c99_2 = "c99.php" nocase

        // R57 Shell signature
        $r57 = "r57 shell" nocase
        $r57_2 = "r57.php" nocase

        // Adminer (often misused)
        $adminer = "Adminer" nocase
        $adminer_2 = "adminer.php" nocase

        // WSO Shell
        $wso = "WSO" nocase
        $wso_2 = "w0rm" nocase

        // Encode check (common in shells)
        $encode = "base64_encode" nocase

    condition:
        (any of ($c99*, $r57*, $adminer*, $wso*)) or
        (filesize < 1MB and $encode)
}

rule Webshell_MultiLayer_Obfuscation {
    meta:
        description = "Detects heavily obfuscated webshells using stacking techniques"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1027 - Obfuscated Files or Information"
        severity = "high"

    strings:
        // Multiple encoding layers
        $layer1 = "base64_decode(gzinflate(" nocase
        $layer2 = "gzuncompress(base64_decode(" nocase

        // Eval chains
        $eval1 = "eval(base64_decode(" nocase
        $eval2 = "assert(" nocase

        // Hex encoding patterns
        $hex1 = "\\x" nocase

        // String concatenation obfuscation
        $concat1 = "strrev(" nocase
        $concat2 = "str_rot13(" nocase

    condition:
        (any of ($layer*, $eval*, $concat*)) or
        (($hex1) and (any of ($layer*, $eval*)))
}

/*
    TESTING EXAMPLES:

    1. Scan a web directory:
       yara webshell_detection.yara /var/www/html/

    2. Scan with strings displayed:
       yara -s webshell_detection.yara /tmp/suspicious.php

    3. Create test shell to validate detection:
       echo '<?php system($_GET["cmd"]); ?>' > test.php
       yara webshell_detection.yara test.php
       // Should match: Webshell_PHP_CommandExecution

    4. Search entire web server:
       yara -r webshell_detection.yara /var/www/

    REAL-WORLD DETECTION NOTES:
    - PHP webshells often found in: wp-content, uploads/, plugins/
    - ASP shells commonly in: C:\inetpub\wwwroot\
    - JSP shells in: /tomcat/webapps/
    - Combine with file integrity monitoring for better detection
    - Check file modification times against deployment dates
    - Monitor Apache/IIS logs for POST requests to detected files
*/
