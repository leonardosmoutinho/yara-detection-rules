/*
    COMMAND & CONTROL (C2) DETECTION RULES

    This file contains YARA rules to detect command & control communication patterns,
    known C2 frameworks, beacon traffic, and lateral movement indicators.

    Author: Leonardo Moutinho
    Date: June 2026
    MITRE ATT&CK: T1071 (Application Layer Protocol), T1008 (Fallback Channels)
*/

rule C2_CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon indicators and command execution"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1071 - Application Layer Protocol, T1059 - Command and Scripting Interpreter"
        severity = "critical"

        // Cobalt Strike is leading commercial C2 framework used by APT groups
        // Beacon communicates with C2 via HTTP/HTTPS with distinctive patterns

    strings:
        // Cobalt Strike user agent strings
        $ua1 = "Mozilla/5.0 (Windows NT" nocase
        $ua2 = "MSIE 10.0" nocase
        $ua3 = "Opera/9.80" nocase

        // HTTP request patterns
        $http1 = "GET /submit.php?" nocase
        $http2 = "POST /upload.php" nocase
        $http3 = "Cookie:" nocase

        // Beacon communication headers
        $header1 = "X-Forwarded-For:" nocase
        $header2 = "X-Real-IP:" nocase

        // Known C2 domain patterns (malleable C2)
        $domain1 = "jquery.js.map" nocase
        $domain2 = "bootstrap.js" nocase
        $domain3 = "/images/style.css" nocase

        // Memory pipe patterns
        $pipe1 = "\\\\.\\pipe\\msagent_" nocase
        $pipe2 = "\\\\.\\pipe\\status_" nocase

    condition:
        (any of ($ua*, $http*, $header*)) or
        (any of ($domain*, $pipe*))
}

rule C2_Mimikatz_Execution {
    meta:
        description = "Detects Mimikatz usage for credential extraction and lateral movement"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1003 - OS Credential Dumping, T1570 - Lateral Tool Transfer"
        severity = "critical"

        // Mimikatz is leading post-exploitation tool used with C2

    strings:
        // Mimikatz command indicators
        $mimi1 = "sekurlsa::logonpasswords" nocase
        $mimi2 = "lsadump::sam" nocase
        $mimi3 = "lsadump::secrets" nocase
        $mimi4 = "privilege::debug" nocase
        $mimi5 = "token::elevate" nocase

        // Mimikatz export formats
        $export1 = "logonpasswords" nocase
        $export2 = "msv::logonpasswords" nocase
        $export3 = "ntds::dumpfile" nocase

        // Memory dump patterns
        $dump1 = "lsass" nocase
        $dump2 = "dumpcreds" nocase

        // Golden ticket creation (horizontal escalation)
        $ticket1 = "kerberos::golden" nocase
        $ticket2 = "kerberos::list" nocase

    condition:
        (any of ($mimi*, $export*)) or
        (any of ($dump*, $ticket*))
}

rule C2_DNSTunneling {
    meta:
        description = "Detects DNS tunneling for C2 communication"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1071.004 - DNS, T1008 - Fallback Channels"
        severity = "high"

        // Real-world: Used by Cobalt Strike, PuTTY RAT, iodine, dnscat2

    strings:
        // Suspicious DNS query patterns
        $dns1 = /([a-z0-9]{20,}\.[a-z0-9]{3,})/i  // Long subdomains
        $dns2 = /([a-z0-9]{40,}\.[a-z0-9]{3,})/i  // 40+ char subdomain

        // Known DNS tunneling tools
        $tool1 = "iodine" nocase
        $tool2 = "dnscat" nocase
        $tool3 = "nslookup" nocase

        // DNS query indicators
        $query1 = "recursion desired" nocase
        $query2 = "standard query" nocase

        // Base32 encoding in DNS (common obfuscation)
        $encoding1 = "[a-z2-7]{20,}" nocase

    condition:
        (any of ($dns*)) or
        (any of ($tool*, $encoding*))
}

rule C2_DynamicDNS_Beacon:
    meta:
        description = "Detects usage of Dynamic DNS services for C2 callbacks"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1008 - Fallback Channels"
        severity = "high"

        // Real-world: Malware uses DynDNS for flexible C2 infrastructure

    strings:
        // Common Dynamic DNS providers
        $dyndns1 = ".dyndns.org" nocase
        $dyndns2 = ".no-ip.org" nocase
        $dyndns3 = ".serveftp.com" nocase
        $dyndns4 = ".avi-dns.com" nocase
        $dyndns5 = ".hopto.org" nocase
        $dyndns6 = ".gotdns.com" nocase
        $dyndns7 = ".publicvm.com" nocase
        $dyndns8 = ".3322.org" nocase

        // DynDNS update protocol
        $update1 = "dynupdate" nocase
        $update2 = "dyn update" nocase

        // Frequent domain resolution (beacon heartbeat)
        $heartbeat1 = "resolution timeout" nocase
        $heartbeat2 = "retry limit" nocase

    condition:
        any of ($dyndns*) or
        (any of ($update*, $heartbeat*))
}

rule C2_Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter shellcode and behavior"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1059 - Command and Scripting Interpreter"
        severity = "critical"

        // Meterpreter is popular post-exploitation payload from Metasploit

    strings:
        // Meterpreter shellcode signature (x86)
        $meterpreter1 = { 55 8B EC 83 EC 20 53 56 57 }

        // Meterpreter behavior patterns
        $cmd1 = "cmd.exe /c" nocase
        $cmd2 = "cmd.exe /k" nocase

        // Meterpreter API calls
        $api1 = "WaitForSingleObject" nocase
        $api2 = "CreateRemoteThread" nocase
        $api3 = "VirtualAllocEx" nocase

        // Meterpreter DLL patterns
        $dll1 = "meterpreter.dll" nocase
        $dll2 = "metsrv" nocase

        // Registry keys for persistence
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase

    condition:
        (any of ($meterpreter*, $cmd*)) or
        (all of ($api*))
}

rule C2_LateralMovement_Pass_The_Hash {
    meta:
        description = "Detects Pass-the-Hash attacks for lateral movement"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1550.002 - Use Alternate Authentication Material / Pass the Hash"
        severity = "critical"

    strings:
        // Impacket toolkit (common PTH tool)
        $impacket1 = "psexec.py" nocase
        $impacket2 = "wmiexec.py" nocase
        $impacket3 = "atexec.py" nocase

        // PsExec execution
        $psexec1 = "psexec" nocase
        $psexec2 = "\\\\\\\\UNC" nocase

        // NTLM hash patterns
        $hash1 = /([a-f0-9]{32}):([a-f0-9]{32})/i

        // SMB lateral movement
        $smb1 = "445" nocase
        $smb2 = "share$" nocase
        $smb3 = "admin$" nocase
        $smb4 = "ipc$" nocase

    condition:
        (any of ($impacket*, $psexec*)) or
        (any of ($hash*, $smb*))
}

rule C2_Reverse_Shell_Patterns {
    meta:
        description = "Detects common reverse shell connection patterns"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1071 - Application Layer Protocol"
        severity = "critical"

    strings:
        // Bash reverse shell
        $bash1 = "/bin/bash" nocase
        $bash2 = "bash -i" nocase
        $bash3 = "exec 5<>" nocase

        // PowerShell reverse shell
        $ps1 = "powershell" nocase
        $ps2 = "new-object net.sockets.tcpclient" nocase
        $ps3 = "new-object io.streamwriter" nocase

        // Netcat / nc
        $nc1 = "nc -l" nocase
        $nc2 = "nc -e" nocase
        $nc3 = "ncat" nocase

        // Socket connections
        $socket1 = "socket(" nocase
        $socket2 = "connect(" nocase

        // Shell payload patterns
        $shell1 = "/bin/sh" nocase
        $shell2 = "cmd.exe" nocase

    condition:
        (any of ($bash*, $ps*, $nc*)) or
        (all of ($socket*, $shell*))
}

rule C2_Known_C2_Frameworks {
    meta:
        description = "Generic detection of known C2 framework signatures"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1071 - Application Layer Protocol"
        severity = "critical"

    strings:
        // Empire C2 framework
        $empire1 = "Empire" nocase
        $empire2 = "powershell-empire" nocase

        // Sliver C2 (modern Cobalt Strike alternative)
        $sliver1 = "Sliver" nocase
        $sliver2 = "singularity" nocase

        // PoshC2
        $posh1 = "PoshC2" nocase
        $posh2 = "runbeacon" nocase

        // Covenant C2
        $covenant1 = "Covenant" nocase
        $covenant2 = "grunts" nocase

        // Command patterns across frameworks
        $beacon1 = "beacon" nocase
        $beacon2 = "callback" nocase
        $beacon3 = "c2" nocase

    condition:
        (any of ($empire*, $sliver*, $posh*, $covenant*)) or
        (2 of ($beacon*))
}

/*
    DETECTION & HUNTING EXAMPLES:

    1. Monitor network traffic for C2:
       Wireshark filter: (http.request) and (ssl.handshake.type == 1)
       Look for: Unusual user agents, long DNS queries, Dynamic DNS services

    2. Hunt for Cobalt Strike:
       tasklist /v | findstr java
       Get-Process | Where-Object {$_.PM -gt 100MB}
       Event ID 3 (Network Connection Created)

    3. Check for Mimikatz usage:
       Monitor: lsass.exe memory access
       Event ID 10 (Process accessed)
       Sysmon logging

    4. Detect reverse shells:
       netstat -an | findstr ESTABLISHED
       lsof -i -P | grep ESTABLISHED

    HUNTING QUERIES:

    Windows Event Log:
    Event ID 3 (Sysmon Network Connection):
    - Outbound connections to suspicious IPs
    - Dynamic DNS lookups
    - High-frequency DNS queries

    Event ID 10 (Sysmon Process Access):
    - lsass.exe access (credential dumping)
    - Unusual process memory access patterns

    Event ID 5156 (Windows Firewall):
    - Outbound connections from cmd.exe, powershell.exe
    - Connections to unusual ports (4444, 5555, 8080)
*/
