/*
    PERSISTENCE MECHANISM DETECTION RULES

    This file contains YARA rules to detect common persistence techniques:
    scheduled tasks, registry modifications, startup folder abuse, WMI event subscriptions.

    Author: Leonardo Moutinho
    Date: June 2026
    MITRE ATT&CK: T1547 (Boot or Logon Autostart Execution), T1053 (Scheduled Task/Job)
*/

rule Persistence_ScheduledTaskCreation {
    meta:
        description = "Detects creation of suspicious scheduled tasks for persistence"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1053 - Scheduled Task/Job"
        severity = "critical"

        // Real-world: Used by Emotet, Trickbot, Ryuk, Conti for persistence

    strings:
        // schtasks.exe command line indicators
        $schtasks1 = "schtasks /create" nocase
        $schtasks2 = "/tr " nocase     // Task to run
        $schtasks3 = "/sc " nocase     // Schedule (MINUTE, HOURLY, DAILY, WEEKLY)
        $schtasks4 = "/tn " nocase     // Task name

        // Suspicious task paths (hidden tasks use backslash prefix)
        $path1 = "\\Microsoft\\" nocase
        $path2 = "\\System32\\" nocase
        $path3 = "\\Windows\\" nocase

        // Command execution indicators
        $exec1 = "cmd.exe" nocase
        $exec2 = "powershell" nocase
        $exec3 = "cmd /c" nocase

        // Obfuscation techniques
        $obf1 = "\\x" nocase
        $obf2 = "^" nocase              // CMD escape character

    condition:
        ($schtasks1 and $schtasks2) or
        ($schtasks1 and any of ($exec*)) or
        (any of ($path*) and any of ($exec*))
}

rule Persistence_RegistryRunKey {
    meta:
        description = "Detects registry modifications for Run key persistence"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1547.001 - Registry Run Keys / Startup Folder"
        severity = "critical"

    strings:
        // Registry Run key locations
        $run1 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $run4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase

        // Registry modification commands
        $reg_cmd1 = "reg add" nocase
        $reg_cmd2 = "SetValue" nocase
        $reg_cmd3 = "CreateKey" nocase

        // Suspicious values (unusual paths, cmd execution)
        $suspicious1 = "cmd.exe" nocase
        $suspicious2 = "powershell.exe" nocase
        $suspicious3 = ".ps1" nocase
        $suspicious4 = "rundll32" nocase
        $suspicious5 = "mshta" nocase

    condition:
        (any of ($run*)) and
        (any of ($reg_cmd*) or any of ($suspicious*))
}

rule Persistence_StartupFolderAbuse {
    meta:
        description = "Detects attempts to place malware in Windows startup folders"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1547.001 - Registry Run Keys / Startup Folder"
        severity = "critical"

    strings:
        // Startup folder paths
        $startup1 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $startup2 = "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $startup3 = "\\Startup\\" nocase

        // File operation verbs
        $copy1 = "copy " nocase
        $copy2 = "xcopy " nocase
        $move1 = "move " nocase
        $write1 = "file_put_contents" nocase
        $write2 = "WriteFile" nocase

        // Common executable extensions
        $exe1 = ".exe" nocase
        $exe2 = ".scr" nocase
        $exe3 = ".bat" nocase
        $exe4 = ".ps1" nocase
        $exe5 = ".vbs" nocase

    condition:
        (any of ($startup*)) and
        (any of ($copy*, $move*, $write*)) and
        (any of ($exe*))
}

rule Persistence_WMIEventSubscription {
    meta:
        description = "Detects WMI event subscription abuse for persistence"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1546.003 - Event Triggered Execution / WMI Event Subscription"
        severity = "critical"

        // Real-world: APT29 (Cozy Bear) uses WMI for persistent C2

    strings:
        // WMI command line tools
        $wmi1 = "wmic.exe" nocase
        $wmi2 = "wmi.exe" nocase

        // Event subscription creation
        $event1 = "Create EventFilter" nocase
        $event2 = "CommandLineEventConsumer" nocase
        $event3 = "__EventConsumer" nocase
        $event4 = "ActiveScriptEventConsumer" nocase

        // Suspicious WMI queries
        $query1 = "SELECT.*FROM.*Win32_" nocase
        $query2 = "TargetEvent" nocase

        // Command execution indicators
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $script1 = ".vbs" nocase
        $script2 = ".js" nocase

    condition:
        (any of ($wmi*, $event*)) and
        (any of ($cmd*, $script*, $query*))
}

rule Persistence_TaskSchedulerAbuse {
    meta:
        description = "Detects abuse of Windows Task Scheduler for persistence (advanced)"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1053.005 - Scheduled Task/Job"
        severity = "high"

    strings:
        // Task scheduler XML manipulation
        $xml1 = "<?xml" nocase
        $xml2 = "<Task" nocase
        $xml3 = "<Actions>" nocase
        $xml4 = "<Exec>" nocase
        $xml5 = "Command>" nocase

        // Suspicious task properties
        $prop1 = "HighestAvailable" nocase    // Elevated privileges
        $prop2 = "SYSTEM" nocase              // System context

        // Trigger patterns (unusual times)
        $trigger1 = "OnLogon" nocase
        $trigger2 = "OnStartup" nocase
        $trigger3 = "AtSystemStart" nocase

    condition:
        (all of ($xml1, $xml2, $xml4)) and
        (any of ($prop*, $trigger*))
}

rule Persistence_PrinterSpooler {
    meta:
        description = "Detects attempts to inject DLL into Print Spooler for persistence"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1547 - Boot or Logon Autostart Execution"
        severity = "high"

        // Real-world: CVE-2020-1048, CVE-2021-34481 exploits

    strings:
        // Spooler driver paths
        $spooler1 = "System32\\spool\\drivers\\color" nocase
        $spooler2 = "System32\\spool\\drivers\\w32x86" nocase
        $spooler3 = "System32\\spool" nocase

        // DLL injection patterns
        $dll1 = ".dll" nocase
        $inject1 = "mscorlib" nocase
        $inject2 = "clr.dll" nocase

        // Spooler service commands
        $service1 = "spoolsv.exe" nocase
        $service2 = "net start spooler" nocase

    condition:
        (any of ($spooler*)) and
        (any of ($dll*, $inject*))
}

rule Persistence_ServiceInstallation {
    meta:
        description = "Detects installation of malicious Windows services for persistence"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1543.003 - Create or Modify System Process / Windows Service"
        severity = "critical"

    strings:
        // Service creation commands
        $sc_create = "sc.exe create" nocase
        $sc_start = "sc.exe start" nocase
        $sc_description = "sc.exe description" nocase

        // Service parameters
        $binpath = "binpath=" nocase
        $start_type = "start=" nocase

        // Suspicious service names (mimicking legitimate services)
        $fake1 = "Windows" nocase
        $fake2 = "System" nocase
        $fake3 = "Update" nocase

        // Command execution from service
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell.exe" nocase

    condition:
        ($sc_create or $sc_start) and
        (any of ($binpath, $start_type)) and
        (any of ($cmd*))
}

/*
    DETECTION AND TESTING:

    1. Monitor scheduled task creation:
       tasklist /v | findstr "schtasks"
       Get-ScheduledTask -TaskPath "\*" | Where-Object {$_.Author -like "*"}

    2. Check Run registry keys:
       reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
       reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

    3. Scan for WMI persistence:
       wmic /namespace:\\root\subscription PATH __EventFilter
       wmic /namespace:\\root\subscription PATH CommandLineEventConsumer

    4. Test rule against suspicious script:
       echo "schtasks /create /tn \"WindowsUpdate\" /tr \"cmd.exe /c powershell -nop\"" > test.txt
       yara persistence_mechanisms.yara test.txt
       // Should match: Persistence_ScheduledTaskCreation

    DEFENSIVE RECOMMENDATIONS:
    - Monitor %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup for new files
    - Audit scheduled task creation via Windows Event ID 4698
    - Monitor WMI event consumer creation via Event ID 5861
    - Use Windows Defender for Application Control to restrict service creation
    - Implement AppLocker rules for schtasks.exe and sc.exe
*/
