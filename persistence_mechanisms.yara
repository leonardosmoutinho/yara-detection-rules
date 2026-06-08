/*
    PERSISTENCE MECHANISM DETECTION RULES

    This file contains YARA rules to detect common persistence techniques.

    Author: Leonardo Moutinho
    Date: June 2026
    MITRE ATT&CK: T1547, T1053
*/

rule Persistence_ScheduledTaskCreation {
    meta:
        description = "Detects creation of suspicious scheduled tasks for persistence"
        author = "Leonardo Moutinho"
        mitre_att_ck = "T1053 - Scheduled Task/Job"
        severity = "critical"

    strings:
        $schtasks1 = "schtasks /create" nocase
        $schtasks2 = "/tr " nocase
        $exec1 = "cmd.exe" nocase
        $exec2 = "powershell" nocase

    condition:
        ($schtasks1 and $schtasks2) or
        ($schtasks1 and any of ($exec*))
}

rule Persistence_RegistryRunKey {
    meta:
        description = "Detects registry modifications for Run key persistence"
        author = "Leonardo Moutinho"
        mitre_att_ck = "T1547.001 - Registry Run Keys / Startup Folder"
        severity = "critical"

    strings:
        $run1 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $run4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase

        $reg_cmd1 = "reg add" nocase
        $suspicious1 = "cmd.exe" nocase
        $suspicious2 = "powershell.exe" nocase

    condition:
        (any of ($run*)) and
        ($reg_cmd1 or any of ($suspicious*))
}

rule Persistence_StartupFolderAbuse {
    meta:
        description = "Detects attempts to place malware in Windows startup folders"
        author = "Leonardo Moutinho"
        mitre_att_ck = "T1547.001 - Registry Run Keys / Startup Folder"
        severity = "critical"

    strings:
        $startup1 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $startup2 = "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase

        $copy1 = "copy " nocase
        $move1 = "move " nocase

        $exe1 = ".exe" nocase
        $exe2 = ".bat" nocase

    condition:
        (any of ($startup*)) and
        (any of ($copy*, $move*)) and
        (any of ($exe*))
}

rule Persistence_WMIEventSubscription {
    meta:
        description = "Detects WMI event subscription abuse for persistence"
        author = "Leonardo Moutinho"
        mitre_att_ck = "T1546.003 - Event Triggered Execution / WMI Event Subscription"
        severity = "critical"

    strings:
        $wmi1 = "wmic.exe" nocase
        $event1 = "Create EventFilter" nocase
        $event2 = "CommandLineEventConsumer" nocase
        $cmd1 = "cmd.exe" nocase
        $script1 = ".vbs" nocase

    condition:
        (any of ($wmi*, $event*)) and
        (any of ($cmd*, $script*))
}

rule Persistence_TaskSchedulerAbuse {
    meta:
        description = "Detects abuse of Windows Task Scheduler for persistence (advanced)"
        author = "Leonardo Moutinho"
        mitre_att_ck = "T1053.005 - Scheduled Task/Job"
        severity = "high"

    strings:
        $xml1 = "<?xml" nocase
        $xml2 = "<Task" nocase
        $xml4 = "<Exec>" nocase

        $prop1 = "HighestAvailable" nocase
        $trigger1 = "OnLogon" nocase

    condition:
        (all of ($xml1, $xml2, $xml4)) and
        (any of ($prop*, $trigger*))
}

rule Persistence_PrinterSpooler {
    meta:
        description = "Detects attempts to inject DLL into Print Spooler for persistence"
        author = "Leonardo Moutinho"
        mitre_att_ck = "T1547 - Boot or Logon Autostart Execution"
        severity = "high"

    strings:
        $spooler1 = "System32\\spool" nocase
        $dll1 = ".dll" nocase
        $service1 = "spoolsv.exe" nocase

    condition:
        ($spooler1) and
        (any of ($dll*, $service*))
}

rule Persistence_ServiceInstallation {
    meta:
        description = "Detects installation of malicious Windows services for persistence"
        author = "Leonardo Moutinho"
        mitre_att_ck = "T1543.003 - Create or Modify System Process / Windows Service"
        severity = "critical"

    strings:
        $sc_create = "sc.exe create" nocase
        $binpath = "binpath=" nocase
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell.exe" nocase

    condition:
        ($sc_create and $binpath) and
        (any of ($cmd*))
}
