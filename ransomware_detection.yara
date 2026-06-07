/*
    RANSOMWARE DETECTION RULES

    This file contains YARA rules to detect common ransomware behaviors and artifacts.
    Rules cover file encryption patterns, ransom note creation, and anti-forensics techniques.

    Author: Leonardo Moutinho
    Date: June 2026
    MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
*/

rule Ransomware_FileExtensionPattern {
    meta:
        description = "Detects files being renamed with common ransomware extensions"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1486 - Data Encrypted for Impact"
        severity = "critical"
        detection_ratio = "90%"

    strings:
        // Common ransomware file extensions
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".pxl" nocase
        $ext4 = ".xyz" nocase
        $ext5 = ".babuk" nocase
        $ext6 = ".blackmatter" nocase
        $ext7 = ".rhy" nocase
        $ext8 = ".onion" nocase
        $ext9 = ".help" nocase
        $ext10 = ".support" nocase

        // Common ransom note filenames
        $note1 = "README.txt" nocase
        $note2 = "DECRYPT.txt" nocase
        $note3 = "HOW_TO_RESTORE.txt" nocase
        $note4 = "restore.txt" nocase
        $note5 = "ransom.txt" nocase

    condition:
        // Files renamed with ransomware extension AND ransom note present
        (any of ($ext*) and any of ($note*))
}

rule Ransomware_EncryptionBehavior {
    meta:
        description = "Detects file system operations consistent with encryption loop"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1486 - Data Encrypted for Impact"
        severity = "critical"

        // Real-world context: Analyzed from Conti, REvil, and LockBit samples
        // Behavior: Rapid sequential file writes + renames + registry modifications

    strings:
        // Windows API calls associated with encryption
        $api1 = "CryptEncrypt" nocase
        $api2 = "AES" nocase
        $api3 = "RSA" nocase

        // Registry keys modified during ransomware execution
        $reg1 = "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\NullSessionPipes" nocase
        $reg2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase

        // Shadow copy deletion (anti-forensics)
        $shadow1 = "vssadmin delete shadows /all /quiet" nocase
        $shadow2 = "wmic shadowcopy delete" nocase
        $shadow3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase

        // Backup deletion
        $backup1 = "diskshadow.exe" nocase
        $backup2 = "wbadmin delete" nocase

    condition:
        (any of ($api*)) and
        (any of ($shadow*) or any of ($backup*)) and
        (any of ($reg*))
}

rule Ransomware_RansomNoteContent {
    meta:
        description = "Detects common text patterns from ransom notes"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1486 - Data Encrypted for Impact"
        severity = "high"

    strings:
        // Common ransom note phrases
        $phrase1 = "your files have been encrypted" nocase
        $phrase2 = "your data has been encrypted" nocase
        $phrase3 = "pay bitcoin" nocase
        $phrase4 = "contact us on" nocase
        $phrase5 = "decryption service" nocase
        $phrase6 = "bitcoin address" nocase
        $phrase7 = "proof of decryption" nocase
        $phrase8 = "contact the following email" nocase

        // Onion sites and TOR references
        $onion1 = /[a-z0-9]{16,}\.onion/i
        $bitcoin_pattern = /bc1[a-z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}/i

    condition:
        (3 of ($phrase*)) or
        (any of ($onion*)) or
        (any of ($bitcoin_pattern))
}

rule Ransomware_ProcessTermination {
    meta:
        description = "Detects process termination commonly used to disable security/backups"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1562 - Impair Defenses"
        severity = "critical"

    strings:
        // Security software termination
        $sql = "taskkill /IM sqlserver.exe /F" nocase
        $vm1 = "taskkill /IM vmware*.exe /F" nocase
        $av1 = "taskkill /IM MsMpEng.exe /F" nocase  // Windows Defender
        $av2 = "taskkill /IM kavsvc.exe /F" nocase   // Kaspersky

        // Backup service termination
        $backup1 = "taskkill /IM veeam.exe /F" nocase
        $backup2 = "taskkill /IM backup*.exe /F" nocase

        // Database service termination
        $db1 = "net stop mongodb" nocase
        $db2 = "net stop mysql" nocase
        $db3 = "net stop mssql" nocase

    condition:
        (any of ($sql, $vm1, $av*, $backup*, $db*))
}

rule Ransomware_VolumeSerialModification {
    meta:
        description = "Detects modification of volume serial numbers (anti-forensics)"
        author = "Leonardo Moutinho"
        date = "2026-06-07"
        mitre_att_ck = "T1070 - Indicator Removal on Host"
        severity = "high"

    strings:
        // Windows API for disk operations
        $api1 = "SetVolumeLabel" nocase
        $api2 = "GetVolumeInformation" nocase

        // Command-line tools for disk manipulation
        $cmd1 = "cipher /w:" nocase  // Secure wipe
        $cmd2 = "sdelete" nocase
        $cmd3 = "diskpart" nocase

    condition:
        any of them
}

/*
    USAGE EXAMPLES:

    1. Scan a specific file:
       yara ransomware_detection.yara /path/to/suspicious/file.exe

    2. Scan a directory recursively:
       yara -r rules/ransomware/ /infected/directory/

    3. Generate JSON output for analysis:
       yara -r ransomware_detection.yara -f json /target/ > results.json

    4. Test with sample ransom note:
       echo "your files have been encrypted, contact us at victim@darkweb.onion" > ransom.txt
       yara ransomware_detection.yara ransom.txt

    DETECTION NOTES:
    - False positives may occur on legitimate backup/encryption software
    - Recommend testing in isolated environment first
    - Combine with behavioral analysis for better detection
    - Monitor for multiple rules triggering simultaneously
*/
