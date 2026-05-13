rule PDF_Active_Content_Indicators
{
    meta:
        description = "PDF with active-content or embedded-object indicators"
        category = "pdf"
    strings:
        $pdf = "%PDF"
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $open = "/OpenAction"
        $aa = "/AA"
        $launch = "/Launch"
        $embed = "/EmbeddedFile"
        $xfa = "/XFA"
    condition:
        $pdf at 0 and any of ($js*, $open, $aa, $launch, $embed, $xfa)
}

rule PDF_Embedded_Or_Encrypted_Content
{
    meta:
        description = "PDF with embedded files, object streams, encryption, or rich media"
        category = "pdf"
    strings:
        $pdf = "%PDF"
        $embed1 = "/EmbeddedFile"
        $embed2 = "/Filespec"
        $objstm = "/ObjStm"
        $encrypt = "/Encrypt"
        $rich = "/RichMedia"
        $acro = "/AcroForm"
        $xfa = "/XFA"
    condition:
        $pdf at 0 and any of ($embed*, $objstm, $encrypt, $rich, $acro, $xfa)
}

rule PDF_External_Link_Or_Form_Action
{
    meta:
        description = "PDF with external links or form submission actions"
        category = "pdf"
    strings:
        $pdf = "%PDF"
        $uri = "/URI"
        $submit = "/SubmitForm"
        $gotor = "/GoToR"
        $gotoe = "/GoToE"
        $http1 = "http://" nocase
        $http2 = "https://" nocase
    condition:
        $pdf at 0 and any of ($uri, $submit, $gotor, $gotoe) and any of ($http*)
}

rule Script_Suspicious_Execution
{
    meta:
        description = "Script or command text with suspicious execution primitives"
        category = "script"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "FromBase64String" nocase
        $ps3 = "Invoke-Expression" nocase
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "wscript.shell" nocase
        $cmd3 = "rundll32" nocase
        $net1 = "http://" nocase
        $net2 = "https://" nocase
    condition:
        2 of them
}

rule Script_Encoded_Powershell
{
    meta:
        description = "PowerShell command line with encoded-command style arguments"
        category = "script"
    strings:
        $ps = "powershell" nocase
        $enc1 = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $hidden = "-windowstyle hidden" nocase
        $nop = "-nop" nocase
        $b64_ps1 = /(SQB|JAB|UwB|YwB)[A-Za-z0-9+\/]{80,}={0,2}/
    condition:
        $ps and any of ($enc*) and ($b64_ps1 or $hidden or $nop)
}

rule Script_Download_And_Execute
{
    meta:
        description = "Script-like content that combines download and execution indicators"
        category = "script"
    strings:
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $download3 = "curl" nocase
        $download4 = "wget" nocase
        $download5 = "Invoke-WebRequest" nocase
        $exec1 = "Start-Process" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "cmd.exe" nocase
        $exec4 = "powershell" nocase
        $net1 = "http://" nocase
        $net2 = "https://" nocase
    condition:
        any of ($download*) and any of ($exec*) and any of ($net*)
}

rule Windows_LOLBins_Command_Surface
{
    meta:
        description = "Windows living-off-the-land binary command names"
        category = "command"
    strings:
        $l1 = "mshta.exe" nocase
        $l2 = "regsvr32.exe" nocase
        $l3 = "rundll32.exe" nocase
        $l4 = "certutil.exe" nocase
        $l5 = "bitsadmin.exe" nocase
        $l6 = "wmic.exe" nocase
        $l7 = "schtasks.exe" nocase
        $l8 = "installutil.exe" nocase
        $l9 = "msiexec.exe" nocase
    condition:
        2 of them
}

rule PE_Suspicious_API_Surface
{
    meta:
        description = "PE-like file with suspicious Windows API strings"
        category = "pe"
    strings:
        $mz = "MZ"
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "LoadLibrary" ascii wide
        $api5 = "GetProcAddress" ascii wide
        $api6 = "WinExec" ascii wide
        $api7 = "URLDownloadToFile" ascii wide
    condition:
        $mz at 0 and 2 of ($api*)
}

rule PE_Networking_API_Surface
{
    meta:
        description = "PE-like file with Windows networking API strings"
        category = "pe"
    strings:
        $mz = "MZ"
        $net1 = "InternetOpen" ascii wide
        $net2 = "InternetConnect" ascii wide
        $net3 = "HttpOpenRequest" ascii wide
        $net4 = "WinHttpOpen" ascii wide
        $net5 = "WinHttpConnect" ascii wide
        $net6 = "WSAStartup" ascii wide
        $net7 = "connect" ascii wide
        $net8 = "send" ascii wide
        $net9 = "recv" ascii wide
        $ua = "User-Agent" ascii wide nocase
    condition:
        $mz at 0 and 3 of ($net*, $ua)
}

rule PE_Persistence_And_System_Modification_API
{
    meta:
        description = "PE-like file with persistence or system modification API strings"
        category = "pe"
    strings:
        $mz = "MZ"
        $reg1 = "RegSetValue" ascii wide
        $reg2 = "RegCreateKey" ascii wide
        $svc1 = "CreateService" ascii wide
        $svc2 = "StartService" ascii wide
        $svc3 = "OpenSCManager" ascii wide
        $task = "schtasks" ascii wide nocase
        $startup = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase
    condition:
        $mz at 0 and 2 of ($reg*, $svc*, $task, $startup)
}

rule PE_AntiDebug_Or_VM_Strings
{
    meta:
        description = "PE-like file with anti-debug or virtual-machine related strings"
        category = "pe"
    strings:
        $mz = "MZ"
        $dbg1 = "IsDebuggerPresent" ascii wide
        $dbg2 = "CheckRemoteDebuggerPresent" ascii wide
        $dbg3 = "OutputDebugString" ascii wide
        $dbg4 = "NtQueryInformationProcess" ascii wide
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VirtualBox" ascii wide nocase
        $vm3 = "VBox" ascii wide nocase
        $vm4 = "QEMU" ascii wide nocase
        $vm5 = "Sandboxie" ascii wide nocase
    condition:
        $mz at 0 and 2 of ($dbg*, $vm*)
}

rule PE_Credential_Or_Browser_Targeting_Strings
{
    meta:
        description = "PE-like file with browser or credential-store targeting strings"
        category = "pe"
    strings:
        $mz = "MZ"
        $b1 = "Login Data" ascii wide
        $b2 = "Cookies" ascii wide
        $b3 = "Local State" ascii wide
        $b4 = "key4.db" ascii wide
        $b5 = "logins.json" ascii wide
        $c1 = "CryptUnprotectData" ascii wide
        $c2 = "sqlite3_open" ascii wide
    condition:
        $mz at 0 and 3 of ($b*, $c*)
}

rule Office_Macro_Indicators
{
    meta:
        description = "Office/OLE macro and automation indicators"
        category = "office"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $vba1 = "VBA" ascii wide
        $vba2 = "AutoOpen" ascii wide nocase
        $vba3 = "Document_Open" ascii wide nocase
        $vba4 = "CreateObject" ascii wide nocase
        $vba5 = "Shell" ascii wide nocase
    condition:
        $ole at 0 and 2 of ($vba*)
}

rule Office_OOXML_Macro_Or_External_Relationship
{
    meta:
        description = "OOXML document with macro project or external relationship indicators"
        category = "office"
    strings:
        $zip = { 50 4B 03 04 }
        $vba = "vbaProject.bin" ascii nocase
        $macro = "macrosheets" ascii nocase
        $rel1 = "TargetMode=\"External\"" ascii nocase
        $rel2 = "oleObject" ascii nocase
        $rel3 = "attachedTemplate" ascii nocase
        $rel4 = "http://" ascii nocase
        $rel5 = "https://" ascii nocase
    condition:
        $zip at 0 and ($vba or $macro or (any of ($rel1, $rel2, $rel3) and any of ($rel4, $rel5)))
}

rule Archive_Java_Android_Package_Indicators
{
    meta:
        description = "ZIP-like archive with JAR/APK package indicators"
        category = "archive"
    strings:
        $zip = { 50 4B 03 04 }
        $jar1 = "META-INF/MANIFEST.MF" ascii
        $jar2 = ".class" ascii
        $apk1 = "AndroidManifest.xml" ascii
        $apk2 = "classes.dex" ascii
        $apk3 = "resources.arsc" ascii
    condition:
        $zip at 0 and (2 of ($jar*) or 2 of ($apk*))
}

rule ELF_Suspicious_Runtime_Surface
{
    meta:
        description = "ELF file with runtime execution, tracing, or network tooling strings"
        category = "elf"
    strings:
        $elf = { 7F 45 4C 46 }
        $exec1 = "/bin/sh" ascii
        $exec2 = "system" ascii
        $exec3 = "execve" ascii
        $trace1 = "ptrace" ascii
        $trace2 = "LD_PRELOAD" ascii
        $net1 = "curl" ascii nocase
        $net2 = "wget" ascii nocase
        $net3 = "http://" ascii nocase
        $net4 = "https://" ascii nocase
    condition:
        $elf at 0 and 3 of ($exec*, $trace*, $net*)
}

rule Generic_High_Signal_Base64_Text
{
    meta:
        description = "Text-like file containing long base64-looking blobs plus execution indicators"
        category = "generic"
    strings:
        $b64_payload = /(TVqQ|UEsDB|JVBER|H4sI|PD94)[A-Za-z0-9+\/]{80,}={0,2}/
        $exec1 = "powershell" nocase
        $exec2 = "cmd.exe" nocase
        $exec3 = "eval" nocase
        $exec4 = "base64" nocase
        $exec5 = "FromBase64String" nocase
    condition:
        $b64_payload and any of ($exec*)
}
