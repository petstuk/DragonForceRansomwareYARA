/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2025-06-07
   Identifier: dragonforce
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570 {
   meta:
      description = "dragonforce - file 01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9 {
   meta:
      description = "dragonforce - file 80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef {
   meta:
      description = "dragonforce - file 822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d {
   meta:
      description = "dragonforce - file b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32 {
   meta:
      description = "dragonforce - file b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429 {
   meta:
      description = "dragonforce - file ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c {
   meta:
      description = "dragonforce - file c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6 {
   meta:
      description = "dragonforce - file d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403 {
   meta:
      description = "dragonforce - file df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b {
   meta:
      description = "dragonforce - file 1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b"
   strings:
      $s1 = "gdi32.dll" fullword ascii
      $s2 = "ccccUUUU!!!!" fullword ascii
      $s3 = "GetKeyNameTextW" fullword ascii
      $s4 = "YYYYGGGG" fullword ascii
      $s5 = "GetMessageW" fullword ascii
      $s6 = "&&&&6666????" fullword ascii /* hex encoded string 'ff' */
      $s7 = "GetTextColor" fullword ascii
      $s8 = "GetDlgItem" fullword ascii
      $s9 = "EndDialog" fullword ascii
      $s10 = "GetWindowTextW" fullword ascii
      $s11 = "DialogBoxParamW" fullword ascii
      $s12 = "GetTickCount" fullword ascii
      $s13 = "eeeezzzz" fullword ascii
      $s14 = "kkkkoooo" fullword ascii
      $s15 = "YYYY''''" fullword ascii
      $s16 = "CCCCDDDD" ascii
      $s17 = "FFFFWWWW" fullword ascii
      $s18 = "x%Jo%.\\r." fullword ascii
      $s19 = "GetDeviceCaps" fullword ascii
      $s20 = "CCCCMMMM3333" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83 {
   meta:
      description = "dragonforce - file 312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83"
   strings:
      $s1 = "CreateProcessWithTokenW" fullword ascii
      $s2 = "StartServiceW" fullword ascii
      $s3 = "CreateServiceW" fullword ascii
      $s4 = "y-MEYJ}s3" fullword ascii
      $s5 = "URPQQhp" fullword ascii
      $s6 = "ONoo_?SH" fullword ascii
      $s7 = "jLhI7,O" fullword ascii
      $s8 = "gdrv\\H" fullword ascii
      $s9 = "jFhkq-D" fullword ascii
      $s10 = "ysrgs6V" fullword ascii
      $s11 = "izaj;7C" fullword ascii
      $s12 = "DuplicateTokenEx" fullword ascii
      $s13 = "\\X\\H!t%" fullword ascii
      $s14 = "TUnDQ9" fullword ascii
      $s15 = "5 5$5<5L5P5h5x5|5" fullword ascii
      $s16 = "1$1,10181L1T1\\1d1h1l1t1" fullword ascii
      $s17 = "3N3U3^3" fullword ascii
      $s18 = "E-BKGI" fullword ascii
      $s19 = "9n;u;|;" fullword ascii
      $s20 = "6 6(60686@6H6" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3 {
   meta:
      description = "dragonforce - file d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3"
   strings:
      $s1 = "CreateProcessWithTokenW" fullword ascii
      $s2 = "StartServiceW" fullword ascii
      $s3 = "CreateServiceW" fullword ascii
      $s4 = "gS{NA\\+ " fullword ascii
      $s5 = "URPQQhp" fullword ascii
      $s6 = "jLhI7,O" fullword ascii
      $s7 = "jFhkq-D" fullword ascii
      $s8 = "FbzR:Gx8" fullword ascii
      $s9 = "@JjdlGjF|Znve" fullword ascii
      $s10 = "RqzQ/H!" fullword ascii
      $s11 = "FKOL&68" fullword ascii
      $s12 = "xPtD\\F" fullword ascii
      $s13 = "faHe):Y7" fullword ascii
      $s14 = "DuplicateTokenEx" fullword ascii
      $s15 = "5 5$5<5L5P5h5x5|5" fullword ascii
      $s16 = "1$1,10181L1T1\\1d1h1l1t1" fullword ascii
      $s17 = "3N3U3^3" fullword ascii
      $s18 = "9n;u;|;" fullword ascii
      $s19 = "6 6(60686@6H6" fullword ascii
      $s20 = "4'5;5k5t5" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9 {
   meta:
      description = "dragonforce - file d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9"
   strings:
      $s1 = "CreateProcessWithTokenW" fullword ascii
      $s2 = "StartServiceW" fullword ascii
      $s3 = "CreateServiceW" fullword ascii
      $s4 = "y-MEYJ}s3" fullword ascii
      $s5 = "URPQQhp" fullword ascii
      $s6 = "ONoo_?SH" fullword ascii
      $s7 = "jLhI7,O" fullword ascii
      $s8 = "gdrv\\H" fullword ascii
      $s9 = "jFhkq-D" fullword ascii
      $s10 = "ysrgs6V" fullword ascii
      $s11 = "izaj;7C" fullword ascii
      $s12 = "DuplicateTokenEx" fullword ascii
      $s13 = "\\X\\H!t%" fullword ascii
      $s14 = "TUnDQ9" fullword ascii
      $s15 = "5 5$5<5L5P5h5x5|5" fullword ascii
      $s16 = "1$1,10181L1T1\\1d1h1l1t1" fullword ascii
      $s17 = "3N3U3^3" fullword ascii
      $s18 = "E-BKGI" fullword ascii
      $s19 = "9n;u;|;" fullword ascii
      $s20 = "6 6(60686@6H6" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}


/* Super Rules ------------------------------------------------------------- */

rule _01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570_312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3f_0 {
   meta:
      description = "dragonforce - from files 01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570.exe, 312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83.exe, 80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9.exe, 822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef.exe, b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d.exe, b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32.exe, ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429.exe, c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c.exe, d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6.exe, d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3.exe, d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9.exe, df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570"
      hash2 = "312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83"
      hash3 = "80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9"
      hash4 = "822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef"
      hash5 = "b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d"
      hash6 = "b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32"
      hash7 = "ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429"
      hash8 = "c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c"
      hash9 = "d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6"
      hash10 = "d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3"
      hash11 = "d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9"
      hash12 = "df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403"
   strings:
      $s1 = "Process is elevated: %d" fullword wide
      $s2 = "ADVAPI32.dll" fullword ascii
      $s3 = "OLEAUT32.dll" fullword ascii
      $s4 = "kernel32.dll" fullword wide
      $s5 = "mscoree.dll" fullword wide
      $s6 = "GetCurrentProcessId" fullword ascii
      $s7 = "GetCurrentProcess" fullword ascii
      $s8 = "GetProcessHeap" fullword ascii
      $s9 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s10 = "ole32.dll" fullword ascii
      $s11 = "OpenProcessToken" fullword ascii
      $s12 = "no child process" fullword ascii
      $s13 = "executable format error" fullword ascii
      $s14 = "no such process" fullword ascii
      $s15 = "connection already in progress" fullword ascii
      $s16 = "WS2_32.dll" fullword ascii
      $s17 = "broken pipe" fullword ascii
      $s18 = "GetTempPath2W" fullword ascii
      $s19 = "host unreachable" fullword ascii
      $s20 = "IsProcessorFeaturePresent" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570_80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d_1 {
   meta:
      description = "dragonforce - from files 01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570.exe, 80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9.exe, 822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef.exe, b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d.exe, b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32.exe, ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429.exe, c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c.exe, d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6.exe, df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570"
      hash2 = "80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9"
      hash3 = "822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef"
      hash4 = "b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d"
      hash5 = "b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32"
      hash6 = "ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429"
      hash7 = "c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c"
      hash8 = "d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6"
      hash9 = "df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403"
   strings:
      $s1 = "SHELL32.dll" fullword ascii
      $s2 = "SHLWAPI.dll" fullword ascii
      $s3 = "IPHLPAPI.DLL" fullword ascii
      $s4 = "NETAPI32.dll" fullword ascii
      $s5 = "RstrtMgr.DLL" fullword ascii
      $s6 = "GetProcessId" fullword ascii
      $s7 = "CreateMutexA" fullword ascii
      $s8 = "CreateProcessW" fullword ascii
      $s9 = "CommandLineToArgvW" fullword ascii
      $s10 = "PostQueuedCompletionStatus" fullword ascii
      $s11 = "GetQueuedCompletionStatus" fullword ascii
      $s12 = "GetNativeSystemInfo" fullword ascii
      $s13 = "GetLogicalDriveStringsW" fullword ascii
      $s14 = "CreateIoCompletionPort" fullword ascii
      $s15 = "RmGetList" fullword ascii
      $s16 = "4%4,4_4&5-5" fullword ascii /* hex encoded string 'DDU' */
      $s17 = "CryptEncrypt" fullword ascii
      $s18 = "GetIpNetTable" fullword ascii
      $s19 = "GetFileAttributesW" fullword ascii
      $s20 = "CoSetProxyBlanket" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "d428b0554d443c341b28703744573111" and ( 8 of them )
      ) or ( all of them )
}

rule _312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83_d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c2_2 {
   meta:
      description = "dragonforce - from files 312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83.exe, d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3.exe, d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83"
      hash2 = "d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3"
      hash3 = "d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9"
   strings:
      $s1 = "CreateProcessWithTokenW" fullword ascii
      $s2 = "StartServiceW" fullword ascii
      $s3 = "CreateServiceW" fullword ascii
      $s4 = "URPQQhp" fullword ascii
      $s5 = "jLhI7,O" fullword ascii
      $s6 = "jFhkq-D" fullword ascii
      $s7 = "DuplicateTokenEx" fullword ascii
      $s8 = "5 5$5<5L5P5h5x5|5" fullword ascii
      $s9 = "1$1,10181L1T1\\1d1h1l1t1" fullword ascii
      $s10 = "3N3U3^3" fullword ascii
      $s11 = "9n;u;|;" fullword ascii
      $s12 = "6 6(60686@6H6" fullword ascii
      $s13 = "4'5;5k5t5" fullword ascii
      $s14 = "9 9$9(9,90949" fullword ascii
      $s15 = "5$5,50?8?@?H?P?X?`?h?p?x?" fullword ascii
      $s16 = "9&9d9v9" fullword ascii
      $s17 = ";h;r;w;" fullword ascii
      $s18 = "2\"373A3" fullword ascii
      $s19 = "2 2$2(2,2024282<2@2D2H2L2P2T2X2\\2h2l2p2t2x2|2" fullword ascii
      $s20 = "6$6X6x6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "3290792225a4bb825deba733e52cbd8e" and ( 8 of them )
      ) or ( all of them )
}

rule _312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83_d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a5_3 {
   meta:
      description = "dragonforce - from files 312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83.exe, d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83"
      hash2 = "d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9"
   strings:
      $s1 = "y-MEYJ}s3" fullword ascii
      $s2 = "ONoo_?SH" fullword ascii
      $s3 = "gdrv\\H" fullword ascii
      $s4 = "ysrgs6V" fullword ascii
      $s5 = "izaj;7C" fullword ascii
      $s6 = "\\X\\H!t%" fullword ascii
      $s7 = "TUnDQ9" fullword ascii
      $s8 = "E-BKGI" fullword ascii
      $s9 = "p;r?q>" fullword ascii
      $s10 = "*3mI/x" fullword ascii
      $s11 = "y|i_7$" fullword ascii
      $s12 = "_FUm8<" fullword ascii
      $s13 = "Q/Y6uC6" fullword ascii
      $s14 = "451!Mp~d" fullword ascii
      $s15 = "c >)l>8\\l" fullword ascii
      $s16 = "5qJdef" fullword ascii
      $s17 = "/_&D_g" fullword ascii
      $s18 = "Ys\\qoL<" fullword ascii
      $s19 = "34C<ap" fullword ascii
      $s20 = "@ Z/V<t" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "3290792225a4bb825deba733e52cbd8e" and ( 8 of them )
      ) or ( all of them )
}

rule _01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570_1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce99_4 {
   meta:
      description = "dragonforce - from files 01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570.exe, 1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b.exe, 312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83.exe, 80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9.exe, 822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef.exe, b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d.exe, b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32.exe, ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429.exe, c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c.exe, d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6.exe, d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3.exe, d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9.exe, df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570"
      hash2 = "1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b"
      hash3 = "312ca1a8e35dcf5b80b1526948bd1081fed2293b31d061635e9f048f3fe5eb83"
      hash4 = "80e3a04fa68be799b3c91737e1918f8394b250603a231a251524244e4d7f77d9"
      hash5 = "822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef"
      hash6 = "b714cb02cfd5d67e1502b45242636ee6b35c1b609072d3082378c50a177df15d"
      hash7 = "b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32"
      hash8 = "ba1be94550898eedb10eb73cb5383a2d1050e96ec4df8e0bf680d3e76a9e2429"
      hash9 = "c844d02c91d5e6dc293de80085ad2f69b5c44bc46ec9fdaa4e3efbda062c871c"
      hash10 = "d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6"
      hash11 = "d4de7d7990114c51056afeedb827d880549d5761aac6bdef0f14cb17c25103b3"
      hash12 = "d626eb0565fac677fdc13fb0555967dc31e600c74fbbd110b744f8e3a59dd3f9"
      hash13 = "df5ab9015833023a03f92a797e20196672c1d6525501a9f9a94a45b0904c7403"
   strings:
      $s1 = "USER32.dll" fullword ascii
      $s2 = "KERNEL32.dll" fullword ascii
      $s3 = "GetCommandLineA" fullword ascii
      $s4 = "GetCommandLineW" fullword ascii
      $s5 = "GetLastError" fullword ascii
      $s6 = "SetLastError" fullword ascii
      $s7 = "@.data" fullword ascii
      $s8 = ".idata$2" fullword ascii
      $s9 = ".rdata$zzzdbg" fullword ascii
      $s10 = "FreeLibrary" fullword ascii
      $s11 = ".idata$5" fullword ascii
      $s12 = ".idata$3" fullword ascii
      $s13 = ".idata$4" fullword ascii
      $s14 = ".idata$6" fullword ascii
      $s15 = ".text$mn" fullword ascii
      $s16 = "LoadLibraryW" fullword ascii
      $s17 = "!This program cannot be run in DOS mode." fullword ascii
      $s18 = "`.rdata" fullword ascii
      $s19 = ".rdata" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570_822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f_5 {
   meta:
      description = "dragonforce - from files 01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570.exe, 822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "01f1e82d4c2b04a4652348fb18bb480396db2229c4fd22d2be1ea58e6bf4a570"
      hash2 = "822ceefb12b030f2ff28dcda6776addda77b041dbb48d2e3a8c305721f4cc8ef"
   strings:
      $s1 = "4rt'KlaC#!" fullword ascii
      $s2 = "&]q:R)" fullword ascii
      $s3 = "80A,()" fullword ascii
      $s4 = "0FD5?c" fullword ascii
      $s5 = "]*?cP:" fullword ascii
      $s6 = "Cd?F*b" fullword ascii
      $s7 = "MQz4R6" fullword ascii
      $s8 = "A%EI)f" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "d428b0554d443c341b28703744573111" and ( all of them )
      ) or ( all of them )
}

rule _b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32_d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab303_6 {
   meta:
      description = "dragonforce - from files b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32.exe, d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-06-07"
      hash1 = "b9bba02d18bacc4bc8d9e4f70657d381568075590cc9d0e7590327d854224b32"
      hash2 = "d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6"
   strings:
      $s1 = "Pk0e4?)" fullword ascii
      $s2 = "H4 fZK" fullword ascii
      $s3 = "o5LV7F" fullword ascii
      $s4 = "C(|hkC" fullword ascii
      $s5 = "9:~Petb" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "d428b0554d443c341b28703744573111" and ( all of them )
      ) or ( all of them )
}

