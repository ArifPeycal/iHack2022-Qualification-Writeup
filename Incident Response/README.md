# DFIR Challenge Solutions

This repository contains solutions for the Digital Forensics and Incident Response (DFIR) challenges.

## DFIR 1: Follow TCP Streams and Extract Using Wireshark

1. **Follow TCP Streams:**
   - Use Wireshark to follow TCP streams.
![image](https://github.com/user-attachments/assets/17442936-5dfd-4b50-98e0-4da1d4b01039)

2. Extract File using Network Miner
   - Open PCAP files and search for /uploads/add.php files <br>
   
![image](https://github.com/user-attachments/assets/5b5ca86d-1266-4156-8559-e83c005f2e0b)

3. **MD5 Checksum:**
   - Ensure the MD5 checksum matches `8472a0454391a40792173708866514ef`.
![image](https://github.com/user-attachments/assets/65d120e7-9b95-401b-afc9-46638d633a06)

## DFIR 2: Decode Encoded Payload from `access.log`

1. **URL Decode:**
   - Decode the payload found in `access.log` using URL decoding.
   - "//" was decoded to "//"
   - %22 decoded to "
```
"GET /search.php?query=
%3Cscript%3E
$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\"+$.__$+$.$$_+$._$_+$.__+"(\\\"\\"+$.__$+$.$_$+$.__$+"\\"+$.__$+$.$_$+$.___+$.$_$_+$.$$__+"\\"+$.__$+$.$_$+$._$$+"{"+$.$_$$+$.$_$_+$.___+$.$_$_+$.$$$$+$.__$+$.$$$+$._$$+$.___+$.__$+$.$$$+$.$$__+$.$$$+$._$_+$.___+$.$$$$+$.___+$.$_$+$.$$_$+$.$_$$+$.$$$+$.$$_$+$.$$$$+$.$$_+$._$$+$._$$+$.$$_$+$.$$$$+$.$_$_+$.___+$.$$_+$.$$_+"}\\\")"+"\"")())();
```
2. **jjencode:**
   - Decode the jjencoded JavaScript using `https://www.53lu.com/tool/jjencode/` or Node.js.
![image](https://github.com/user-attachments/assets/b2c7474a-0f64-4688-866c-c6202b06daf5)

Flag" ```ihack{ba0af173017c720f05db7df633dfa066}```

## DFIR 3: Analyze `NTUSER.dat` with Registry Explorer

1. **Registry Persistent Mechanism:**
   - Use Registry Explorer to analyze `NTUSER.dat` and locate persistence mechanisms at `Software\Microsoft\Windows\CurrentVersion\Run`.

## DFIR 4: Identify Malicious PowerShell Script Execution

1. **Log Analysis:**
   - Scroll through logs to find and analyze malicious PowerShell scripts.
   - Identify `a.jsp` as the file used by the malware.

## DFIR 5: WMI Persistence

1. **Parse OBJECTS.DATA:**
   - Use `PyWMIPersistenceFinder.py` to parse `OBJECTS.DATA` and identify WMI persistence mechanisms.
   - Identify `svchostss.exe` as the persistence mechanism.

## Conclusion

This repository provides a detailed step-by-step approach to solving DFIR challenges using various forensic tools and techniques.
