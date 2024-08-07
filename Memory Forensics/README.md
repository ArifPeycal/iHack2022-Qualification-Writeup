# IHACK 2022 Memory Forensics Writeup

This repository provides a detailed walkthrough for a memory forensics challenge, where we identify various artifacts from a memory dump using Volatility and other tools.

## Challenge Overview
### I. MD5 Hash of Memory Image
Task: Provide the MD5 hash of the memory image.

Command: <br>

Linux
```
md5sum artefact.vmem
```
Windows CMD
```
certutil -hashfile artefact.vmem MD5
```

Optional: <br>

https://emn178.github.io/online-tools/md5_checksum.html

Answer: 2aff5e0bd33f622790c3db33f0798978 <br>

Flag: ```ihack{2aff5e0bd33f622790c3db33f0798978}```

### II. Suspicious Process Name
Task: Identify the suspicious process name used by the attacker.

Command: 
```
volatility -f artefact.vmem --profile=Win7SP1x86 pslist
```

![image](https://github.com/user-attachments/assets/1caf9501-1cf4-466d-815d-cb1b145f19b0)

Answer: putty.exe <br>
- PuTTY is commonly used by attackers to establish remote access to a compromised machine. This makes it a known tool that might be flagged in forensic investigations.

Flag: ```ihack{putty.exe}```

### III. Process ID (PID) of Suspicious Process
Task: Identify the process ID (PID) of the suspicious process.

Command: 
```
volatility -f artefact.vmem --profile=Win7SP1x86 pslist
```
Answer: 1732 <br>

Flag: ```ihack{1732}```

### IV. IP Address Connected to C2's Attacker
Task: Identify the IP address that connected to the C2's attacker.

Command: 
```
volatility -f artefact.vmem --profile=Win7SP1x86 netscan
```
![image](https://github.com/user-attachments/assets/9fe04c00-100e-4867-8312-e8e0c58e5c2c)

Answer: 139.59.122.20 <br>

Flag: ```ihack{139.59.122.20}```

### V. Created User by Attacker
Task: Identify the user created on the compromised host.

Command:
Use evtxtract to dump event logs and identify events related to user creation. (Open with VS Code)
```
evtxtract artefact.vmem > output.xml
```
- Event ID 4720 is a specific event logged in the Windows Security Event Log whenever a new user account is created on a Windows system. This event provides detailed information about the creation of the user account, which is essential for security monitoring and auditing. <br>

![image](https://github.com/user-attachments/assets/2b91c835-bcc7-494a-ad77-518fe3cec86f)

Alternatively, use volatility to dump memory for the suspicious process and search for user creation evidence:

```
volatility -f artefact.vmem --profile=Win7SP1x86 memdump -p 1732 -D /dump | strings dump/1732.dmp
```
Answer: sysadmin <br>

Flag: ```ihack{sysadmin}```

### VI. IP Address of RDP Connection
Task: Identify the IP address that connected to the PC through RDP.

Command: 
Use evtxtract to analyze event logs and identify RDP connection events.
```
evtxtract artefact.vmem > output.xml
```

Microsoft-Windows-TerminalServices-LocalSessionManager/Operational Log
- Event ID 21 - Remote Desktop Services: Session logon succeeded

![image](https://github.com/user-attachments/assets/56b5e499-d858-4009-a6b0-9344c5dbc24b)

Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational Log
- Event ID 1149 - Remote Desktop Services: User authentication succeeded

![image](https://github.com/user-attachments/assets/2521374b-6fa6-4e13-b9f4-2a17cd5729a8)

Answer: 192.168.74.171 

<br>

Flag: ```ihack{192.168.74.171}```

### VII. Timestamp of User Creation
Task: Provide the timestamp when the attacker created the new user on the victim's PC.

Command: Use evtxtract to analyze event logs and identify the timestamp of user creation (event ID 4720).
![image](https://github.com/user-attachments/assets/cc107f1f-330e-4f6e-9f39-04c26c959793)

Answer: 2022-12-09 13:34:07 (UTC)<br><br>

Flag: ```ihack{2022-12-09 13:34:07}``` & ```ihack{2022-12-09 21:34:07}```

## Tools and References

1. Volatility Framework: A memory forensics framework for incident response and malware analysis. <br>
 <a href = "https://volatilityfoundation.org/">Volatility</a> <br>
 
2. EVTXtract: A tool to extract event logs from memory images. <br>
<a href = "https://github.com/williballenthin/EVTXtract">EVTXtract</a>

3.  FRSecure Blog on RDP Connection Event Logs:
<a href =  "https://frsecure.com/blog/rdp-connection-event-logs/">RDP Connection Event Logs</a>

