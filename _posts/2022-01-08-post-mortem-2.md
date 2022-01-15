---
layout: post
title: another post-mortem
tags: pt
---

# pre
0845 - everything worked well  
0900 - received package, did the necessary  
0905 - started  

# day one
# flag 1
0905 - 1100 - everything went wrong. nmap discovered http on only one of the two exposed servers, leading down a completely wrong path, e.g. tried to fit asp, hta, dntjs into an xss vulnerability. also for the first time ever ran sqlmap for this course - had to make sure this was allowed before trying. but nothing worked.  

1100 - guessed port 80 on the other exposed server, and a webpage actually loaded. nmap was bluffing! re-ran nmap on the other server. raged.  
1101 - immediately discovered the foothold vector on the other exposed server - word document phishing / vba execution.  
1102 - started using my makemacro.py to make malicious vba - only to discover connecting to the exam vpn completely wrecked the connection between kali and my windows vm. restarted computer twice before i came to this realization. this meant my entire workflow that i had practiced on the for past six months would be completely wrecked once i re-connected to the exam pvn. rekt.  
1104 - 1106 - on third restart, quickly ran makemacro -> compiled the accompanying runspace binary -> copied the macro into my word doc.  
1107 - 1122 - fumbled with sending email with attachment via linux for the first time ever in my life, including quick googles for how-to-dos for swaks and sendemail. didn't work. in this time also connected to devbox to test out macro, since the exam instructions had said the devbox would contain tools including office and email server/client. the macro worked.  
1123 - used mozilla thunderbird on devbox to send email with attachment  
1125 - used sendemail to send attachment  
1130 - checked out hosts file on the devbox - added entry to my own hosts file  
1131 - 1134 - used swaks to send attachment  
1135 - flying finally, the macro worked on the real victim.  
1136 - basked in the glory of a meterpreter callback  
1136 - getuid, sysinfo  
1137 - first local  

# flag 2
1139 - checked powershell context - fulllanguage. awesome.  
1144 - did the usual enum - jaws, up, view, hound  
1144 - checked kerberos tix  
1202 - finally looked at the escalation vector recommended by up. took so long because i didn't want to believe / act on it at first - had never seen this in the labs.  
1208 - still chose not to act on the vector - tried looking at bloodhound results to see if i could move via domain rights. couldnt.  
1214 - finally acted on the escalation vector, ran the default command recommended by up - didn't work  
1233 - used runspace to generate hollow, then adapted code into plain non-runspace hollow code  
1255 - on-the-spot learnt how to use MSI Wrapper, used it to wrap hollow.exe into hollow.msi with "always elevate" privs  
1257 - ran met listener job, uploaded hollow.msi, ran hollow.msi with msiexec  
1259 - met came back  
1259 - with nt authority\system  
1301 - hashdump didn't work - didn't think much of this at first. proceeded to killdef  
1302 - first proof

# flag 3
1309 - thought about using fodhelper to bypass uac  
1309 - thought really hard about it  
1310 - gave up that avenue and setup chisel  
1312 - setup local admin 'jack'  
1317 - added 'jack' to RDP users  
1318 - setup met proxy - not sure why i did that  
1337 - attempted to setup rs.txt - again not sure why i did that  
1413 - enumerated domain using powerview using techniques learnt from the syllabas - noticed a user with GenericWrite privs, noted that down.  
1415 - RDP'ed into box 1 as first user - not sure why i did that  
1427 - tried visiting webpage on internal box via box 1 - didn't look exploitable  
1429 - sprayed first user's creds with crackmapexec - looked promising but no admin  
1430 - first user's creds could login mssql on another internal box  
1432 - saw linked mssql server on the box  
1437 - tried relaying mssql hash on a logical target - didn't work  
1438 - 1449 - guessed the first box's admin creds could be the same on another logical target - and yes it was  
1450 - prepared runspace hollow  
1452 - prepared runspace hollow again - not sure why i had to  
1453 - ran runspace hollow via impacket-psexec shell on the logical target  
1455 - met callback as nt authority\system on the logical target  
1455 - hashdump worked. saw another user on the box  
1456 - saw .ssh folder on the other user's home folder  
1456 - saw ssh keys in the .ssh folder  
1458 - cracked passphrase for the private ssh key  
1459 - looked into public key for ssh target  
1501 - grabbed proof. no local.  

# flag 4
1507 - made other user local admin on the box  
1508 - made other user RDP user on the box  
1510 - logged in as other user via RDP, used the ssh keys successfully  
1510 - tried sudo - asked for password, both the ssh passphrase and the other user's password didn't work  
1512 - setup makewrap on port 1433 - this didn't work  
1519 - setup makewrap on port 443  
1519 - this worked  
1520 - grabbed local

# flag 5
1524 - checked local user's bash history - nothing. copied my ssh pub key into authorized_keys file  
1610 - took me long enough to realize the privesc vector was staring at me from the local user's home directory all along - an ansible vault file not named like oen  
1614 - cracked the ansible vault file password  
1623 - took me embarassing amount of time to apply cracked password to decrypt the vault - but i got there  
1625 - got root, grabbed proof

# flag 6
1633 - had entered another user's directory to find another ssh key, followed the trail into the next box, and was already checking the bash history. saw sudo password.  
1636 - setup my ssh pub key into authorized_keys file on the box, then grabbed proof

# flag 7
1638 - found krb5cc ticket on the box  
1651 - took me longer than needed to download the krb5cc ticket, but i got there  
1652 - injected ticket into my session on kali, checked it  
1653 - 1659 - had remembered the krb5cc ticket's user was the one i saw earlier that had GenericWrite privs that can lead to RBCD attack - and the standard exploitation method from the syllabus for this was via windows (mad + view + rub)  
1700 - setup nt authority\system on first box to use as a jump-host  
1701 - converted krb5cc into kirbi using ticket_converter.py  
1703 - uploaded kirbi  
1705 - injected kirbi using mimikatz  
1705 - checked kerberos tix as the user  
1706 - commenced RBCD attack  
1707 - checked progress  
1711 - completed RBCD, checked progress - worked    
1712 - entered session on new box with psexec.exe  
1713 - killdef  
1715 - ran runspace  
1715 - met called  
1720 - grabbed proof, no local

# flag 8
1724 - setup RDP and RDP with hash on the box  
1727 - add current user as local admin and RDP user on the box  
1729 - RDP'ed into the box as the user, and saw some blackmagicfuckery going on  
1743 - still didn't know what was happening, or how to proceed  

1927 - still stuck - had checked smbmap to see a writable folder on another box, but saw there's a process that would remove files in the folder every ~5 minutes.  
1955 - attempted to makelat to attempt lat movement to that other box after having copied hollow.exe to that writable folder  
1956 - finished compiling lat - note that i was using devbox to compile my exploits, and this didn't help against the time limit  
2008 - apparently lat didn't work, so was checking out cifs privs by listing kerberos tickets - key lession: see who the "client" is when klisting
  
2053 - tried cracking mssql hash from another box - no luck  
  
2225 - tried looking deeper into bloodhound for any avenues - no luck  
2227 - tried looking deeper via powerview - here i was enumerating domain groups for any possible privs bloodhound might have missed  
2227 - checked out other groups / users in the domain - here i thought i could phish them, but all the addresses didn't work as email destinations (first box's smtp didn't recognize them as email destinations)  
  
2228 - 2242 - was about to head to sleep and try again, when i had the idea to check whether machine accounts could login mssql  
  
2243 - logged in with the box's machine account on an mssql instance on another box - not only did it work, it had impersonation privs!  
2244 - and if i took up the impersonation, i had a linked login!  
2245 - confirmed linked server!  
2253 - checked priv on linked server - 'sa'!!!!!  
2254 - without checking if the linked server had a link-back, or even if the link-back would execute with 'sa', attempted mssql link-back code exec first step of enabling "show advanced options" - it worked!!!!!!  
2255 - enabled xp_cmdshell via link-back  
2256 - 2259 - got shell as mssql user on new box!  
2300 - compiled runspace pipepipe  
2301 - setup first stage of printspoofer by listening with pipepipe  
2302 - triggered spoolsample to complete second stage of printspoofer, pipepipe executed powershell runner  
2304 - met called back, killdef  
2308 - setup RDP, used first box as jumphost, used mimikatz to pass admin hash and open RDP restrictedadmin  
2310 - grabbed local (no proof altho admin)  

# flag 9
2316 - used cyberchef powershell-base64-encode a powershell cradle  
2318 - opened ssms and immediately executed mssql link code exec on the next box  
2318 - met called  
2320 - tried printspoofer to privesc - listening with pipepipe  
2321 - 2327 - but printspoofer failed. i wouldn't know why not, would discover later it's cos spooler service was disabled on the box.  
2328 - grabbed local (no proof, fair enough)

# flag secret
2328 - noticed during grab local on the box that it had two interfaces - and one of them is in the same subnet as the box that hosts the secret (actually alr saw this from internal nmap)  
2334 - so i setup chisel

2335 - went to sleep

# day 2

0141 - woke up  
0142 - enumerated database on the box  
  
0218 - located sqlcmd.exe on the box, continued enumerating database  
  
0219 - 0541 - break, back, break, back, break, back..  
  
0542 - wondered if final box could use nearby db to tunnel out to me, by setting up chisel link between nearby db and db closest to me  
0546 - setup chisel links between said dbs - would give up this avenue after thinking twice  
0554 - tried wpscan - failed

0657 - was where i realized i could replace the wp admin user's password hash with my own, so generated a wp hash of "P@ssw0rd"  
0659 - updated wordpress database with my admin password  
0702 - hit some snags with powershell special character quirks (the dollar sign)  
0703 - fix the snag  
0704 - login as admin worked  
0708 - saw that i could edit php pages and visit them  
0708 - at Appearance -> Edit Themes  
0712 - inserted php webshell code and got code exec  
0713 - checked spooler service running on the box  
0719 - but confirmed the box can't reach me  
0746 - checked out some apparently important wp secret file, but was gibberish  
0748 - kept at finding any possible secrets  
0821 - could upload file.txt and certutil -decode successfully via webshell  
0823 - saw that i could reliably upload files via webshell  

0824 - 1244 - found no routes into final box, and had convinced myself that webshell was a dead end. heavily considered resigning to fate.    

1245 - went back to enum db more  
1316 - and enum db more  

1547 - had a brainwave - final box couldn't egress out to me, but what if i could dump creds then use creds to ingress into final box instead? started making minidump for lsass dumping  
1554 - obviously minidump wouldn't work without admin priv - only obvious choice was to choose to use pipepipe to run minidump with system priv, if that would even work - but i had to give it a try  
1559 - ..and then it actually worked  
1559 - it actually worked!!!  
1559 - took another screenshot of spoolsample output just for security  
1559 - lsass.dmp with 47mb now just sitting on the box - but i couldn't download since it was created by system, and i was just a normal service user  
1610 - tried using pipepipe to run icacls to change lsass.dmp permissions  
1614 - pipepipe ran as intended - but still not enough privs  
1616 - then another brainwave - why not create local admin user, a la normal service abuse? wrote pipepipe to do this  
1618 - pipepipe ran as intended  
1620 - just now was creating jack, now was adding jack to local admin group  
1621 - ran as intended - and then it didn't work  
1634 - but then i recalled 5985 on the box, so added jack to remote management users  
1639 - tested it on devbox and realized cmd prompt absolutely _hates_ with single quotes for strings  
1643 - pipepipe ran as intended and added jack to remote management users  
1643 - and then i really could login.  
1711 - used pipepie to killdef  
1716 - realized even when logged in as jack with local admin membership, i was still low-priv. very effective uac at work - so again consulted stackoverflow and tried icacls to grant privs on lsass.dmp  
1735 - was when i finally had the biggest brainwave - write a powershell script as local admin, then simply make pipepipe keep running that script with system privs  
1737 - worked  
1755 - made myself RDP into the final box - surreal  
1755 - captured screenshot of my script just for security   
1757 - saw secret, but didn't open it since i was on RDP, and that wouldn't count  
1804 - impacket-psexec in with admin hash, grabbed secret




