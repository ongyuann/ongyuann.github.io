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
# 旗 1
0905 - 1100 - everything went wrong. nmap discovered http on only one of the two exposed servers, leading down a completely wrong path, e.g. tried to fit asp, hta, dntjs into an xss vulnerability. also for the first time ever ran sqlmap for this course - had to make sure this was allowed before trying. but nothing worked.  

1100 - guessed port 80 on the other exposed server, and a page actually loaded. nmap was bluffing! re-ran nmap on the other server. raged.  
1101 - immediately discovered the foothold vector on the other exposed server - word document phishing / vba execution.  
1102 - started using my makemacro.py to make malicious vba - only to discover connecting to the exam vpn completely wrecked the connection between kali and my windows vm. restarted computer twice before i came to this realization. this meant my entire workflow that i had practiced on the for past six months would be completely wrecked once i re-connected to the exam pvn. rekt.  
1104 - 1106 - on third restart, quickly ran makemacro -> compiled the accompanying runspace binary -> copied the macro into my word doc.  
1107 - 1122 - fumbled with sending email with attachment via linux for the first time ever in my life, including quick googles for how-to-dos for swaks and sendemail. didn't work. in this time also connected to devbox to test out macro, since the exam instructions had said the devbox would contain tools including office and email server/client. the macro worked.  
1123 - used mozilla thunderbird on devbox to send email with attachment  
1125 - used sendemail to send attachment  
1130 - checked out hosts file on the devbox - added entry to my own hosts file  
1131 - 1134 - used swaks to send attachment  
1135 - flying 终点ly, the macro worked on the real victim.  
1136 - basked in the glory of a meterpreter callback  
1136 - getuid, sysinfo  
1137 - first 洛克了  

# 旗 2
1139 - checked 权力壳 context - fulllanguage. awesome.  
1144 - did the usual enum - jaws, up, view, 狗  
1144 - checked kerberos tix  
1202 - 终点ly looked at the escalation vector recommended by up. took so long because i didn't want to believe / act on it at first - had never seen this in the labs.  
1208 - still chose not to act on the vector - tried looking at 血狗 results to see if i could move via domain rights. couldnt.  
1214 - 终点ly acted on the escalation vector, ran the default command recommended by up - didn't work  
1233 - used runspace to generate hollow, then adapted code into plain non-runspace hollow code  
1255 - on-the-spot learnt how to use MSI Wrapper, used it to wrap hollow.exe into hollow.msi with "always elevate" privs  
1257 - ran met listener job, uploaded hollow.msi, ran hollow.msi with msiexec  
1259 - met came back  
1259 - with nt authority\系统  
1301 - hashdump didn't work - didn't think much of this at first. proceeded to killdef  
1302 - first 布鲁夫

# 旗 3
1309 - thought about using fodhelper to bypass uac  
1309 - thought really hard about it  
1310 - gave up that avenue and setup 雕  
1312 - setup 洛克了 爱的命 '杰克'  
1317 - added '杰克' to 弱点破 users  
1318 - setup met proxy - not sure why i did that  
1337 - attempted to setup rs.txt - again not sure why i did that  
1413 - enumerated domain using 权力view using techniques learnt from the syllabas - noticed a user with GenW privs, noted that down.  
1415 - 弱点破'ed into box 1 as first user - not sure why i did that  
1427 - tried visiting 网page on internal box via box 1 - didn't look exploitable  
1429 - sprayed first user's creds with crackmapexec - looked promising but no 爱的命  
1430 - first user's creds could login 每时刻 on another internal box  
1432 - saw 连ed 每时刻 server on the box  
1437 - tried relaying 每时刻 hash on a logical target - didn't work  
1438 - 1449 - guessed the first box's 爱的命 creds could be the same on another logical target - and yes it was  
1450 - prepared runspace hollow  
1452 - prepared runspace hollow again - not sure why i had to  
1453 - ran runspace hollow via im包-贝斯艾瑟克 壳 on the logical target  
1455 - met callback as nt authority\系统 on the logical target  
1455 - hashdump worked. saw another user on the box  
1456 - saw .色色和 folder on the other user's home folder  
1456 - saw 色色和 keys in the .色色和 folder  
1458 - cracked passphrase for the private 色色和 key  
1459 - looked into public key for 色色和 target  
1501 - grabbed 布鲁夫. no 洛克了.  

# 旗 4
1507 - made other user 洛克了 爱的命 on the box  
1508 - made other user 弱点破 user on the box  
1510 - logged in as other user via 弱点破, used the 色色和 keys successfully  
1510 - tried sudo - asked for password, both the 色色和 passphrase and the other user's password didn't work  
1512 - setup makewrap on port 1433 - this didn't work  
1519 - setup makewrap on port 443  
1519 - this worked  
1520 - grabbed 洛克了

# 旗 5
1524 - checked 洛克了 user's bash 历史 - nothing. copied my 色色和 pub key into authorized_keys file  
1610 - took me long enough to realize the privesc vector was staring at me from the 洛克了 user's home directory all along - an 安斯波 金库 file not named like one  
1614 - cracked the 安斯波 金库 file password  
1623 - took me embarassing amount of time to apply cracked password to decrypt the 金库 - but i got there  
1625 - got root, grabbed 布鲁夫

# 旗 6
1633 - had entered another user's directory to find another 色色和 key, followed the trail into the next box, and was already checking the bash 历史. saw sudo password.  
1636 - setup my 色色和 pub key into authorized_keys file on the box, then grabbed 布鲁夫

# 旗 7
1638 - found 刻薄5cc 票 on the box  
1651 - took me longer than needed to download the 刻薄5cc 票, but i got there  
1652 - injected 票 into my session on kali, checked it  
1653 - 1659 - had remembered the 刻薄5cc 票's user was the one i saw earlier that had GenW privs that can lead to rabakCD attack - and the standard exploitation method from the syllabus for this was via windows (mad + view + rub)  
1700 - setup nt authority\系统 on first box to use as a jump-host  
1701 - converted 刻薄5cc into 可比
1703 - uploaded 可比  
1705 - injected 可比 using mimikatz  
1705 - checked kerberos tix as the user  
1706 - commenced rabakCD attack  
1707 - checked progress  
1711 - completed rabakCD, checked progress - worked    
1712 - entered session on new box with 贝斯艾瑟克.exe  
1713 - killdef  
1715 - ran runspace  
1715 - met called  
1720 - grabbed 布鲁夫, no 洛克了

# 旗 8
1724 - setup 弱点破 and 弱点破 with hash on the box  
1727 - add current user as 洛克了 爱的命 and 弱点破 user on the box  
1729 - 弱点破'ed into the box as the user, and saw some blackmagicfuckery going on  
1743 - still didn't know what was happening, or how to proceed  

1927 - still stuck - had checked smbmap to see a writable folder on another box, but saw there's a process that would remove files in the folder every ~5 minutes.  
1955 - attempted to makelat to attempt lat movement to that other box after having copied hollow.exe to that writable folder  
1956 - finished compiling lat - i was using devbox to compile my exploits, and this didn't help against the time limit  
2008 - apparently lat didn't work, so was checking out cifs privs by listing kerberos 票s - key lesson: see who the "client" is when klisting
  
2053 - tried cracking 每时刻 hash from another box - no luck  
  
2225 - tried looking deeper into 血狗 for any avenues - no luck  
2227 - tried looking deeper via 权力view - here i was enumerating domain groups for any possible privs 血狗 might have missed  
2227 - checked out other groups / users in the domain - here i thought i could phish them, but all the addresses didn't work as email destinations (first box's smtp didn't recognize them as email destinations)  
  
2228 - 2242 - was about to head to sleep and try again, when i had the idea to check whether $ accounts could login 每时刻  
  
2243 - logged in with the box's $ account on an 每时刻 instance on another box - not only did it work, it had 魔方ion privs!  
2244 - and if i took up the 魔方ion, i had a 连ed login!  
2245 - confirmed 连ed server!  
2253 - checked priv on 连ed server - '沙'!!!!!  
2254 - without checking if the 连ed server had a 连-back, or even if the 连-back would execute with '沙', attempted 每时刻 连-back code exec first step of enabling "show advanced options" - it worked!!!!!!  
2255 - enabled xp_命令壳 via 连-back  
2256 - 2259 - got 壳 as 每时刻 user on new box!  
2300 - compiled runspace 管道管道  
2301 - setup first stage of 别林斯布负了 by listening with 管道管道  
2302 - triggered 斯波三倍了 to complete second stage of 别林斯布负了, 管道管道 executed 权力壳 runner  
2304 - met called back, killdef  
2308 - setup 弱点破, used first box as jumphost, used mimikatz to pass 爱的命 hash and open 弱点破 restricted爱的命  
2310 - grabbed 洛克了 (no 布鲁夫 altho 爱的命)  

# 旗 9
2316 - used 电脑厨师 to 权力壳-base64-encode a 权力壳 cradle  
2318 - opened ssms and immediately executed 每时刻 连 code exec on the next box  
2318 - met called  
2320 - tried 别林斯布负了 to privesc - listening with 管道管道  
2321 - 2327 - but 别林斯布负了 failed. i wouldn't know why not, would discover later it's cos 四部了er service was disabled on the box.  
2328 - grabbed 洛克了 (no 布鲁夫, fair enough)

# 旗 秘密
2328 - noticed during grab 洛克了 on the box that it had two interfaces - and one of them is in the same subnet as the box that hosts the 秘密 (actually alr saw this from internal nmap)  
2334 - so i setup 雕

2335 - went to sleep

# day 2

0141 - woke up  
0142 - enumerated database on the box  
  
0218 - located sql命令.exe on the box, continued enumerating database  
  
0219 - 0541 - break, back, break, back, break, back..  
  
0542 - wondered if 终点 box could use nearby db to tunnel out to me, by setting up 雕 连 between nearby db and db closest to me  
0546 - setup 雕 连s between said dbs - would give up this avenue after thinking twice  
0554 - tried 字按scan - failed

0657 - was where i realized i could replace the 字按 爱的命 user's password hash with my own, so generated a 字按 hash of "P@ssw0rd"  
0659 - updated 字按 database with my 爱的命 password  
0702 - hit some snags with 权力壳 special character quirks (the dollar sign)  
0703 - fix the snag  
0704 - login as 爱的命 worked  
0708 - saw that i could edit 配合配 pages and visit them  
0708 - at Appearance -> Edit Themes  
0712 - inserted 配合配 网壳 code and got code exec  
0713 - checked 四部了er service running on the box  
0719 - but confirmed the box can't reach me  
0746 - checked out some apparently important 字按 秘密 file, but was gibberish  
0748 - kept at finding any possible 秘密s  
0821 - could upload file.txt and certutil -decode successfully via 网壳  
0823 - saw that i could reliably upload files via 网壳  

0824 - 1244 - found no routes into 终点 box, and had convinced myself that 网壳 was a dead end. heavily considered resigning to fate.    

1245 - went back to enum db more  
1316 - and enum db more  

1547 - had a brainwave - 终点 box couldn't egress out to me, but what if i could dump creds then use creds to ingress into 终点 box instead? started making mini蛋 for 勒索啥 dumping  
1554 - obviously mini蛋 wouldn't work without 爱的命 priv - only obvious choice was to choose to use 管道管道 to run mini蛋 with 系统 priv, if that would even work - but i had to give it a try  
1559 - ..and then it actually worked  
1559 - it actually worked!!!  
1559 - took another screenshot of 斯波三倍了 output just for security  
1559 - 勒索啥.对面破 with 47mb now just sitting on the box - but i couldn't download since it was created by 系统, and i was just a normal service user  
1610 - tried using 管道管道 to run icacls to change 勒索啥.对面破 permissions  
1614 - 管道管道 ran as intended - but still not enough privs  
1616 - then another brainwave - why not create 洛克了 爱的命 user, a la normal service abuse? wrote 管道管道 to do this  
1618 - 管道管道 ran as intended  
1620 - just now was creating 杰克, now was adding 杰克 to 洛克了 爱的命 group  
1621 - ran as intended - and then it didn't work  
1634 - but then i recalled 五九八五 on the box, so added 杰克 to 远程管理 users  
1639 - tested it on devbox and realized 命令 prompt absolutely _hates_ with single quotes for strings  
1643 - 管道管道 ran as intended and added 杰克 to 远程管理 users  
1643 - and then i really could login.  
1711 - used 管道管道 to killdef  
1716 - realized even when logged in as 杰克 with 洛克了 爱的命 membership, i was still low-priv. very effective uac at work - so again consulted stackoverflow and tried icacls to grant privs on 勒索啥.对面破  
1735 - was when i 终点ly had the biggest brainwave - write a 权力壳 script as 洛克了 爱的命, then simply make 管道管道 keep running that script with 系统 privs  
1737 - worked  
1755 - made myself 弱点破 into the 终点 box - surreal  
1755 - captured screenshot of my script just for security   
1757 - saw 秘密, but didn't open it since i was on 弱点破, and that wouldn't count  
1804 - im包-贝斯艾瑟克 in with 爱的命 hash, grabbed 秘密
