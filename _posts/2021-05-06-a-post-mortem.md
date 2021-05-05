---
layout: post
title: a post-mortem
tags: pt
---

# pre
0845 - found out my hash didn't work    
0849 - sent an email asking for new hash    
0850 - no reply    
0854 - sent another email asking for new hash    
0900 - tried to login again - hash worked    
0906 - emailed sorry for the multiple sends (and possibly my tone)    
0907 - went through the rites    
0920 - all-ok, set to receive package - didn't see it arrive immediately    
0923 - waited so long i got asked if i'd received it - still hadn't    
0926 - package arrived. did the last few things    
0930 - got the all-clear to start    

# day one
## 1
0943 - setup sql logging, noticed collation    
0945 - setup fake account, noticed sql query with admin value set to "1" - does that make my new account admin?    
0946 - discovered database settings file, noticed array holding blacklisted file extensions    
0947 - discovered database credentials    
0949 - read user table    
0952 - located password reset    
0954 - located code for password reset    
0956 - located code for generating password reset link    
0956 - analyzed the password reset function generator    
1008 - looked at user registration    
1009 - looked at user blockage    
1010 - queried the sql backend to see how the reset token looked like    
1029 - tried attacking other vectors, checked sql logs to see how those other vectors worked (tried to notice sql injection)    
1032 - still trying other vectors    
1034 - noticed potential rce vector - but probably required admin rights, and i didn't have that yet    
1036 - still trying other vectors   
1054 - inserted console debug function into source code, got console debugging online    
1055 - figured out how the password reset link looked like    
1058 - confirmed the password reset actually works    
1115 - went full analysis mode on password reset    
1150 - wrote first poc attacking password reset    
1152 - located potential blocker against attacking password reset    
1155 - adjusted poc to test the blocker    
1213 - poc worked    
1249 - expanded poc for whole exploit chain    
    
1308 - logged in as admin, went straight for the potential rce identified earlier    
1312 - grepped error code blocking potential rce    
1313 - located code blocking potential rce    
1314 - located more code blocking potential rce - decided not to read too much into code, went straight to attempt exploiting    
1315 - tested potential rce on burpsuite    
1322 - was blocked but quickly identified bypass - but rce still didn't arrive    
1324 - located blocker that was blocking rce (literally)    
1324 - copy/pasted solution off the internet, immediately worked - rce achieved    
    
1325 - 1515 - tried exploiting on real target for nearly 2 hours, didn't work. but was confident of exploitation path, so decided to move to the next one. also had lunch (20min)

## 2

1516 - located app source, got it decompiled    
1521 - located code for token generation    
1524 - located code for sql sanitization    
1525 - located code for encryption/decryption    
1528 - exported code and opened in visual studio, located app properties    
1530 - used visual studio to search for sql queries: `^.*?sql.*?select`    
1538 - logged in to database    
1538 - listed tables    
1543 - played around with a feature    
1547 - located code for said feature - no juice    
1610 - looked back at results of search for sql queries    
1639 - played around with another feature    
1653 - exhausted options, decided to analyze and replicate encryption/decryption function    
1659 - played around with link generation endpoint    
1727 - snooped around in the code    
1732 - still snooping around in code looking for other possibilities    
1733 - found keyword in code for said possibilities - noticed function where keyword belonged to    
1734 - located said function, triggered on burpsuite - noticed new response    
1758 - located code for new response - identified potential auth bypass    
1808 - continued reading into code for new response    
1823 - code for new response used a funny variable - tried manually looking for funny variable on debug box    
    
2018 - still tried looking for other possibilities. also had dinner (20min)    
    
2105 - still tried looking for other possibilities - no cigar    
    
2130 - options truly exhausted, started digging into said new response    
2130 - got live debugging set up, found the funny variable    
2143 - logged in as admin on the debug box    
2147 - same exploit failed on the real box    

# day two

2148 - 0358 - was satisfied that i probably had the right exploits to get enough points to pass - only problem was they didn't work on the real boxes. left poc for box 1 to continue running, then headed to sleep to clear head for box 2.    

## 2
0359 - located code saying something more about the funny variable    
0359 - excited    
0402 - confirmed excitement    
0403 - super excited    
    
0416 - started looking for ways to find that something more from the web front-end    
0423 - saw blockers in the code    
0433 - confirmed blockers from firefox    
0440 - identified potential way    
0440 - excited    
0446 - calmly checked excitement is real    
0446 - excitement is real    
0515 - admin on real box    
    
0535 - collected screenies    
0537 - grapped proof    
    
0538 - 0758 - grabbed breakfast, a little break, knowing i now just needed poc for box 1 to work on the real box.    

## 1
0759 - poc had run for almost 6 hours with no cigar    
0828 - looked more closely at blocker    
0830 - logged in to database to look more closely at blocker    
0830 - adjusted poc to work around blocker    
0853 - poc worked on debug box!    
0913 - poc worked on debug box again!    
0927 - and again!    
0928 - and again!    
    
0954 - poc finally worked on real box!    
0955 - grabbed proofs    
0956 - grapped screenies    
    
1004 - 1538 - wrote report, with one eye on getting that remaining rce.    

## 2
1954 - started working on rce - still had more than 12 hours    
2009 - saw potential rce    
2018 - located code for potential rce    
2020 - verified potential rce in code    
2021 - verified again    
2024 - and again    
2027 - rce poc worked    
    
2036 - started scripting exploit for rce    
2038 - downloaded necessary libraries for exploit    
2046 - finished installing libraries    
2048 - tested installed libraries    
2050 - downloaded exploit for exploit    
2051 - compiled exploit    
2055 - tested platform for rce    
2125 - continued testing    
2128 - testing    
2130 - testing    
2130 - testing    
2131 - first stage for platform tested    
2131 - verified first stage    
2134 - wrote script for first stage - verified working    
2142 - expanded script to full exploit    
2143 - exploit failed    
2211 - found out why exploit failed    
2214 - fixed the error (or mistake)    
2214 - tested second stage for platform - verified working    
2217 - tested third stage for platform - verified working    
2219 - discovered fourth stage doesn't exist on debug box (and likely on real box too)    
2220 - verified third stage working    
2222 - tested workaround for fourth stage    
2223 - continued testing workaround    
2223 - verified workaround works - now to get it scripted    
2235 - full exploit working    
2236 - pointed exploit at real box, worked!    
2238 - captured proofs    
2239 - submitted all proofs    
    
2312 - captured some screenies    
2359 - captured some screenies    
    
0000 - 0616 (the next day) - rewarded myself with 2 hours extra sleep, then on to capture all evidences for a strong report    

# day three (within 48 hours of start)

0617 - 0802 - captured remaining screenshots, reviewed report, zipped report, md5summed report    
0805 - submitted report    
0812 - actually submitted the report    
0815 - stopped the connection    
