---
layout: post
title: and another post-mortem
tags: pt
---

# pre
0945 - everything worked well  
1000 - received package, did the necessary  
1005 - started  

# day one
## 1
1005 - read the challenge instructions  
1013 - started getting to work with challenge 1  
1016 - adapted my poc skeleton  
1017 - transferred rop gadgets to my kali  
1020 - started playing with buffer sizes  
1023 - found offset  
1025 - started expanding poc  
1025 - confirmed offset is true  
1029 - started finding badchars  
1034 - finding badchars  
1037 - finding badchars - some really weird ones  
1038 - finding badchars - OS really likes playing games  
1039 - finding badchars  
1041 - finding badchars  
1041 - still finding  
1043 - still finding  
1044 - finally finished finding all badchars  
1047 - setup skeletons in poc  
1048 - re-arranged skeletons slightly  
1050 - started reading situation for rop chain  
1051 - reading situation  
1104 - did a quick check on my custom shellcode generator to see how badly infested with badchars it would be - turned out not that bad  
1116 - starting finding spaces in binary for required api  
1120 - parsed pe header  
1121 - parsed pe code region  
1126 - checked memory protections  
1129 - checked data section  
1130 - checked writable section  
1131 - checked protections  
1132 - onto building rop chain  
1139 - using windbp as calculator to get around null-byte limitations  
1157 - testing rop chain  
1211 - testing rop chain  
1220 - testing  
1228 - testing (and building)  
  
1239 - is where i made my first stupid mistake - cost me 1 hour of pain because there was no way my logic was wrong  
  
1243 - found where i made stupid mistake  
1256 - crisis averted, continued rop chain  
1303 - testing rop chain  
1337 - testing  
1340 - rop chain lookin good  
1344 - rop chain good, but found new limitation  
1346 - confirmed new limitation which could be fixed with simple re-arrangment of buffer structure  
  
1415 - started dealing with badchars in shellcode  
1425 - sniping them badchars away  
1426 - on a roll  
1427 - that's right  
1428 - easy  
1429 - gettin' there  
1430 - awesome  
1431 - can't get past me  
1436 - shellcode perfected  
  
1439 - tested full exploit  
1444 - didn't work.. why?  
1455 - api working well. why exploit not working..?  
  
1540 - found why  
1541 - a concerning problem with no logic that i could not understand  
1542 - debugging  
1546 - somehow shellcode was getting truncated at a specific length every time  
1550 - and after truncation, would display the same characters that are not my shellcode, every time  
1554 - was it cos i found the wrong cave? started looking again  
1611 - still couldn't believe what was happening  
1619 - verified the phenomenon was happening consistently at the same length  
1631 - why??  
1633 - started finding alternatives - maybe need 2 buffers?  
1636 - egghunter?  
  
1655 - felt hopeless, went to read instructions for ch2. instant discouragement.  
1657 - read instructions for ch3. a little more hopeful since the ugliness wasn't obvious yet (reversing task)  
  
1659 - got back to my rop on ch1  
1701 - getting obsessed with that same length  
1742 - same length shows up even if shellcode is all the same characters - so the problem wasn't my shellcode  
1744 - and just like that, found the problem and fixed it. exploit now worked on debug box.. but not on real one.  
  
## 3
1822 - since ch2 was hopeless, and ch1 exploit was 100% working just couldn't work on real box, started looking at ch3  
1822 - identified listening port  
1824 - did customary nmod  
1851 - caught the recv, started tracing  
1856 - tracing  
1859 - saw first header obstacle - easily handled  
1901 - continued tracing  
1934 - adjusted poc to include header  
1936 - confirmed header obstacle well handled - moving on  
1937 - tracing  
1941 - found offset  
1949 - tracing  
1957 - tracing + putting comments in IDA along the way  
1958 - identified where i wanted buffer to land  
2003 - adjusted poc  
2004 - tracing  
2018 - tracing  
2026 - identified another spot where i want buffer to land  
2026 - double-checked if buffer was still around  
2049 - found new header, adjusted poc for new header  
2100 - continued tracing  
2102 - tracing  
2222 - tracing  
  
2223 - was when i figured i was well and truly fugged. near-zero chance of passing. decided i had to give myself substantial sleep and continue the next day - strategy was now to focus on ch2 instead, then fix ch1 later.  
  
# day two
## 2
0218 - plan failed, woke up in 4 hours instead.  
0218 - ok, first step for ch2 was not impossible. did it.  
0224 - going well  
0225 - that's right  
0227 - uh-huh  
0244 - oh no  
0305 - oh right  
0311 - easy solve  
0336 - hmm..  
  
0337 - ok, brain died. still haven't rested enough - but have some platform to continue with ch2. went to sleep.  
  
0728 - back to work  
0851 - nice, some success  
0929 - i'm such a smartass  
0930 - woot woot  
0942 - let's go  
0946 - that's right  
0946 - ok working. back to it  
1011 - uh-huh.. hmm. google.  
  
1127 - googled idea working well  
1130 - mm-mm  
1226 - booya  
1239 - prep for next step  
1246 - just do it the recommended way instead  
1249 - wowza!!  
  
1342 - ch2 completed!!! (i have a chance of passing!!!!!)  
1357 - just did it again - it's really working!!!!  
  
# 1
1409 - back to ch1 - now i just had to get this to work on real box  
1430 - had an idea...(hint: size)...  
1431 - it fugging worked!!!!  
1432 - hostname! whoami!  
1433 - proof! ipconfig!  
1433 - submit hash!!!!  
  
# 3
1450 - deleted everything since there's no chance i'd complete this anyway now  
  
# 2
1457 - started collecting screenshots for report  
1458 - collecting  
1459 - feels good  
  
1500 - took a break, told my loved ones i was gonna pass, took a nap, knowing that i just had to write a good report now to bring home the money  
  
2029 - posing for photos  
2042 - still posing  
  
2100 - went to sleep happy, with one eye on waking up early to submit my report  
  
# day three
0549 - woke up. started doing the little things to kill my doubts  
0554 - going well so far  
  
0640 - was when i realized my code would be completely rekt if someone just had to run it in a very common circumstance.  
0743 - fukin squeaky bum time  
0810 - butt squeaking  
0811 - ma's spaghetti  
0812 - feet sweatin  
0846 - fug yea my fix worked  
0907 - yes...  
  
0945 - was gonna continue testing everything to bring home the glory when connection got cut. i'd reached exam end time without knowing.  
  
0950 - submitted report  
