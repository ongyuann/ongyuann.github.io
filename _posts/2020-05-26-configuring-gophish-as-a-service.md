---
layout: post
title: "Configuring GoPhish as a service"
tags: gophish phishing
---

When setting up GoPhish as a service, there's a fantastic guide referenced in the installation documentation:
`https://github.com/gophish/gophish/issues/586`

Pasting the code here for future and easy reference (remember to change the appdirectory):
```
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/goapps/src/github.com/gophish/gophish/config.json

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/goapps/src/github.com/gophish/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
    echo 'Starting '${processName}'...'
    cd ${appDirectory}
    nohup ./$process >>$logfile 2>>$errfile &
    sleep 1
}

stop() {
    echo 'Stopping '${processName}'...'
    pid=$(/usr/sbin/pidof ${process})
    kill ${pid}
    sleep 1 
}

status() {
    pid=$(/usr/sbin/pidof ${process})
    if [[ "$pid" != "" ]]; then
        echo ${processName}' is running...'
    else
        echo ${processName}' is not running...'
    fi
}

case $1 in
    start|stop|status) "$1" ;;
esac
```

however there's a small snag - to complete this setup, the author mentions the following:
```
Change directory to '/etc/init.d/' and make the file executable - 'chmod +x gophish'.
Use 'chkconfig --add gophish' and 'chkconfig --levels [0123456] gophish on' to set and configure the init.d process - set the runlevels according to your system.
I used 2345 for startup and shutdown scripts.
You'll also need to create the '/var/log/gophish' directory accordingly for the log & error files, they'll be created auto-magically for ya when gophish is started.
```

the small snag - but...but `chkconfig` is deprecated in favor of `update-rc.d`.

quick solution can be found at: `https://www.debuntu.org/how-to-managing-services-with-update-rc-d/`

pasting solution here for posterity and quick and easy reference:
```
#adding gophish
sudo update-rc.d gophish defaults

#starting with priority 20 on runlevels 2, 3, 4 and 5 and Kill with priority 80 on runlevels 0, 1 and 6:
sudo update-rc.d gophish start 20 2 3 4 5 . stop 80 0 1 6 .
```

there we go. everything captured.