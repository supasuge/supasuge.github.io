---
author: Supaaasuge
title: Antique - HTB Writeup
date: 2024-05-06
Lastmod: 2024-05-06
description: "Writeup for the Hack The Box room: Antique"
categories:
  - Hack The Box
tags:
  - Linux
---

# Enumeration
Starting off, I ran a nmap TCP scan on all ports. The only open port from this was `23`(Telnet), so I then decided to try a UDP scan (`-sU`), in which port `161`(SNMP) was found.

From here, I went ahead and connected to port 23 using `telnet`. HP JetDirect was the live service for this port, I am going to go ahead and search google for any exploits for HP JetDirect

*To be continued...*
