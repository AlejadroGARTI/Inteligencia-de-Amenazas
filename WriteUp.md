# Auditoría de Seguridad

## Reconocimiento

```bash
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
1880/tcp open  vsat-control
3030/tcp open  arepa-cas
4040/tcp open  yo-main
```

```bash
Host is up (0.032s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
|   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
|_  256 60:da:3e:31:38:fa:b5:49:ab:48:c3:43:2c:9f:d1:32 (ED25519)
1880/tcp open  http    Node.js Express framework
|_http-cors: GET POST PUT DELETE
|_http-title: Node-RED
3030/tcp open  http    Node.js (Express middleware)
|_http-title: SIEM Taskboard
4040/tcp open  http    Node.js (Express middleware)
|_http-title: Net Defender \xE2\x80\x94 Sim
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---


RegreSSHion (CVE-2024-6387): Note that while this is a major OpenSSH vulnerability, Debian 11 Bullseye was officially confirmed not affected as this specific regression was introduced in OpenSSH 8.5p1
```bash
┌──(kali㉿kali)-[~/CVE-2024-6387]
└─$ python3 CVE-2024-6387.py scan -T 10.130.152.121 -p 22
                                                     
   .aMMMb  dMMMMb  dMMMMMP dMMMMb  .dMMMb  .dMMMb  dMP dMP                                             
  dMP"dMP dMP.dMP dMP     dMP dMP dMP" VP dMP" VP dMP dMP                                              
 dMP dMP dMMMMP" dMMMP   dMP dMP  VMMMb   VMMMb  dMMMMMP                                               
dMP.aMP dMP     dMP     dMP dMP dP .dMP dP .dMP dMP dMP                                                
VMMMP" dMP     dMMMMMP dMP dMP  VMMMP"  VMMMP" dMP dMP                                                 
                                                                                                       
   ReggreSSHion CVE-2024-6387 Vulnerability Checker / Exploiter                                        
   2.0 - Optimized by @Kz                                                                              

🚨Servers likely vulnerable: 0
🛡️ Servers not vulnerable: 1
   [+] Server at 10.130.152.121 (N/A):22 (running SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1)
🛡️ Servers likely not vulnerable (possible LoginGraceTime remediation): 0
⚠️ Servers with unknown SSH version: 0
Summary:
📊 Total scanned hosts: 1
🚨 Total vulnerable hosts: 0
🛡️  Total not vulnerable hosts: 1
🛡️  Total likely not vulnerable hosts: 0
⚠️  Total unknown hosts: 0
🔒 Servers with port 22 closed: 0
```
```bash
┌──(kali㉿kali)-[~/CVE-2024-6387-Vulnerability-Checker]
└─$ python3 CVE-2024-6387-Vulnerability-Checker.py 10.130.152.121


  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++                                        
  + CVE-2024-6387 Vulnerability Checker                       +                                        
  + Created by senhasegura Identity Threat Labs               +                                        
  + Filipi Pires - Threat Researcher & Cybersecurity Advocate +                                        
  + @senhasegura / @filipipires                               +                                        
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++                                        
                                                                                                       


SERVER NOT VULNERABLE: 1
[SAFE] -> 10.130.152.121:22-> Running SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1

```
## Explotación

## Escalada de privilegios

## Flags encontradas

