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



```bash
en http://10.128.175.117:3030/api/tasks
0	
title	"Proceso Ejecución"
severity	"critical"
source	"AIDS"
status	"investigating"
description	"Se detectó tráfico potencial de salida, Alerta TCP $HOME_NET -> 162[.]243[.]103[.]246"
tags	
0	"exec"
1	"auth"
quiz	
todo>investigating	
question	"¿Qué es Emotet?"
answer	
0	"troyano polimórfico"
1	"malware troyano polimórfico"
investigating>contained	
question	"Según AlphaSOC, ¿cuál es el vector de entrada?"
answer	
0	"Phishing"
1	"phishing"
contained>closed	
question	"¿Cuál es el último CVE del servidor?"
answer	
0	"CVE-2025-49812"
id	"80c22939-177b-49d8-92c4-6c196e97fee6"
createdAt	"2026-06-16T10:37:31.274Z"
updatedAt	"2026-06-16T11:26:20.126Z"
1	{ title: "Certificado invalido", severity: "low", source: "IDS", … }
2	
title	"Proceso Ejecución"
severity	"low"
source	"Firewall"
status	"todo"
description	"Se detectó un proceso inusual -> 166[.]1.160[.]118"
tags	
0	"C2C"
1	"network"
quiz	
todo>investigating	
question	"¿Qué archivo se ha vinculado?"
answer	
0	"ff4c287c60ede1990442115bddd68201d25a735458f76786a938a0aa881d14ef.exe"
investigating>contained	
question	"¿Según los detalles de Magic, como se llama el fichero?"
answer	
0	"PE32 executable (GUI) Intel 80386, for MS Windows"
contained>closed	
question	"¿Cuál es el tamaño del fichero en bytes?"
answer	
0	"18155592"
1	"18155592 bytes"
id	"395b3976-dcdc-4c4f-8d06-4f56bbf6e7c5"
createdAt	"2026-06-16T10:37:31.274Z"
updatedAt	"2026-06-16T10:37:31.274Z"
3	
title	"HTTP Request"
severity	"low"
source	"IDS"
status	"todo"
description	"Se detectó una petición inusual de solicitud HTTP -> 47[.]121[.]137[.]203"
tags	
0	"http"
1	"network"
quiz	
todo>investigating	
question	"¿Cuál es su hostname?"
answer	
0	"game[.]neosis[.]com[.]cn"
1	"www[.]game[.]neosis[.]com[.]cn"
investigating>contained	
question	"¿Cuántos puertos tiene abierto?"
answer	
0	"5"
contained>closed	
question	"¿Cuánto es el Score en Virus Total?"
answer	
0	"0"
id	"7fd95389-c474-44b3-b243-c82181edb33d"
createdAt	"2026-06-16T10:37:31.274Z"
updatedAt	"2026-06-16T10:37:31.274Z"
4	
title	"Email Phishing"
severity	"low"
source	"EDR"
status	"todo"
description	"Se detectó un potencial fichero adjunto -> 5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f"
tags	
0	"C2C"
1	"auth"
quiz	
todo>investigating	
question	"¿Cuál es el nombre del fichero?"
answer	
0	"syshelpers[.]exe"
investigating>contained	
question	"¿El 2025-06-16 a que URL apuntaba?"
answer	
0	"hxxps[://]bitbucket[.]org/updatevak/upd/downloads/AClient[.]exe"
contained>closed	
question	"¿Cuál es el MD5 del fichero?"
answer	
0	"3d32539314f681bc250ee749e1dc4538"
id	"ff757fad-e8b9-4429-94b2-9913c86e7565"
createdAt	"2026-06-16T10:37:31.274Z"
updatedAt	"2026-06-16T10:37:31.274Z"
```
└─$ ssh dfinkelstein@10.128.143.249                                   
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
dfinkelstein@10.128.143.249's password: 
Linux tnightmarebc 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64
Last login: Fri Oct 31 17:20:09 2025 from 172.16.162.1
dfinkelstein@tnightmarebc:~$ ls
help.txt
dfinkelstein@tnightmarebc:~$ cat help.txt
Contenido seguro para dfinkelstein
Si controlas Node Red controlas el mundo.

[*] Utiliza el servicio para seguir adelante: start|stop|restart|status

- Activar Servicio: sudo /usr/local/bin/nodered-toggle start
- Parar Servicio: sudo /usr/local/bin/nodered-toggle stop
dfinkelstein@tnightmarebc:~$ sudo /usr/local/bin/nodered-toggle start
✅ Node-RED activo
dfinkelstein@tnightmarebc:~$ ls
help.txt
dfinkelstein@tnightmarebc:~$ sudo su
[sudo] password for dfinkelstein: 
Sorry, user dfinkelstein is not allowed to execute '/usr/bin/su' as root on tnightmarebc.
dfinkelstein@tnightmarebc:~$ ls -la
total 20
drwx------ 3 dfinkelstein dfinkelstein 4096 oct 31  2025 .
drwxr-xr-x 5 root         root         4096 oct 31  2025 ..
lrwxrwxrwx 1 dfinkelstein dfinkelstein    9 oct 31  2025 .bash_history -> /dev/null
-rw-r--r-- 1 dfinkelstein dfinkelstein   87 oct 31  2025 .bashrc
-rw------- 1 dfinkelstein dfinkelstein  270 oct 31  2025 help.txt
drwxr-xr-x 3 dfinkelstein dfinkelstein 4096 oct 31  2025 .local
dfinkelstein@tnightmarebc:~$ cd /dev/null
-bash: cd: /dev/null: No es un directorio
dfinkelstein@tnightmarebc:~$ whoami
dfinkelstein
dfinkelstein@tnightmarebc:~$ ls
help.txt
dfinkelstein@tnightmarebc:~$ sudo node -e 'require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})'
[sudo] password for dfinkelstein: 
Sorry, try again.
[sudo] password for dfinkelstein: 
Sorry, try again.
[sudo] password for dfinkelstein: 
sudo: 3 incorrect password attempts
dfinkelstein@tnightmarebc:~$ 
dfinkelstein@tnightmarebc:~$ sudo node -e 'require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})'
[sudo] password for dfinkelstein: 
Sorry, user dfinkelstein is not allowed to execute '/usr/bin/node -e require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})' as root on tnightmarebc.
dfinkelstein@tnightmarebc:~$ ^C
dfinkelstein@tnightmarebc:~$ cd .local
dfinkelstein@tnightmarebc:~/.local$ ls
share
dfinkelstein@tnightmarebc:~/.local$ cat share
cat: share: Es un directorio
dfinkelstein@tnightmarebc:~/.local$ ..
-bash: ..: orden no encontrada
dfinkelstein@tnightmarebc:~/.local$ .
-bash: .: argumento de nombre de fichero requerido
.: modo de empleo: . fichero [argumentos]
dfinkelstein@tnightmarebc:~/.local$ cd ..
dfinkelstein@tnightmarebc:~$ cd .bash_history
-bash: cd: .bash_history: No es un directorio
dfinkelstein@tnightmarebc:~$ cd .bashrc
-bash: cd: .bashrc: No es un directorio
dfinkelstein@tnightmarebc:~$ ls -la .local
total 12
drwxr-xr-x 3 dfinkelstein dfinkelstein 4096 oct 31  2025 .
drwx------ 3 dfinkelstein dfinkelstein 4096 oct 31  2025 ..
drwx------ 3 dfinkelstein dfinkelstein 4096 oct 31  2025 share
dfinkelstein@tnightmarebc:~$ cd .local/.config
-bash: cd: .local/.config: No existe el fichero o el directorio
dfinkelstein@tnightmarebc:~$ cat help.txt
Contenido seguro para dfinkelstein
Si controlas Node Red controlas el mundo.

[*] Utiliza el servicio para seguir adelante: start|stop|restart|status

- Activar Servicio: sudo /usr/local/bin/nodered-toggle start
- Parar Servicio: sudo /usr/local/bin/nodered-toggle stop
dfinkelstein@tnightmarebc:~$ sudo /usr/local/bin/nodered-toggle status
● node-red.service - Node-RED controlled service
     Loaded: loaded (/etc/systemd/system/node-red.service; disabled; vendor preset: enabled)
     Active: activating (auto-restart) (Result: exit-code) since Tue 2026-06-16 18:03:59 CEST; 1s ago
    Process: 3951 ExecStart=/usr/bin/node-red --userDir /home/nightmare/.node-red --port 1880 (code=exited, status=1/FAILURE)                                                                                       
   Main PID: 3951 (code=exited, status=1/FAILURE)
        CPU: 1.341s

jun 16 18:03:59 tnightmarebc systemd[1]: node-red.service: Consumed 1.341s CPU time.
dfinkelstein@tnightmarebc:~$ 
dfinkelstein@tnightmarebc:~$ sudo -l
Matching Defaults entries for dfinkelstein on tnightmarebc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dfinkelstein may run the following commands on tnightmarebc:
    (root) NOPASSWD: /usr/local/bin/nodered-toggle, /usr/local/bin/nodered-toggle *
dfinkelstein@tnightmarebc:~$ 

## Explotación

## Escalada de privilegios

## Flags encontradas

