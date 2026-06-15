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
### Objetivo

### Comandos Utilizados

## Explotación

## Escalada de privilegios

## Flags encontradas

