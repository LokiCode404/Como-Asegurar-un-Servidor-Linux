# Cómo asegurar un servidor Linux

Guía práctica y en evolución para asegurar un servidor Linux que, con suerte, también te enseñe un poco sobre seguridad y por qué es importante.

> **Nota sobre el origen**  
> Este repositorio es una **traducción al castellano** del proyecto original **“How To Secure A Linux Server”** de `imthenachoman`, disponible en: https://github.com/imthenachoman/How-To-Secure-A-Linux-Server  
> Esta traducción mantiene **la misma licencia** que el proyecto original: **CC BY-SA 4.0**. Debes mantener la atribución al autor original y compartir bajo la misma licencia.

[![CC-BY-SA](https://i.creativecommons.org/l/by-sa/4.0/88x31.png)](#licencia)

## Indice

- [Introduccion](#introduccion)
  - [Objetivo de la guia](#objetivo-de-la-guia)
  - [Por que asegurar tu servidor](#por-que-asegurar-tu-servidor)
  - [Por que otra guia mas](#por-que-otra-guia-mas)
  - [Otras guias](#otras-guias)
  - [Pendiente / Por anadir](#pendiente--por-anadir)
- [Vision general de la guia](#vision-general-de-la-guia)
  - [Sobre esta guia](#sobre-esta-guia)
  - [Mi caso de uso](#mi-caso-de-uso)
  - [Editar ficheros de configuracion - Para gente perezosa](#editar-ficheros-de-configuracion---para-gente-perezosa)
  - [Colaborar](#colaborar)
- [Antes de empezar](#antes-de-empezar)
  - [Define tus principios](#define-tus-principios)
  - [Elegir una distribucion Linux](#elegir-una-distribucion-linux)
  - [Instalar Linux](#instalar-linux)
  - [Tareas previasposteriores a la instalacion](#tareas-previasposteriores-a-la-instalacion)
  - [Otras notas importantes](#otras-notas-importantes)
  - [Usar playbooks de Ansible para asegurar tu servidor Linux](#usar-playbooks-de-ansible-para-asegurar-tu-servidor-linux)
- [El servidor SSH](#el-servidor-ssh)
  - [Nota importante antes de hacer cambios en SSH](#nota-importante-antes-de-hacer-cambios-en-ssh)
  - [Claves publicasprivadas de SSH](#claves-publicasprivadas-de-ssh)
  - [Crear grupo de SSH para usar con AllowGroups](#crear-grupo-de-ssh-para-usar-con-allowgroups)
  - [Asegurar etcsshsshd_config](#asegurar-etcsshsshd_config)
  - [Eliminar claves Diffie-Hellman cortas](#eliminar-claves-diffie-hellman-cortas)
  - [2FAMFA para SSH](#2famfa-para-ssh)
- [Lo basico](#lo-basico)
  - [Limitar quien puede usar sudo](#limitar-quien-puede-usar-sudo)
  - [Limitar quien puede usar su](#limitar-quien-puede-usar-su)
  - [Cliente NTP](#cliente-ntp)
  - [Asegurar proc](#asegurar-proc)
  - [Forzar contrasenas seguras](#forzar-contrasenas-seguras)
  - [Actualizaciones de seguridad automaticas y alertas](#actualizaciones-de-seguridad-automaticas-y-alertas)
  - [Pool de entropia mas seguro wip](#pool-de-entropia-mas-seguro-wip)
  - [Anadir sistema de contrasena de panico  secundaria](#anadir-sistema-de-contrasena-de-panico--secundaria)
- [La red](#la-red)
  - [Cortafuegos UFW  iptables  nftables](#cortafuegos-ufw--iptables--nftables)
  - [Proteger contra escaneos de puertos psad  – opcional](#proteger-contra-escaneos-de-puertos-psad--opcional)
  - [Fail2Ban](#fail2ban)
  - [IPv6](#ipv6)
  - [Comprobar puertos abiertos](#comprobar-puertos-abiertos)
- [La auditoria](#la-auditoria)
  - [Supervision de integridad de archivoscarpetas con AIDE](#supervision-de-integridad-de-archivoscarpetas-con-aide)
  - [Analisis antivirus con ClamAV](#analisis-antivirus-con-clamav)
  - [Deteccion de rootkits con rkhunter](#deteccion-de-rootkits-con-rkhunter)
  - [Deteccion de rootkits con chkrootkit](#deteccion-de-rootkits-con-chkrootkit)
  - [logwatch - informes de logs del sistema](#logwatch---informes-de-logs-del-sistema)
  - [ss – ver puertos en escucha](#ss--ver-puertos-en-escucha)
  - [Lynis - auditoria de seguridad para Linux](#lynis---auditoria-de-seguridad-para-linux)
  - [OSSEC - sistema de deteccion de intrusiones en host](#ossec---sistema-de-deteccion-de-intrusiones-en-host)
- [Zona peligrosa](#zona-peligrosa)
  - [Endurecer el kernel con sysctl](#endurecer-el-kernel-con-sysctl)
  - [Proteger GRUB con contrasena](#proteger-grub-con-contrasena)
  - [Desactivar el login de root](#desactivar-el-login-de-root)
  - [Revisar permisos y umask](#revisar-permisos-y-umask)
  - [Software huerfano o innecesario](#software-huerfano-o-innecesario)
- [Miscelanea](#miscelanea)
  - [Enviar correo desde el servidor msmtp](#enviar-correo-desde-el-servidor-msmtp)
  - [Enviar correo con Exim4 y Gmail TLS implicito](#enviar-correo-con-exim4-y-gmail-tls-implicito)
  - [Fichero de log separado para iptables](#fichero-de-log-separado-para-iptables)
  - [Enviar logs a un servidor remoto](#enviar-logs-a-un-servidor-remoto)
  - [Copias de seguridad](#copias-de-seguridad)
  - [Contacto](#contacto)
  - [Enlaces utiles](#enlaces-utiles)
  - [Agradecimientos](#agradecimientos)
- [Licencia](#licencia)


## Introducción

### Objetivo de la guía

El propósito de esta guía es mostrarte cómo asegurar un servidor Linux.

Hay muchas cosas que puedes hacer para asegurar un servidor Linux y esta guía intentará cubrir tantas como sea posible. Con el tiempo se irán añadiendo más temas y contenido a medida que yo aprenda más cosas o que otras personas contribuyan.

([Ir al índice](#índice))

### Por qué asegurar tu servidor

Supongo que estás usando esta guía porque ya entiendes por qué una buena seguridad es importante. Ese es un tema suficientemente grande como para tener su propia guía y se sale del alcance de esta. Si no tienes claro el “por qué”, te recomiendo que investigues un poco primero.

A muy alto nivel, en el momento en que un dispositivo —como un servidor— está en un dominio público (es decir, es visible desde Internet) se convierte en un objetivo para actores maliciosos. Un dispositivo sin proteger es un parque de atracciones para cualquiera que quiera acceder a tus datos o usar tu servidor como otro nodo más dentro de un ataque DDoS de gran escala.

Lo peor es que, sin una buena seguridad, puede que nunca sepas que tu servidor se ha visto comprometido. Un actor malicioso puede haber obtenido acceso no autorizado y haber copiado tus datos sin cambiar nada, de modo que tú no lo notarías. O tu servidor puede haber formado parte de un ataque DDoS sin que tú lo supieras. Si miras muchas de las brechas de datos a gran escala que salen en las noticias, verás que a menudo las empresas no se dan cuenta de la filtración o de la intrusión hasta mucho después de que el atacante se haya ido.

Contrariamente a la creencia popular, los atacantes no siempre quieren romperte cosas o [secuestrar tus datos por dinero](https://en.wikipedia.org/wiki/Ransomware). A veces solo quieren los datos de tu servidor para sus propios almacenes de datos (el *big data* mueve mucho dinero) o quieren usar tu servidor de forma encubierta para sus fines.

([Ir al índice](#índice))

### Por qué otra guía más

Puede que parezca que esta guía es duplicada o innecesaria porque hay montones de artículos en Internet que explican [cómo asegurar Linux](https://duckduckgo.com/?q=how+to+secure+linux), pero la información está repartida en distintos artículos, que cubren cosas diferentes y de formas distintas. ¿Quién tiene tiempo de leer cientos de artículos?

Mientras investigaba para mi instalación de Debian fui tomando notas. Al final me di cuenta de que, junto con lo que ya sabía y lo que estaba aprendiendo, tenía los mimbres de una guía paso a paso. Pensé que sería buena idea publicarla para ayudar a otros a **aprender** y **ahorrar tiempo**.

Nunca he encontrado una guía que lo cubra todo: esta guía es mi intento.

Muchas de las cosas que se tratan aquí son bastante básicas o triviales, pero la mayoría de nosotros no instalamos Linux todos los días y es fácil olvidar las cosas básicas.

([Ir al índice](#índice))

### Otras guías

Hay muchas guías elaboradas por expertos, por líderes del sector y por las propias distribuciones. No es práctico, y a veces va contra el copyright, incluir aquí todo lo que dicen esas guías. Te recomiendo que las revises antes de ponerte con esta.

- El [Center for Internet Security (CIS)](https://www.cisecurity.org/) ofrece [benchmarks](https://www.cisecurity.org/cis-benchmarks/) que son instrucciones exhaustivas, reconocidas en la industria y paso a paso para asegurar muchas variantes de Linux. Consulta su página *About Us* para más detalles. Mi recomendación es que primero sigas **esta** guía y **después** la del CIS. Así sus recomendaciones prevalecerán sobre las de aquí.
- Para guías de endurecimiento/seguridad específicas de una distribución, consulta la documentación de tu distribución.
- https://security.utexas.edu/os-hardening-checklist/linux-7
- https://cloudpro.zone/index.php/2018/01/18/debian-9-3-server-setup-guide-part-1/
- https://blog.vigilcode.com/2011/04/ubuntu-server-initial-security-quick-secure-setup-part-i/
- https://www.tldp.org/LDP/sag/html/index.html
- https://seifried.org/lasg/
- https://news.ycombinator.com/item?id=19178964
- https://wiki.archlinux.org/index.php/Security
- https://securecompliance.co/linux-server-hardening-checklist/

([Ir al índice](#índice))

### Pendiente / Por añadir

- [ ] Cárceles personalizadas para Fail2Ban
- [ ] MAC (Control de Acceso Obligatorio) y Módulos de Seguridad de Linux (LSM)
  - SELinux
  - AppArmor
- [ ] Cifrado de disco
- [ ] rkhunter y chkrootkit
- [ ] Envío/respaldo de logs
- [ ] CIS-CAT
- [ ] debsums

([Ir al índice](#índice))


## Visión general de la guía

### Sobre esta guía

Esta guía...

- **es** un trabajo en curso.
- **está** centrada en servidores Linux **domésticos**. Todos los conceptos y recomendaciones que aparecen aquí sirven para entornos más grandes o profesionales, pero esos casos suelen requerir configuraciones más avanzadas y especializadas que quedan fuera del alcance de esta guía.
- **no** te enseña Linux, ni cómo [instalar Linux](#instalar-linux), ni cómo usarlo. Si eres nuevo en Linux, pásate por https://linuxjourney.com/.
- **pretende** ser [agnóstica de la distribución Linux](#elegir-una-distribución-linux).
- **no** te enseña todo lo que hay que saber sobre seguridad ni entra en todos los aspectos de la seguridad de sistemas/servidores. Por ejemplo, la seguridad física queda fuera de esta guía.
- **no** explica cómo funcionan los programas/herramientas ni entra en todos sus recovecos. La mayoría de los programas/herramientas que menciono son muy potentes y muy configurables. El objetivo aquí es cubrir lo imprescindible —lo suficiente para abrirte el apetito y que quieras aprender más.
- **intenta** que te sea fácil seguirla proporcionando fragmentos de `código` que puedas copiar y pegar. Puede que tengas que modificar los comandos antes de pegarlos, así que ten a mano tu [editor de texto favorito](https://notepad-plus-plus.org/).
- **está** organizada en un orden que a mí me parece lógico —por ejemplo, asegurar SSH antes de instalar un cortafuegos. Por tanto, se recomienda seguir la guía en el orden en que está presentada, pero no es obligatorio. Solo ten cuidado si cambias el orden: algunas secciones dependen de haber completado otras antes.

([Ir al índice](#índice))

### Mi caso de uso

Hay muchos tipos de servidores y distintos casos de uso. Aunque quiero que la guía sea lo más genérica posible, habrá cosas que no apliquen a todos los casos. Usa tu criterio cuando la sigas.

Para dar contexto a muchos de los temas que se tratan en la guía, mi caso de uso/configuración es:

- Un ordenador de clase escritorio...
- Con una sola tarjeta de red (NIC)...
- Conectado a un router doméstico...
- Que recibe una IP WAN dinámica del ISP...
- Con WAN+LAN en IPv4...
- Y la LAN usando NAT...
- Al que quiero poder acceder por SSH de forma remota desde ordenadores y ubicaciones desconocidas (por ejemplo, desde casa de un amigo).

([Ir al índice](#índice))

### Editar ficheros de configuración - Para gente perezosa

Soy muy perezoso y no me gusta editar ficheros a mano si no es necesario. Y supongo que todo el mundo es como yo. :)

Así que, cuando es posible, he puesto fragmentos de `código` para hacer rápido lo que hace falta, como añadir o cambiar una línea en un fichero de configuración.

Los fragmentos usan comandos básicos como `echo`, `cat`, `sed`, `awk` y `grep`. Cómo funciona cada fragmento, es decir, qué hace cada comando/parte, no lo explico aquí —para eso están las páginas `man`.

**Nota**: estos fragmentos no validan o verifican que el cambio se haya aplicado —por ejemplo, que la línea se haya añadido o cambiado. Te dejo la verificación a ti. En los pasos sí incluyo hacer copias de seguridad de los ficheros que se van a modificar.

No todos los cambios se pueden automatizar con fragmentos. Algunos hay que hacerlos a la vieja usanza, editando a mano. Por ejemplo, no puedes simplemente añadir una línea al final de un fichero tipo [INI](https://en.wikipedia.org/wiki/INI_file). Usa tu [editor de Linux favorito](https://en.wikipedia.org/wiki/Vi).

([Ir al índice](#índice))

### Colaborar

Quise poner la guía en [GitHub](http://www.github.com) para facilitar la colaboración. Cuanta más gente contribuya, mejor y más completa será.

Puedes hacer un fork y enviar un pull request o abrir una [issue nueva](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server/issues/new).

([Ir al índice](#índice))


## Antes de empezar

### Define tus principios

Antes de hacer nada tienes que decidir cuáles son tus principios de seguridad. ¿Cuál es tu [modelo de amenazas](https://en.wikipedia.org/wiki/Threat_model)? Algunas preguntas que deberías hacerte:

- ¿Por qué quieres asegurar este servidor?
- ¿Cuánta seguridad quieres o necesitas?
- ¿Cuánta comodidad estás dispuesto a sacrificar por seguridad (y viceversa)?
- ¿Contra qué amenazas concretas quieres protegerte?
- ¿Hay acceso físico posible al servidor o a la red?
- ¿Vas a abrir puertos en el router para entrar desde fuera de casa?
- ¿Vas a compartir archivos desde este servidor con un PC de escritorio que podría infectarse?
- Si tu propia configuración de seguridad te bloquea, ¿tienes forma de recuperar el acceso?

Estas son solo **algunas** de las cosas que debes pensar. Saber qué quieres proteger y por qué te dirá qué partes de la guía tienes que aplicar.

([Ir al índice](#índice))

### Elegir una distribución Linux

La guía intenta ser agnóstica para que puedas usar prácticamente cualquier distribución, pero hay cosas a tener en cuenta. Quieres una distribución que…

- **sea estable**. No quieres que una actualización automática a las 2 de la mañana te deje el servidor KO.
- **tenga los parches de seguridad al día**. Puedes endurecer mucho un sistema, pero si el sistema base o los paquetes tienen vulnerabilidades conocidas, no estarás realmente seguro.
- **conozcas**. Si no sabes Linux, juega primero con una distro en un entorno de pruebas hasta que te sientas cómodo instalando paquetes, editando ficheros, etc.
- **esté bien soportada**. Incluso el admin más veterano necesita poder buscar ayuda.

([Ir al índice](#índice))

### Instalar Linux

Instalar Linux queda fuera del alcance de esta guía porque cada distro lo hace de forma distinta y porque la instalación suele estar bien documentada. El proceso a alto nivel suele ser:

1. Descargar la ISO.
2. Volcarla a un medio de instalación (USB, CD…).
3. Arrancar el servidor desde ese medio.
4. Seguir el asistente.

Cuando puedas, usa la instalación “avanzada” para tener más control sobre lo que se instala. **Instala solo lo imprescindible.** Personalmente, el autor solo instala SSH y suele activar el cifrado de disco.

([Ir al índice](#índice))

### Tareas previas/posteriores a la instalación

- Si vas a abrir puertos en el router para acceder desde fuera, **no** abras todavía el port forwarding hasta que el sistema esté asegurado.
- Asegúrate de que tienes acceso remoto (SSH) si no vas a trabajar físicamente en el servidor.
- Mantén el sistema actualizado (por ejemplo, en Debian/Ubuntu: `sudo apt update && sudo apt upgrade`).
- Haz las tareas específicas de tu entorno:
  - Configurar la red
  - Configurar los puntos de montaje en `/etc/fstab`
  - Crear las cuentas de usuario iniciales
  - Instalar utilidades básicas como `man`, etc.
- El servidor debe poder **enviar correo** para que recibas alertas (más abajo hay una sección de correo).
- Se recomienda leer los CIS Benchmarks **antes** de empezar, para saber qué proponen. La recomendación del autor es: primero esta guía y **luego** la guía CIS, para que sus ajustes prevalezcan.

([Ir al índice](#índice))

### Otras notas importantes

- La guía está escrita y probada en Debian. La mayoría debería funcionar en otras distros. Si algo no funciona, consulta la documentación de tu distribución.
- Las rutas de ficheros y algunos comandos cambian de una distro a otra.
- Lee toda la guía antes de empezar, por si hay algo que en tu caso concreto no deberías hacer o deberías hacerlo en otro orden.
- No copies y pegues a ciegas. Algunos comandos hay que adaptarlos a tus usuarios, rutas o caso de uso.

([Ir al índice](#índice))

### Usar playbooks de Ansible para asegurar tu servidor Linux

Los playbooks de Ansible de esta guía están disponibles en el repositorio:

> **How To Secure A Linux Server With Ansible** – https://github.com/moltenbit/How-To-Secure-A-Linux-Server-With-Ansible

Pasos básicos:

1. Instala [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html).
2. Haz `git clone` del repo.
3. Crea las claves públicas/privadas de SSH como se explica en la sección de SSH de esta guía.
4. Edita todas las variables en `group_vars/variables.yml` según tus necesidades.
5. Activa temporalmente el acceso SSH de root en el servidor **solo** para que Ansible pueda hacer los cambios iniciales.
6. (Recomendado) configura IP estática.
7. Añade la IP de tu servidor al inventario `hosts.yml`.
8. Ejecuta primero el playbook de requisitos con la contraseña de root.
9. Ejecuta después el playbook principal con la contraseña del usuario nuevo.
10. Si lo vas a ejecutar más veces, usa la clave SSH y el puerto SSH nuevo que configuraste.

Lee todas las tareas antes de ejecutarlas y comprueba después que los valores han quedado como tú quieres.

([Ir al índice](#índice))


## El servidor SSH

### Nota importante antes de hacer cambios en SSH

Antes de tocar la configuración de SSH es muy buena idea mantener **una segunda sesión/terminal SSH abierta** al servidor. Así, si cometes un error y tu sesión principal se cierra o deja de poder autenticarse, podrás usar la otra sesión para corregir el problema sin tener que ir físicamente al equipo.

(Gracias a Sonnenbrand por señalarlo en la issue original.)

([Ir al índice](#índice))

### Claves públicas/privadas de SSH

#### Por qué

Usar autenticación basada en claves es **más seguro** y suele ser **más cómodo** que usar contraseña. La contraseña viaja como secreto que alguien puede adivinar o intentar por fuerza bruta; la clave privada **nunca sale** de tu máquina.

#### Cómo funciona

SSH usa un par de claves: una **clave pública** y una **clave privada**. El par se genera en el **cliente** (tu portátil/PC). La clave privada se queda contigo y no se comparte. La clave pública se copia al servidor, a la cuenta con la que quieras iniciar sesión (normalmente en `~/.ssh/authorized_keys`).

Cuando el servidor recibe una conexión SSH tuya, comprueba si la cuenta tiene una clave pública autorizada. Si la tiene, le pide al cliente que demuestre que posee la clave privada correspondiente. Si la demostración es correcta, el servidor te deja entrar **sin pedir contraseña de cuenta**.

Como la clave privada es lo que te permite entrar, es importante protegerla (por ejemplo, con una *passphrase*). Y como la clave pública es la que el servidor usa para identificarte, hay que asegurarse de que no cae en manos de terceros que puedan meterla en tus servidores.

En esta guía se recomienda usar claves **Ed25519** porque ofrecen buena seguridad y rendimiento frente a RSA/ECDSA/DSA.

#### Objetivos

- Crear un par de claves SSH (pública/privada) en **cada** equipo desde el que vayas a conectarte.
- Copiar la clave **pública** al servidor, a la cuenta correspondiente.
- Comprobar que puedes entrar sin contraseña.

#### Notas

- Debes repetir este proceso para **cada ordenador** y **cada usuario** que vaya a entrar por SSH.
- Si pones *passphrase* a la clave, tendrás una capa extra de seguridad.

#### Referencias

- https://www.ssh.com/ssh/public-key-authentication
- https://help.ubuntu.com/community/SSH/OpenSSH/Keys
- https://linux-audit.com/using-ed25519-openssh-keys-instead-of-dsa-rsa-ecdsa/
- https://www.digitalocean.com/community/tutorials/understanding-the-ssh-encryption-and-connection-process
- https://wiki.archlinux.org/index.php/SSH_Keys
- https://www.ssh.com/ssh/copy-id
- `man ssh-keygen`
- `man ssh-copy-id`
- `man ssh-add`

#### Pasos

1. En el **cliente** (tu equipo), genera el par de claves Ed25519:

   ```bash
   ssh-keygen -t ed25519
   ```

   Acepta la ruta por defecto (`~/.ssh/id_ed25519`) y, si quieres, ponle una frase de paso.

2. Copia la **clave pública** al servidor con:

   ```bash
   ssh-copy-id usuario@tu-servidor
   ```

   Esto añade tu clave al fichero `~/.ssh/authorized_keys` de ese usuario en el servidor.

3. Prueba la conexión:

   ```bash
   ssh usuario@tu-servidor
   ```

   Si todo está bien, entrarás sin que el servidor te pida la contraseña de la cuenta (o solo la *passphrase* de la clave).

([Ir al índice](#índice))

### Crear grupo de SSH para usar con AllowGroups

#### Por qué

Para que solo **ciertas** cuentas puedan entrar por SSH. Si luego añades/eliminas usuarios de ese grupo, no tendrás que tocar otra vez la configuración SSH.

#### Cómo funciona

OpenSSH permite limitar el acceso por grupos UNIX mediante la directiva `AllowGroups` en `/etc/ssh/sshd_config`. Creamos un grupo (por ejemplo `sshusers`) y en la configuración de SSH decimos: “solo los usuarios de este grupo entran”.

#### Objetivos

- Tener un grupo del sistema pensado para SSH.
- Poder añadir/quitar usuarios de ese grupo según quién deba tener acceso.

#### Pasos

1. Crear el grupo:

   ```bash
   sudo groupadd sshusers
   ```

2. Añadir usuarios al grupo:

   ```bash
   sudo usermod -a -G sshusers usuario1
   sudo usermod -a -G sshusers usuario2
   ```

([Ir al índice](#índice))

### Asegurar `/etc/ssh/sshd_config`

#### Por qué

SSH suele ser **la puerta principal** del servidor. Una configuración débil permite ataques de fuerza bruta, algoritmos inseguros, acceso de root o contraseñas fáciles. Endurecer `sshd_config` reduce muchísimo la superficie de ataque.

#### Cómo funciona

El fichero `/etc/ssh/sshd_config` dice al daemon SSH qué puerto usar, qué algoritmos permitir, si permitir root, si permitir contraseñas, qué grupos pueden entrar, etc. Vamos a partir de las recomendaciones de Mozilla para OpenSSH 6.7+ y añadir los ajustes propios de la guía.

#### Objetivos

- Tener una copia de seguridad del fichero actual.
- Quitar líneas comentadas para trabajar más claro.
- Definir algoritmos seguros.
- Desactivar lo que no se usa.
- Limitar el acceso a nuestro grupo SSH.

#### Notas

- SSH no se lleva bien con entradas duplicadas y contradictorias: revisa el fichero y deja solo **una** por opción.
- Si cambias el puerto SSH, acuérdate de abrirlo en el firewall antes de activar el firewall.
- Después de cambiar la configuración, **no cierres** la sesión actual hasta haber comprobado que puedes entrar con la nueva.

#### Referencias

- https://infosec.mozilla.org/guidelines/openssh
- `man sshd_config`

#### Pasos

1. Haz copia de seguridad y quita comentarios/líneas vacías para trabajar mejor:

   ```bash
   sudo cp --archive /etc/ssh/sshd_config /etc/ssh/sshd_config-COPY-$(date +"%Y%m%d%H%M%S")
   sudo sed -i -r -e '/^#|^$/ d' /etc/ssh/sshd_config
   ```

2. Edita `/etc/ssh/sshd_config` y asegúrate de que contiene, adaptado a tu entorno, algo como:

   ```text
   ########################################################################################################
   # ajustes recomendados (adaptados) de https://infosec.mozilla.org/guidelines/openssh
   ########################################################################################################

   HostKey /etc/ssh/ssh_host_ed25519_key
   HostKey /etc/ssh/ssh_host_rsa_key
   HostKey /etc/ssh/ssh_host_ecdsa_key

   KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

   Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

   MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

   # Registrar el fingerprint del usuario
   LogLevel VERBOSE

   ########################################################################################################
   # fin ajustes de Mozilla
   ########################################################################################################

   # Solo protocolo 2
   Protocol 2

   # No permitir variables de entorno del usuario
   PermitUserEnvironment no

   # Subsystem SFTP más verboso
   Subsystem sftp internal-sftp -f AUTHPRIV -l INFO

   # No X11
   X11Forwarding no

   # No TCP Forwarding salvo que lo necesites
   AllowTcpForwarding no

   # Limitar acceso por grupo
   AllowGroups sshusers

   # Desactivar login directo de root
   PermitRootLogin no

   # Desactivar autenticación por contraseña (si ya tienes claves)
   PasswordAuthentication no
   ```

   **Ajusta** estos valores a tu caso real (por ejemplo, si sí necesitas `AllowTcpForwarding`).

3. Comprueba la configuración antes de reiniciar:

   ```bash
   sudo sshd -T
   ```

   Si no hay errores, recarga/reinicia el servicio:

   ```bash
   sudo systemctl restart sshd
   ```

   (o `sudo service ssh restart` según la distro).

([Ir al índice](#índice))

### Eliminar claves Diffie-Hellman cortas

#### Por qué

Las guías modernas recomiendan no usar grupos Diffie-Hellman demasiado pequeños porque debilitan el intercambio de claves. OpenSSH usa `/etc/ssh/moduli` para esto; podemos filtrar las entradas cortas.

#### Objetivo

- Dejar en `/etc/ssh/moduli` solo entradas de 3072 bits o más.

#### Referencias

- https://infosec.mozilla.org/guidelines/openssh

#### Pasos

1. Copia de seguridad:

   ```bash
   sudo cp --archive /etc/ssh/moduli /etc/ssh/moduli-COPY-$(date +"%Y%m%d%H%M%S")
   ```

2. Filtra y sustituye:

   ```bash
   sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp
   sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli
   ```

([Ir al índice](#índice))

### 2FA/MFA para SSH

#### Por qué

SSH con claves ya es muy seguro, pero si alguien roba tu clave privada o una contraseña, podría entrar. Añadiendo un **segundo factor** (por ejemplo un código TOTP de 6 dígitos que cambia cada 30 segundos) elevas mucho el nivel.

#### Notas

- Usaremos el módulo PAM de Google (`libpam-google-authenticator`).
- Cada usuario que quiera 2FA debe generar su propio secreto.
- Necesitarás una app de autenticación (Google Authenticator, Authy, Aegis, etc.).

#### Pasos

1. Instala el módulo:

   ```bash
   sudo apt install libpam-google-authenticator
   ```

2. Como el **usuario** que quieres proteger, ejecuta:

   ```bash
   google-authenticator
   ```

   Responde “sí” a las opciones recomendadas: limitar reusos, permitir pequeño desfase horario, generar códigos de emergencia, etc. Escanea el QR con tu app.

3. Edita `/etc/pam.d/sshd` y añade al principio:

   ```text
   auth required pam_google_authenticator.so
   ```

4. Activa los *challenge-response* en SSH:

   ```bash
   sudo sed -i -r -e "s/^(ChallengeResponseAuthentication .*)$/# \1/" /etc/ssh/sshd_config
   echo -e "\nChallengeResponseAuthentication yes" | sudo tee -a /etc/ssh/sshd_config
   ```

5. Reinicia SSH:

   ```bash
   sudo systemctl restart sshd
   ```

6. Prueba una conexión SSH nueva: debería pedirte usuario, luego autenticarse con tu clave y, finalmente, pedirte el código de la app.

([Ir al índice](#índice))


## Lo básico

Esta sección reúne varias medidas “fundamentales” que deberías aplicar casi siempre en un servidor Linux recién instalado. Son cosas que reducen superficie de ataque, mejoran la trazabilidad y ponen orden.

([Ir al índice](#índice))

### Limitar quién puede usar `sudo`

#### Por qué

`sudo` permite ejecutar comandos como otro usuario, incluido `root`. No todas las cuentas del sistema deberían poder hacerlo. Vamos a limitarlo a un grupo.

#### Cómo funciona

Creamos un grupo (si tu distro no lo trae ya), añadimos ahí solo a las cuentas que necesiten `sudo` y en el fichero de configuración de `sudo` indicamos que solo ese grupo puede usarlo.

#### Notas

- En Debian/Ubuntu suele existir el grupo `sudo`.
- En Red Hat/CentOS suele existir el grupo `wheel`.
- Comprueba primero si ya tienes uno de esos grupos y aprovéchalo.

#### Pasos

1. Crear el grupo (si no existe):

   ```bash
   sudo groupadd sudousers
   ```

2. Añadir usuarios al grupo:

   ```bash
   sudo usermod -a -G sudousers usuario1
   sudo usermod -a -G sudousers usuario2
   ```

3. Copia de seguridad de `/etc/sudoers`:

   ```bash
   sudo cp --archive /etc/sudoers /etc/sudoers-COPY-$(date +"%Y%m%d%H%M%S")
   ```

4. Editar con `visudo`:

   ```bash
   sudo visudo
   ```

5. Añadir la línea:

   ```text
   %sudousers   ALL=(ALL:ALL) ALL
   ```

Con esto, solo los usuarios de `sudousers` podrán usar `sudo`.

([Ir al índice](#índice))

### Limitar quién puede usar `su`

#### Por qué

`su` también permite cambiar de usuario, incluso a `root`. Es buena idea limitarlo a un grupo concreto para que no cualquier cuenta local pueda hacer un `su`.

#### Pasos

1. Crear el grupo:

   ```bash
   sudo groupadd suusers
   ```

2. Añadir usuarios al grupo:

   ```bash
   sudo usermod -a -G suusers usuario1
   ```

3. Cambiar permisos de `/bin/su` para que solo ese grupo pueda usarlo:

   ```bash
   sudo dpkg-statoverride --update --add root suusers 4750 /bin/su
   ```

([Ir al índice](#índice))

### Cliente NTP

#### Por qué

La hora correcta es clave para seguridad: logs coherentes, tokens válidos, certificados, 2FA… Si el reloj se desajusta, pueden fallar cosas.

#### Pasos

1. Instalar NTP (o el cliente de tiempo de tu distro):

   ```bash
   sudo apt install ntp
   ```

2. Editar `/etc/ntp.conf` si quieres cambiar los servidores por los de tu país o empresa.

3. Comprobar:

   ```bash
   sudo systemctl status ntp
   sudo ntpq -p
   ```

([Ir al índice](#índice))

### Asegurar `/proc`

#### Por qué

Por defecto, en muchas distros los usuarios pueden ver procesos de otros usuarios a través de `/proc`. Montarlo con `hidepid=2` evita esa fuga de información.

#### Pasos

1. Copia de seguridad de `/etc/fstab`:

   ```bash
   sudo cp --archive /etc/fstab /etc/fstab-COPY-$(date +"%Y%m%d%H%M%S")
   ```

2. Añade esta línea (o ajusta la existente) al final:

   ```text
   proc  /proc  proc  defaults,hidepid=2  0  0
   ```

3. Remonta:

   ```bash
   sudo mount -o remount,hidepid=2 /proc
   ```

Ten en cuenta que algunas herramientas antiguas pueden verse afectadas; el original lo avisaba como “puede dar problemas en algunas distros”.

([Ir al índice](#índice))

### Forzar contraseñas seguras

#### Por qué

Sin políticas de complejidad, los usuarios pueden poner contraseñas débiles. Con `libpam-pwquality` (o similar) obligamos a que las nuevas contraseñas tengan longitud mínima, tipos de caracteres, etc.

#### Pasos

1. Instalar:

   ```bash
   sudo apt install libpam-pwquality
   ```

2. Copia de seguridad del fichero PAM de contraseñas:

   ```bash
   sudo cp --archive /etc/pam.d/common-password /etc/pam.d/common-password-COPY-$(date +"%Y%m%d%H%M%S")
   ```

3. Editar `/etc/pam.d/common-password` y dejar la línea de `pam_pwquality.so` más o menos así (ajusta a tus políticas):

   ```text
   password requisite pam_pwquality.so retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3
   ```

([Ir al índice](#índice))

### Actualizaciones de seguridad automáticas y alertas

#### Por qué

La mayoría de las intrusiones explotan **vulnerabilidades conocidas**. Si tu sistema está al día, reduces mucho el riesgo. En un servidor casero, es muy cómodo que se actualice solo y además te avise.

#### Pasos (Debian/Ubuntu)

1. Instalar:

   ```bash
   sudo apt install unattended-upgrades apt-listchanges apticron
   ```

2. Configurar `/etc/apt/apt.conf.d/50unattended-upgrades` y/o crear un fichero propio en `/etc/apt/apt.conf.d/` indicando:
   - qué orígenes actualizar
   - si enviar correo
   - si reiniciar automáticamente

3. Probar en modo simulación:

   ```bash
   sudo unattended-upgrade --dry-run --debug
   ```

4. Ajustar `apticron` para que envíe un correo con las actualizaciones disponibles.

([Ir al índice](#índice))

### Pool de entropía más seguro (WIP)

El original marcaba esta parte como “work in progress”. La idea es mejorar la entropía del sistema instalando algo como `rng-tools` o `haveged`:

```bash
sudo apt install rng-tools
echo "HRNGDEVICE=/dev/urandom" | sudo tee -a /etc/default/rng-tools
sudo systemctl restart rng-tools.service
```

([Ir al índice](#índice))

### Añadir sistema de contraseña de pánico / secundaria

El original mencionaba usar un módulo tipo `pam-duress` para tener una **segunda contraseña** que, si te ves obligado a darla, ejecute un script (por ejemplo, para avisar o bloquear). Esto es avanzado y delicado, así que solo úsalo si sabes lo que haces y personaliza el script que se ejecuta.

([Ir al índice](#índice))


## La red

En esta parte vamos a reducir qué puede entrar y qué puede hacer ruido en el servidor desde fuera. La idea es: por defecto se niega todo lo entrante, se permite lo saliente y solo se abren los puertos que realmente vas a usar.

([Ir al índice](#índice))

### Cortafuegos (UFW / iptables / nftables)

#### Por qué

Un cortafuegos es tu primera línea de defensa. Aunque algún servicio quede escuchando por error, el firewall puede impedir que sea accesible desde Internet.

#### Opciones

- En Debian/Ubuntu es muy sencillo usar **UFW** (Uncomplicated Firewall).
- Puedes usar directamente `iptables` o `nftables` si prefieres reglas más finas.

#### Objetivos

- Política por defecto: **denegar entrantes**.
- Permitir SSH (en el puerto que uses).
- Permitir HTTP/HTTPS si haces de servidor web.
- Registrar lo que se bloquee.

#### Pasos con UFW

1. Instalar (si no lo tienes):

   ```bash
   sudo apt install ufw
   ```

2. Fijar políticas por defecto:

   ```bash
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   ```

3. Permitir SSH **antes** de activar el firewall (si no, te cierras la puerta). Si usas el puerto 22:

   ```bash
   sudo ufw allow 22/tcp comment 'SSH'
   ```

   Si cambiaste el puerto en `sshd_config`, usa ese:

   ```bash
   sudo ufw allow 2222/tcp comment 'SSH personalizado'
   ```

4. Si tienes web:

   ```bash
   sudo ufw allow 80/tcp comment 'HTTP'
   sudo ufw allow 443/tcp comment 'HTTPS'
   ```

5. Activar:

   ```bash
   sudo ufw enable
   ```

6. Ver estado:

   ```bash
   sudo ufw status verbose
   ```

([Ir al índice](#índice))

### Proteger contra escaneos de puertos (psad) – opcional

#### Por qué

Tu servidor en Internet va a recibir port scans constantemente. `psad` lee los logs del firewall y detecta patrones típicos de escaneo; puede alertarte e incluso bloquear.

#### Pasos (resumen)

1. Instalar:

   ```bash
   sudo apt install psad
   ```

2. Configurar `/etc/psad/psad.conf` con tu correo y tu IP de confianza.

3. Actualizar firmas y analizar reglas:

   ```bash
   sudo psad --sig-update
   sudo psad --fw-analyze
   ```

4. Reiniciar el servicio `psad`.

([Ir al índice](#índice))

### Fail2Ban

#### Por qué

Aunque tengas SSH con claves, puede que algún servicio de tu máquina sí use contraseña (p. ej. un panel web). `Fail2Ban` mira los logs y, cuando ve muchos intentos fallidos desde la misma IP, mete una regla en el firewall para **banear** esa IP durante un tiempo.

#### Pasos

1. Instalar:

   ```bash
   sudo apt install fail2ban
   ```

2. Crear tu fichero local (no edites el global):

   ```bash
   sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
   ```

3. En `/etc/fail2ban/jail.local`, al menos activa la jaula de SSH:

   ```text
   [sshd]
   enabled  = true
   port     = ssh
   logpath  = /var/log/auth.log
   maxretry = 5
   bantime  = 3600
   ```

4. Reiniciar:

   ```bash
   sudo systemctl restart fail2ban
   ```

5. Ver estado:

   ```bash
   sudo fail2ban-client status
   sudo fail2ban-client status sshd
   ```

([Ir al índice](#índice))

### IPv6

#### Por qué

Si tu servidor tiene IPv6 pero tu firewall solo está protegiendo IPv4, tienes un agujero. O lo desactivas o lo filtras.

#### Opciones

- Desactivar IPv6 en `/etc/sysctl.conf`:

  ```text
  net.ipv6.conf.all.disable_ipv6 = 1
  net.ipv6.conf.default.disable_ipv6 = 1
  ```

  y aplicar con:

  ```bash
  sudo sysctl -p
  ```

- O habilitar IPv6 en UFW (`IPV6=yes` en `/etc/default/ufw`) y crear reglas para IPv6 también.

([Ir al índice](#índice))

### Comprobar puertos abiertos

#### Por qué

Después de montar firewall y servicios, conviene comprobar desde **otra máquina** qué puertos están realmente accesibles.

#### Pasos

1. Desde otra máquina de la red:

   ```bash
   nmap -sS -Pn TU.IP
   ```

2. Si el servidor va a Internet, prueba desde fuera (otra red o un VPS).

3. Ajusta el firewall según el resultado.

([Ir al índice](#índice))


## La auditoría

Aquí añadimos herramientas para **ver** lo que pasa en el sistema, para que te avisen cuando cambie algo que no debería o cuando aparezca algo sospechoso. Endurecer sin mirar los logs sirve de poco.

([Ir al índice](#índice))

### Supervisión de integridad de archivos/carpetas con AIDE

#### Por qué

Si alguien entra en el sistema, es muy probable que cambie o añada archivos. Una herramienta de integridad como **AIDE** crea una base de datos con los hashes de ficheros importantes y luego compara para detectar cambios inesperados.

#### Pasos básicos

1. Instalar:

   ```bash
   sudo apt install aide
   ```

2. Inicializar la base de datos:

   ```bash
   sudo aideinit
   ```

   Esto suele crear `/var/lib/aide/aide.db.new`.

3. Sustituir la base de datos activa por la nueva:

   ```bash
   sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
   ```

4. Para comprobar:

   ```bash
   sudo aide --check
   ```

5. Programa un `cron` diario/semanal para que ejecute el chequeo y te envíe el informe por correo.

([Ir al índice](#índice))

### Análisis antivirus con ClamAV

#### Por qué

En servidores Linux no siempre es imprescindible, pero si compartes archivos o recibes ficheros que luego se pasan a máquinas Windows, viene bien poder escanear.

#### Pasos básicos

1. Instalar:

   ```bash
   sudo apt install clamav clamav-freshclam
   ```

2. Actualizar firmas:

   ```bash
   sudo freshclam
   ```

3. Lanzar un escaneo:

   ```bash
   sudo clamscan -r /home
   ```

4. Si quieres, prográmalo en `cron` para revisar ciertas carpetas.

([Ir al índice](#índice))

### Detección de rootkits con rkhunter

#### Por qué

Un rootkit intenta esconder la presencia de un atacante. `rkhunter` compara tu sistema contra firmas conocidas y contra cambios sospechosos.

#### Pasos

1. Instalar:

   ```bash
   sudo apt install rkhunter
   ```

2. Actualizar:

   ```bash
   sudo rkhunter --update
   sudo rkhunter --propupd
   ```

3. Chequear:

   ```bash
   sudo rkhunter --check
   ```

4. Revisa el informe en `/var/log/rkhunter.log`.

([Ir al índice](#índice))

### Detección de rootkits con chkrootkit

Este es otro escáner clásico. Puedes usarlo como complemento a `rkhunter`.

1. Instalar:

   ```bash
   sudo apt install chkrootkit
   ```

2. Ejecutar:

   ```bash
   sudo chkrootkit
   ```

([Ir al índice](#índice))

### logwatch - informes de logs del sistema

#### Por qué

El sistema genera muchos logs, pero no tenemos tiempo de leerlos todos. **logwatch** hace un resumen diario de lo importante y te lo envía por correo.

#### Pasos

1. Instalar:

   ```bash
   sudo apt install logwatch
   ```

2. Probar manualmente:

   ```bash
   sudo logwatch --output mail --mailto root --range yesterday --service all
   ```

3. Ajustar la configuración en `/etc/logwatch/conf/logwatch.conf` si quieres cambiar rango, nivel de detalle o destinatario.

4. Deja que `cron.daily` lo ejecute.

([Ir al índice](#índice))

### `ss` – ver puertos en escucha

#### Por qué

Es la forma rápida de saber qué servicios están escuchando y en qué puertos.

#### Ejemplos

```bash
sudo ss -tulnp          # todo en escucha
sudo ss -tln            # solo TCP
sudo ss -tulnp | grep 22
```

([Ir al índice](#índice))

### Lynis - auditoría de seguridad para Linux

#### Por qué

**Lynis** es una herramienta que revisa tu sistema y te da una lista de recomendaciones de seguridad. Es una buena forma de validar que no te has dejado nada.

#### Pasos

1. Instalar:

   ```bash
   sudo apt install lynis
   ```

2. Auditar:

   ```bash
   sudo lynis audit system
   ```

3. Revisa el informe y aplica lo que te interese.

([Ir al índice](#índice))

### OSSEC - sistema de detección de intrusiones en host

Si quieres algo más completo (HIDS), **OSSEC** monitoriza logs, cambios, rootkits y puede enviar alertas o ejecutar acciones. La instalación es más larga, así que sigue la documentación oficial del proyecto.

([Ir al índice](#índice))


## Zona peligrosa

El autor llama así a esta parte porque aquí hay ajustes que **pueden dejarte fuera** de tu propio servidor o romper cosas si tu caso de uso es distinto. Léelo todo, haz copia de seguridad antes y ten una sesión SSH abierta mientras lo aplicas.

([Ir al índice](#índice))

### Endurecer el kernel con sysctl

#### Por qué

Linux permite ajustar muchos comportamientos de red y del kernel mediante `/etc/sysctl.conf` o ficheros en `/etc/sysctl.d/`. Algunos valores reducen la superficie de ataque, evitan redirecciones, registran paquetes sospechosos o desactivan funciones que no necesitas.

#### Pasos

1. Copia de seguridad:

   ```bash
   sudo cp --archive /etc/sysctl.conf /etc/sysctl.conf-COPY-$(date +"%Y%m%d%H%M%S")
   ```

2. Añade al final de `/etc/sysctl.conf` algo como:

   ```text
   # no aceptar redirecciones ICMP
   net.ipv4.conf.all.accept_redirects = 0
   net.ipv4.conf.default.accept_redirects = 0
   net.ipv6.conf.all.accept_redirects = 0
   net.ipv6.conf.default.accept_redirects = 0

   # no aceptar source routing
   net.ipv4.conf.all.accept_source_route = 0
   net.ipv4.conf.default.accept_source_route = 0

   # protección SYN
   net.ipv4.tcp_syncookies = 1

   # ignorar broadcasts
   net.ipv4.icmp_echo_ignore_broadcasts = 1

   # registrar paquetes raros
   net.ipv4.conf.all.log_martians = 1
   net.ipv4.conf.default.log_martians = 1

   # no reenviar paquetes (si no somos router)
   net.ipv4.ip_forward = 0
   net.ipv6.conf.all.forwarding = 0

   # evitar errores ICMP falsos
   net.ipv4.icmp_ignore_bogus_error_responses = 1
   ```

3. Aplicar:

   ```bash
   sudo sysctl -p
   ```

Adáptalo a tu entorno: si tu servidor actúa de router/VPN, no desactives el reenvío.

([Ir al índice](#índice))

### Proteger GRUB con contraseña

#### Por qué

Si alguien tiene acceso físico al servidor, puede editar la línea de arranque de GRUB y conseguir una shell de root o arrancar en modo de rescate. Poner contraseña a GRUB evita eso.

#### Pasos

1. Generar una contraseña cifrada:

   ```bash
   sudo grub-mkpasswd-pbkdf2
   ```

   Introduce la contraseña que quieras y copia la línea larga que empieza por `grub.pbkdf2.sha512...`.

2. Editar `/etc/grub.d/40_custom` y añadir:

   ```text
   set superusers="root"
   password_pbkdf2 root grub.pbkdf2.sha512.10000....
   ```

3. Regenerar GRUB:

   ```bash
   sudo update-grub
   ```

4. Reinicia y prueba que, al intentar editar la entrada de GRUB, pide contraseña.

([Ir al índice](#índice))

### Desactivar el login de root

En la parte de SSH ya desactivamos `PermitRootLogin`. Si además quieres bloquear la cuenta `root` para que no pueda iniciar sesión en TTYs:

```bash
sudo passwd -l root
```

**Asegúrate** de que tienes una cuenta de usuario en el grupo de `sudo` antes de hacer esto.

([Ir al índice](#índice))

### Revisar permisos y umask

Si tu sistema viene con una `umask` demasiado permisiva, los ficheros nuevos podrían ser legibles por otros usuarios. Un valor más restrictivo es:

```text
umask 027
```

Ponlo en `/etc/profile` o en los perfiles de shell que usen tus usuarios, revisando que no rompe nada de tu entorno.

([Ir al índice](#índice))

### Software huérfano o innecesario

Cuanto más software haya instalado, más superficie de ataque. De vez en cuando:

```bash
sudo apt autoremove
sudo apt purge paquete-que-no-usas
```

Y revisa con:

```bash
sudo ss -tulnp
```

que no haya servicios escuchando que no necesitas.

([Ir al índice](#índice))


## Miscelánea

Esta sección recoge las cosas útiles que no encajan del todo en las secciones anteriores, pero que completan la seguridad y el mantenimiento del servidor.

([Ir al índice](#índice))

### Enviar correo desde el servidor (msmtp)

Si no quieres configurar un MTA completo (Postfix/Exim4) y solo quieres que el servidor pueda enviar los correos del sistema usando tu cuenta de Gmail (o similar), puedes usar **msmtp**, que actúa como un `sendmail` muy simple.

1. Instala:

   ```bash
   sudo apt install msmtp msmtp-mta
   ```

2. Crea `/etc/msmtprc` (o `~/.msmtprc` si solo es para un usuario) con algo como:

   ```text
   defaults
     auth           on
     tls            on
     tls_trust_file /etc/ssl/certs/ca-certificates.crt
     logfile        /var/log/msmtp.log

   account gmail
     host smtp.gmail.com
     port 587
     from TU_CORREO@gmail.com
     user TU_CORREO@gmail.com
     password TU_APP_PASSWORD

   account default : gmail
   ```

3. Protege el fichero si contiene contraseñas:

   ```bash
   sudo chown root:root /etc/msmtprc
   sudo chmod 600 /etc/msmtprc
   ```

4. Prueba:

   ```bash
   echo "prueba" | msmtp -a default tu-correo@ejemplo.com
   ```

([Ir al índice](#índice))

### Enviar correo con Exim4 y Gmail (TLS implícito)

Si prefieres tener un MTA un poco más completo pero seguir usando Gmail como *smarthost*, puedes hacerlo con Exim4.

1. Instala Exim4:

   ```bash
   sudo apt install exim4
   ```

2. Reconfigura:

   ```bash
   sudo dpkg-reconfigure exim4-config
   ```

   Elige la opción de “enviar correo mediante *smarthost*” y “no recibir correo”.

3. Añade tu usuario/contraseña de Gmail (o app password) a `/etc/exim4/passwd.client`:

   ```text
   smtp.gmail.com:TU_CORREO@gmail.com:TU_APP_PASSWORD
   ```

4. Fuerza TLS y puertos adecuados en `/etc/exim4/exim4.conf.localmacros`, por ejemplo:

   ```text
   MAIN_TLS_ENABLE = 1
   REMOTE_SMTP_SMARTHOST_HOSTS_REQUIRE_TLS = *
   TLS_ON_CONNECT_PORTS = 465
   REQUIRE_PROTOCOL = smtps
   IGNORE_SMTP_LINE_LENGTH_LIMIT = true
   ```

5. Actualiza y reinicia:

   ```bash
   sudo update-exim4.conf
   sudo systemctl restart exim4
   ```

6. Prueba con `mail -s ...` y revisa `/var/log/exim4/mainlog`.

([Ir al índice](#índice))

### Fichero de log separado para iptables

Para que los registros del cortafuegos no ensucien `syslog`, puedes mandarlos a su propio fichero.

1. Crea `/etc/rsyslog.d/10-iptables.conf`:

   ```text
   :msg, contains, "iptables" -/var/log/iptables.log
   & stop
   ```

   (O usa el prefijo que tú uses en tus reglas de firewall.)

2. Crea el fichero y pon permisos:

   ```bash
   sudo touch /var/log/iptables.log
   sudo chown syslog:adm /var/log/iptables.log
   sudo chmod 640 /var/log/iptables.log
   ```

3. Reinicia rsyslog:

   ```bash
   sudo systemctl restart rsyslog
   ```

([Ir al índice](#índice))

### Enviar logs a un servidor remoto

Si alguien entra, puede borrar los logs locales. Si los estás enviando en paralelo a otro servidor de logs (rsyslog remoto), conservarás las trazas.

1. En el servidor de logs, habilita rsyslog para escuchar en 514.
2. En este servidor, añade algo como:

   ```text
   *.*  @IP_DEL_SERVIDOR_DE_LOGS:514
   ```

3. Reinicia rsyslog.

([Ir al índice](#índice))

### Copias de seguridad

No es 100% seguridad preventiva, pero sí es seguridad de recuperación. Si algo sale mal, necesitas backup. Usa la herramienta que prefieras (borg, restic, duplicity, rsnapshot…) y si la copia sale del servidor, **cifra** los datos.

([Ir al índice](#índice))

### Contacto

En el README original se indicaba que, si alguien veía algo que faltaba o estaba mal, abriera una *issue* o mandara un *pull request* en GitHub. En tu repositorio puedes dejar una nota similar:

> Si encuentras errores en esta traducción o quieres añadir nuevas secciones, abre una issue o un PR en este repositorio.

([Ir al índice](#índice))

### Enlaces útiles

El original recopilaba algunos enlaces que iban cambiando con el tiempo: documentación de distros, benchmarks del CIS, wiki de Arch Linux (seguridad), etc. Puedes dejar una pequeña lista de referencia:

- Benchmarks del CIS
- Documentación de seguridad de tu distribución
- Wiki de Arch Linux – Security
- Repo Ansible relacionado: https://github.com/moltenbit/How-To-Secure-A-Linux-Server-With-Ansible

([Ir al índice](#índice))

### Agradecimientos

A todas las personas que aportaron información, correcciones y ejemplos en el repositorio original “How To Secure A Linux Server”.

([Ir al índice](#índice))

## Licencia

Este documento es una **traducción al español** del original “How To Secure A Linux Server”, publicado bajo licencia **Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)**.

Esta traducción se distribuye bajo la **misma licencia**. Debes:

1. Mantener la atribución al autor original.
2. Compartir cualquier obra derivada bajo la misma licencia.

Más información: https://creativecommons.org/licenses/by-sa/4.0/

([Ir al índice](#índice))
