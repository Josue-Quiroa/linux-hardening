# Guía detallada de harden.sh

> Volver al [README principal](../README.md). Si clonaste el repositorio, da permisos de ejecución con
> `chmod +x harden.sh` (o ejecuta siempre `sudo bash harden.sh ...`).

Framework en **Bash puro** para endurecer servidores **Ubuntu 22.04/24.04, Debian 12/13 y RHEL/Rocky/Alma 8/9**
en cuatro niveles acumulativos: **básico, medio, máximo y pánico (lockdown)**.
Cada control explica *por qué* existe, se puede auditar sin cambiar nada, se respalda antes de tocar
y se puede revertir.

> ⚠️ **Pruebe siempre primero en una VM o con snapshot.** Ejecute `--audit` y `--dry-run` antes de aplicar,
> y mantenga una sesión SSH abierta (o acceso por consola) mientras aplica.

Documentos: [INVESTIGACION.md](INVESTIGACION.md) (fuentes y enfoques) · [ESTRUCTURA.md](ESTRUCTURA.md) (diseño y matriz de niveles).

## Requisitos
- root (o `sudo`), Bash ≥ 4.4, coreutils, awk, findmnt, systemd (recomendado).
- Opcionales según el nivel: `ufw`/`firewalld`/`nft`, `auditd`, `aide`, `apparmor-utils`/`policycoreutils` (el script instala lo necesario si hay red).

## Uso rápido

```bash
sudo ./harden.sh                                   # menú interactivo (nivel → auditar / dry-run / aplicar)
sudo ./harden.sh --level medio --audit             # ¿cuánto cumplo ya? (no cambia nada)
sudo ./harden.sh --level medio --dry-run           # qué cambiaría, con diffs
sudo ./harden.sh --level medio                     # aplicar (pide confirmación)
sudo ./harden.sh --level maximo --yes --report /root/hardening.json
sudo ./harden.sh --level medio --only ssh,sysctl   # sólo algunos módulos
sudo ./harden.sh --level maximo --skip firewall --skip-control FS-05,SSH-19
sudo ./harden.sh --level panico --admin-ip 203.0.113.10/32
sudo ./harden.sh --rollback last                   # deshacer la última ejecución
sudo ./harden.sh --rollback all                    # deshacer todas (de la más nueva a la más antigua)
./harden.sh --list-controls --level medio          # qué tocaría el nivel medio (sin root, sin cambios)
./harden.sh --list-controls --format json > controles.json   # también md | csv
sudo ./harden.sh --precheck --level maximo         # sólo detectar cargas críticas y conflictos
sudo ./harden.sh --level maximo --safe --dry-run   # adaptar automáticamente a lo detectado
./harden.sh --help
```

Configuración persistente: `conf/hardening.conf` (o `--config FICHERO`). Las variables más importantes:
`ADMIN_USERS`, `ADMIN_IPS`, `SSH_PORTS`, `FW_ALLOW_IN`, `FW_ALLOW_OUT`, `IS_ROUTER`, `SERVICES_KEEP`,
`LOG_REMOTE_HOST`, `ALLOW_USB_STORAGE`, `PANIC_*` y (v1.1) `SAFE_MODE`, `FW_AUTO_ALLOW_MAXLEVEL`,
`KEEP_SHELL_USERS`, `DIFF_CONSOLE_LINES`.

Variables de entorno: `HARDENING_CONFIRM_WORD=LOCKDOWN` (pánico con `--yes`), `HARDENING_CONTAINER=0|1`
(forzar la detección de contenedor), `NO_COLOR=1`.

Módulos: `evidence, updates, sysctl, filesystems, ssh, firewall, users, services, logging, mac, integrity, misc, lockdown`
(`--list-modules`).

## Qué hace cada nivel y qué puede romper

| Nivel | Para qué | Puede romper |
|---|---|---|
| **básico** | Cualquier servidor o escritorio. Sin riesgo de pérdida de acceso: sysctl de red/kernel seguros, FS raros deshabilitados, SSH sin contraseñas vacías/rhosts, permisos de ficheros críticos, sudo con log, journald persistente, sin core dumps. | Casi nada. Sistemas de ficheros exóticos (hfs, jffs2…) dejan de montarse. |
| **medio** (≈ CIS L1 Server) | Servidores en producción. Firewall deny-by-default (permite SSH y lo que ya escucha), SSH sólo con claves **si hay admin con claves**, criptografía moderna, pwquality ≥ 14, faillock, auditd, AppArmor/SELinux, actualizaciones automáticas de seguridad, banners. | Clientes SSH muy antiguos; contraseñas cortas al cambiarlas; usuarios bloqueados 15 min tras 5 fallos; servicios que escuchen *después* (hay que abrirlos en el firewall); avahi/cups-browsed; SELinux puede requerir reinicio y relabel. |
| **máximo** (≈ CIS L2 Server + STIG) | Servidores expuestos o con datos sensibles. Salida de red restringida (DNS, NTP, HTTP/S), root sin login SSH, sin forwarding/túneles, `/tmp` noexec, USB bloqueado, auditd inmutable, AIDE, TMOUT, `su` restringido. | Túneles SSH/`ssh -L`, agent forwarding, scripts en /tmp (instaladores, algunos `apt`/`pip`), tráfico saliente a otros puertos (SMTP, BBDD remotas: use `FW_ALLOW_OUT`), USB, gdb/strace de usuarios, sesiones inactivas se cierran, cambios en reglas de auditd hasta reiniciar. |
| **pánico** (lockdown) | **Respuesta a incidente**: se sospecha compromiso. Captura evidencia primero, aísla la red salvo la IP admin, bloquea usuarios humanos no admin, para servicios no esenciales, auditd con execve/connect. | **Todo lo que no sea su sesión SSH de administración**: servicios web, BBDD, contenedores rootless, salida a Internet (incluidas actualizaciones), otros usuarios. No es un estado para operar normalmente. Requiere escribir `LOCKDOWN`. |

### Salvaguardas anti-bloqueo
- SSH: drop-in `/etc/ssh/sshd_config.d/01-hardening.conf`, validación `sshd -t` antes y después, verificación `sshd -T`; `PasswordAuthentication no` sólo si algún admin tiene `authorized_keys`; `PermitRootLogin no` sólo si hay admin no-root; **nunca cambia el puerto**; `reload` no corta sesiones.
- Firewall: antes de cambiar se programa una **reversión automática** (por defecto 120 s). Si no confirma (respondiendo `si` o con `sudo ./harden.sh --confirm-firewall`), el firewall vuelve al estado anterior. La IP de su sesión SSH y `--admin-ip` siempre se permiten.
- Pánico: falla de forma segura (FALLÓ) si no hay IP admin detectada ni `--admin-ip`, salvo `PANIC_ALLOW_NO_SSH=1` (acceso sólo por consola).
- No se desactiva `ip_forward` en routers/hosts con Docker/K8s/VPN (detectado o `IS_ROUTER=1`).

## Qué toca cada nivel: `--list-controls`

Lista **sin root y sin modificar nada** cada control con: ID, módulo, niveles en los que actúa,
tipo (cambio/aviso), **riesgo** (bajo/medio/alto), **¿requiere reinicio?** (sí / no — se recarga X /
nuevas sesiones / inmediato), archivos-servicios-paquetes que **afecta** y qué **puede romper**.

```bash
./harden.sh --list-controls                          # todos los niveles (columna B M X P)
./harden.sh --list-controls --level maximo           # sólo lo que aplica máximo (acumulativo)
./harden.sh --list-controls --level medio --only ssh,firewall
./harden.sh --list-controls --format md   > CONTROLES.md
./harden.sh --list-controls --format json | jq '.controls[] | select(.reboot_required)'
./harden.sh --list-controls --format csv  > controles.csv
```

La tabla **no se mantiene a mano**: sale de los metadatos `ctl_meta` que cada módulo declara junto a
su código (ver ESTRUCTURA.md). `tests/check-meta.sh` falla si algún control del código no tiene
metadatos. [CONTROLES.md](CONTROLES.md) es la salida `--format md` de esta versión.

Extracto (`--list-controls --level medio --only ssh`):

```
[30 ssh] Servidor OpenSSH
  SSH-14  - M X P  cambio  riesgo:alto  reinicio: no (se recarga sshd)
          sshd: PasswordAuthentication no (sólo si un admin tiene authorized_keys)
          afecta: /etc/ssh/sshd_config.d/01-hardening.conf
          puede romper: Usuarios que entran con contraseña
```

## Pre-check de cargas críticas y modo `--safe`

Antes de aplicar (y **siempre** en `--dry-run` y `--audit`) el script detecta, sólo leyendo
(unidades systemd habilitadas/activas, procesos, binarios, rutas y puertos en escucha):

| Categoría | Detecta | Controles afectados (ejemplos) | Con `--safe` |
|---|---|---|---|
| Bases de datos | MySQL/MariaDB, PostgreSQL, MongoDB, Redis/Valkey, Elasticsearch/OpenSearch | FW-02 (puerto cerrado en máximo), FW-03 (réplicas), UPD-04 (reinicio de la BD), USR-10 (`su - postgres`), FS-05 (`/tmp` noexec rompe JNA de Elasticsearch), SVC-05 | permite puertos en escucha y salida de réplica, omite UPD-04 y FS-05 (Elastic), conserva la shell de `postgres`, no la para en pánico |
| Contenedores | Docker, containerd, Podman (rootless), Kubernetes (kubelet/k3s/rke2) | SYS-32/33 ip_forward, SYS-26/27 rp_filter, FW-02/03 (cadenas propias, DOCKER-USER, tráfico entre nodos), SYS-41..43 user namespaces, FS-02 (SCTP), PNC-01 (br_netfilter/overlay), SVC-05 | modo router, omite userns/SCTP/bloqueo de módulos, omite el firewall en nodos K8s, no para los runtimes en pánico |
| Web | nginx, Apache, HAProxy, Caddy | FW-02 (80/443 en máximo), FW-03, USR-09/14 (umask, UserDir) | permite puertos en escucha |
| Virtualización | libvirt/KVM | ip_forward (NAT), FW-02, sVirt (MAC-03/04) | modo router |
| Compartición | NFS/Samba servidor, montajes NFS/SMB cliente | SVC-03 (rpcbind), FW-02, FW-03 | conserva rpcbind, permite 2049/111/445 |
| VPN | WireGuard, OpenVPN, IPsec, Tailscale/ZeroTier | reenvío, rp_filter, FW-02/03, FW-04 (admin vía VPN), PNC-01 | modo router, permite UDP de la VPN |
| Correo | Postfix, Exim, Sendmail, Dovecot | FW-03 (25/465/587), FW-02 | permite salida SMTP |
| Directorio | SSSD, slapd, winbind | FW-03 (LDAP/Kerberos: sin ellos no hay login), USR-07, AllowUsers en pánico | permite 389/636/88/464/3268/3269 salientes |
| Monitorización/EDR | node_exporter, Zabbix, Datadog, Wazuh, osquery, Falco, CrowdStrike... | FW-03, SYS-36 (perf/eBPF), LOG-03/04 (socket de auditoría), PNC-01 | permite salidas típicas, omite SYS-36 y PNC-01 |
| Puertos en escucha | cualquier puerto accesible desde la red | FW-02 en máximo, FW-04 | permite los puertos en escucha también en máximo |

```bash
sudo ./harden.sh --precheck                 # sólo el pre-check (todos los niveles)
sudo ./harden.sh --precheck --level maximo  # filtrado al nivel
sudo ./harden.sh --level maximo --safe      # aplicar adaptándose a lo detectado
```

- Sin `--safe`, si hay conflictos el script los muestra y **pide confirmación explícita** antes de aplicar.
- Con `--safe`, cada control omitido queda como `OMITIDO (modo --safe: <carga>: <motivo>)` y las
  suavizaciones (puertos, servicios conservados, modo router) se listan en el reporte (`report.md`,
  `report.json` → `safe_adjustments`, `workloads`).
- Detección basada sólo en un puerto conocido se marca como **"(posible)"**.
- En pánico, `--safe` mantiene corriendo los servicios críticos detectados, pero el lockdown de red sigue
  cerrándolo todo salvo SSH desde la IP admin.

## Reinicio, recarga o efecto inmediato

Cada control declara su efecto en los metadatos; `--list-controls` lo muestra y **al final de cada
ejecución** se imprime:

```
=== EFECTO DE LOS CAMBIOS ===
Requiere reinicio (2): LOG-06, FS-05
Servicios recargados: sshd (SSH-01, SSH-02, ...); auditd (LOG-04, LOG-05)
Efectivo inmediatamente (23): SYS-01, ..., FW-02, USR-02, ...
Efectivo en nuevas sesiones de login (7): USR-06, USR-07, USR-08, USR-09, USR-12, USR-13, MSC-01
```

En dry-run se titula "(si se aplicara)" y en auditoría "(si se corrigiera lo que NO CUMPLE)". Si algo
requiere reinicio al aplicar, se crea `/run/reboot-required` (+ `reboot-required.pkgs`, lo muestran el
motd de Ubuntu y needrestart) y `/run/hardening-reboot-required` con la lista. Un control `PENDIENTE`
siempre cuenta como "requiere reinicio".

| Efecto | Controles | Notas |
|---|---|---|
| **Requiere reinicio** | FS-05 (máximo: `/tmp` tmpfs), LOG-06 (`audit=1` en GRUB), LOG-08 (`-e 2`), MAC-03 (SELinux disabled→permissive + relabel), SSH-92 (crypto-policy: cada servicio TLS/SSH al reiniciarse) | |
| **Parcial: inmediato + reinicio para completar** | FS-01/02/03 (módulos ya cargados siguen hasta reiniciar), FS-04/06/07 (remount en caliente; fstab al arrancar), UPD-04 (kernel/glibc nuevos), PNC-01 (irreversible hasta reiniciar) | el resumen los cuenta como inmediatos |
| **Recarga de servicio** | `sshd`: SSH-01..28, SSH-90, SSH-91 (reload: no corta sesiones) · `auditd`: LOG-04, LOG-05, LOG-07 (augenrules) · `systemd-journald`: LOG-01 · `rsyslog`: LOG-09 | |
| **Nuevas sesiones de login** | USR-06 pwquality, USR-07 faillock, USR-08 login.defs, USR-09 umask, USR-12 su, USR-13 TMOUT, MSC-01 core dumps | las sesiones abiertas no cambian |
| **Inmediato** | sysctl SYS-01..43 (`sysctl -w` + persistente), firewall FW-02..04 (con reversión automática), permisos USR-01/02/14/17, sudo USR-03, cuentas USR-05/10/11/19, servicios SVC-01..05, LOG-02/03, MAC-04, AIDE INT-01/02, MSC-02..06 | |

## Reporte

Al final se muestra una tabla por control con estado `APLICADO, YA_CUMPLE, NO_CUMPLE, DRY-RUN, PENDIENTE (reinicio), OMITIDO (no aplica / salvaguarda), MANUAL (recomendación), FALLÓ`, un índice de cumplimiento y la ruta del directorio de la ejecución con `report.txt`, `report.md`, `report.json` y `harden.log`. Código de salida: `0` ok, `1` error de uso, `2` algún control FALLÓ.

### Cambios en archivos: hashes y diff

- **Al aplicar**: para cada archivo del MANIFEST se compara la copia del backup con el archivo actual:
  **SHA-256 antes/después**, **permisos y propietario antes/después** y **diff unificado** (`diff -u`).
- **En dry-run**: el contenido candidato que se escribiría se compara con el actual (diff de lo que *se
  aplicaría*); los cambios hechos por comandos (ufw, usermod, systemctl...) se muestran como `[DRY] comando`.
- Archivos generados en el directorio de la ejecución: `changes.tsv` (una fila por archivo), `changes.diff`
  (diff **completo**), sección "Cambios en archivos" en `report.md` y campo `changes[]` en `report.json`
  (`sha256_before`, `sha256_after`, `mode_*`, `owner_*`, `secret`, `diff_lines`). La consola trunca cada diff a
  `DIFF_CONSOLE_LINES` (40) líneas.
- **Secretos**: `/etc/shadow`, `/etc/gshadow` (y sus copias `-`), `/etc/security/opasswd`, claves privadas de
  host SSH, `*.key/*.pem`, `user.cfg` de GRUB y la base de AIDE nunca aparecen en diffs: sólo hashes + nota.

Extracto de `report.md`:

```
| `/etc/ssh/sshd_config` | permisos | `9c1e…` | `9c1e…` | 644 root:root → 600 root:root | 0 líneas |  |
| `/etc/gshadow` | modificado | `7d79…` | `c530…` | 640 root:shadow → 640 root:shadow | omitido (secreto) | archivo secreto: diff omitido, sólo hashes |
```

## Backups y rollback

Cada ejecución real guarda en `/var/backups/hardening/<fecha>-<nivel>/`:
`files/` (copias originales), `MANIFEST` (todas las acciones), `rollback.sh` (autónomo), logs y reportes.

```bash
sudo ./harden.sh --list-backups
sudo ./harden.sh --rollback last
sudo ./harden.sh --rollback /var/backups/hardening/20261115-180000-medio
sudo /var/backups/hardening/20261115-180000-medio/rollback.sh   # sin el repositorio
```

El rollback restaura ficheros y directorios, borra lo creado, rehabilita servicios, desbloquea usuarios, elimina grupos y la tabla nft de lockdown, restaura el estado del firewall y la crypto-policy, y recarga sysctl/sshd/auditd/journald. **No desinstala paquetes** (quedan listados en el MANIFEST). Cambios de fstab, GRUB, SELinux o `audit -e 2` requieren reinicio para revertirse por completo.

## Cómo probar de forma segura
1. Cree una VM igual a producción (o un snapshot / `lvcreate --snapshot` / snapshot del proveedor cloud).
2. `sudo ./harden.sh --level medio --audit --report /root/antes.md`
3. `sudo ./harden.sh --level medio --dry-run | less -R` y revise los diffs.
4. Con **una segunda sesión SSH abierta**, aplique: `sudo ./harden.sh --level medio`.
5. Desde otra terminal abra una **nueva** conexión SSH antes de confirmar el firewall.
6. Reinicie la VM y verifique que arranca, que hay SSH y que sus servicios funcionan.
7. Pruebe el rollback: `sudo ./harden.sh --rollback last` y compare.
8. Suba de nivel gradualmente. Pánico sólo se ensaya en VM.

## Validación externa posterior

```bash
# Lynis (sólo auditoría)
sudo apt install lynis   # o: sudo dnf install lynis (EPEL)
sudo lynis audit system  # compare el "Hardening index" antes/después

# OpenSCAP + SCAP Security Guide (RHEL/Rocky/Alma)
sudo dnf install openscap-scanner scap-security-guide
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
  --report /root/oscap.html /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml   # ssg-rhel9-ds.xml / ssg-almalinux9-ds.xml
oscap info /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml   # lista de perfiles disponibles

# Ubuntu (con Ubuntu Pro)
sudo pro enable usg && sudo apt install usg
sudo usg audit cis_level1_server      # o cis_level2_server

# SSH
ssh-audit localhost
```

## Limitaciones conocidas
- Probado en chroots de Ubuntu 24.04, Debian 12 y Rocky 9 (dry-run, audit y aplicación en sandbox sin systemd); **no** en VMs reales con systemd: valide ufw/firewalld, auditd, journald y servicios en su VM antes de producción.
- Docker publica puertos saltándose ufw/firewalld (se avisa en FW-05; use la cadena `DOCKER-USER`).
- Algunos cambios sólo surten efecto tras reiniciar (fstab, GRUB `audit=1`, SELinux, `audit -e 2`, módulos ya cargados).
- La contraseña de GRUB y la eliminación de compiladores quedan como recomendaciones manuales.
- La base de AIDE se genera en segundo plano y puede tardar mucho en discos grandes.
- `admin_space_left_action = suspend` en auditd (CIS sugiere `halt`): desviación consciente para no apagar servidores.
- Con `-e 2` (máximo) las reglas de auditd no se pueden cambiar hasta reiniciar, ni siquiera por el rollback.
- Repositorios apt con `trusted=yes` sólo se reportan; no se modifican.
- El rollback no desinstala paquetes instalados por el script.
- No crea particiones separadas (/var, /var/log…): sólo endurece las que ya existan.
- Distribuciones distintas de las soportadas requieren `--force`.
- Pre-check: la detección es heurística (unidades, procesos, binarios, rutas, puertos). Sin root no ve los
  procesos/puertos de otros usuarios; cargas en contenedores sin unidad en el host pueden no verse;
  una detección "sólo por puerto" puede ser otro programa (se marca "(posible)").
- `--safe` adapta los controles con conflictos conocidos, no garantiza que nada se rompa: revise el pre-check.
  En firewalld antiguo (< 0.9, sin políticas) FW-03 se omite igualmente.
- Diffs en dry-run: sólo para archivos escritos con contenido completo; si varios controles editan el mismo
  archivo por claves (p. ej. `login.defs`), en dry-run se ve un diff parcial por control; al aplicar se ve el
  diff final real.
