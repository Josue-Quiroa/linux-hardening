# Estructura y diseño del framework

## Árbol de directorios

```
linux-hardening/
├── harden.sh                  # punto de entrada: flags, menú, flujo, rollback
├── conf/hardening.conf        # configuración comentada (admins, IPs, puertos, pánico…)
├── lib/
│   ├── all.sh                 # carga todas las librerías
│   ├── common.sh              # valores por defecto, logs, run_cmd (respeta dry-run), confirmaciones
│   ├── distro.sh              # detección de SO/familia, gestor de paquetes, systemd, contenedor, svc_*
│   ├── context.sh             # admins, IP del cliente SSH, puertos SSH, ¿router?
│   ├── backup.sh              # directorio de ejecución, backups, MANIFEST, rollback
│   ├── rollback-template.sh   # rollback.sh autónomo copiado en cada backup
│   ├── fileops.sh             # write_file atómico/idempotente, permisos, fstab/montajes
│   ├── control.sh             # motor de controles (control, control_batch, advise)
│   ├── report.sh              # resultados, resumen, report.txt/.md/.json
│   ├── fwsafety.sh            # red de seguridad del firewall (reversión automática)
│   ├── listing.sh             # --list-controls (text/md/json/csv) desde los metadatos
│   ├── workloads.sh           # pre-check de cargas críticas y modo --safe
│   └── changes.sh             # SHA-256, permisos y diff de cada archivo (apply y dry-run)
├── modules/                   # se cargan en orden numérico
│   ├── 00-evidence.sh  10-updates.sh  20-sysctl.sh  25-filesystems.sh
│   ├── 30-ssh.sh       40-firewall.sh 50-users.sh   60-services.sh
│   └── 70-logging.sh   80-mac.sh      85-integrity.sh 90-misc.sh 99-lockdown.sh
├── tests/check-meta.sh        # todo control del código tiene metadatos
├── .github/workflows/shellcheck.yml   # CI: shellcheck + list-controls + dry-run sin root
├── README.md  LICENSE  CHANGELOG.md
└── docs/
    ├── GUIA.md                # guía de uso detallada
    ├── INVESTIGACION.md       # fuentes y enfoques (CIS, OpenSCAP, Lynis, STIG...)
    ├── ESTRUCTURA.md          # este documento
    └── CONTROLES.md           # = ./harden.sh --list-controls --format md
```

## Motor de controles

Cada control es `control ID NIVEL "descripción" check_fn apply_fn`:

| Función | Retorno | Significado |
|---|---|---|
| `check` | 0 / 1 / 2 | cumple / no cumple / no aplica (→ OMITIDO) |
| `apply` | 0 / 3 / 4 | aplicado / omitido por salvaguarda / requiere reinicio (→ PENDIENTE) |

- `NIVEL`: `2` = nivel ≥ 2; `2-3` = sólo medio y máximo (p. ej. el firewall de pánico es distinto).
- `apply` se ejecuta en `( set -e; apply )`: un error marca **FALLÓ** sin abortar el resto; cada módulo corre además en su propia subshell.
- `control_batch` agrupa claves de un mismo fichero (sysctl, sshd): se evalúa cada clave por separado y el fichero se escribe una sola vez.
- `advise` registra recomendaciones **MANUAL** (cosas que no conviene automatizar).

### Metadatos de control (fuente única de verdad)

Cada módulo declara, junto al código del control:

```bash
ctl_meta ID NIVELES TIPO RIESGO EFECTO "descripción" "afecta" "puede romper"
#  TIPO: cambio|aviso   RIESGO: bajo|medio|alto
#  EFECTO: inmediato | sesion | recarga:<servicio> | reinicio | ninguno  [;aclaración]
```

Los controles generados desde tablas (sysctl `SYSCTL_RULES`, directivas SSH `SSH_ID_LIST`) registran sus
metadatos automáticamente desde esa misma tabla. De los metadatos salen:
`--list-controls`, el filtrado por nivel del pre-check, el resumen final "requiere reinicio / servicios
recargados / inmediato" y el aviso `/run/reboot-required`. `tests/check-meta.sh` garantiza cobertura total.

### Pre-check y `--safe`

`lib/workloads.sh` contiene dos tablas: `WL_DEFS` (cómo detectar cada carga: unidades, procesos, binarios,
rutas, puertos) y `WL_IMPACTS` (carga → IDs afectados → acción `--safe` → motivo). Acciones:
`skip` (registra `SAFE_SKIP[ID]`; el motor marca OMITIDO y los módulos con archivo compartido excluyen la
clave), `router`, `fwin`, `fwout:<puertos>`, `keep`, `pkeep`, `shell:<usuarios>` (ajustan variables antes de
ejecutar los módulos) y `warn` (sólo aviso).

### Trazabilidad de archivos

`write_file` en dry-run pasa el contenido candidato a `changes_record_dry`; al aplicar,
`changes_collect_apply` recorre `FILE|`/`NEW|` del MANIFEST y compara la copia de `files/` con el archivo
actual. Resultado: `changes.tsv`, `changes.diff` (completo) y secciones en `report.md`/`report.json`.
Los archivos que casan con `SECRET_FILE_RE` sólo aportan hashes.
- Estados del reporte: `APLICADO, YA_CUMPLE, NO_CUMPLE (audit), DRY-RUN, PENDIENTE, OMITIDO, MANUAL, FALLÓ`.

## Flujo de ejecución

```
preload_config → parse_args → (menú interactivo si no hay --level)
→ is_root / detect_os / detect_context → advertencias del nivel
→ confirmación (sí/no; en pánico escribir LOCKDOWN) → lock (/run/hardening.lock)
→ backup_init (/var/backups/hardening/<ts>-<nivel>/) → load_modules (+ metadatos)
→ PRE-CHECK de cargas críticas (siempre) → --safe: SAFE_SKIP y ajustes
→ advertencias del nivel → si hay conflictos sin --safe: confirmación extra
→ run_modules (orden numérico, filtros --only/--skip/--skip-control/--safe)
→ cambios en archivos (sha256/permisos/diff) → efecto (reinicio/recarga/inmediato)
→ reporte en pantalla + report.{txt,md,json}, changes.{tsv,diff}, precheck.tsv
→ /run/reboot-required si procede → código de salida (2 si hubo FALLÓ)

Acciones que no aplican nada: --list-controls (sin root), --precheck, --list-modules, --list-backups.
```

## Matriz de niveles (acumulativos)

| Área (módulo) | Básico (1) | Medio (2) | Máximo (3) | Pánico (4) | Efecto |
|---|---|---|---|---|---|
| Evidencias (00) | – | – | – | EVD-01 captura forense (procesos, sockets, sesiones, cron, claves, SUID, `dpkg --verify`/`rpm -Va`, hashes) **antes** de cambiar nada | ninguno |
| Actualizaciones (10) | GPG de repos; aviso de pendientes | actualizaciones automáticas sólo seguridad (sin reinicio); aplica parches de seguridad | aplica todas las actualizaciones | no actualiza salvo `PANIC_UPDATE=1` | inmediato (kernel nuevo: reinicio) |
| Kernel/sysctl (20) | ASLR, protected_*, dmesg/kptr, syncookies, sin source-route/redirects (SYS-01..21) | rp_filter, log_martians, ptrace=1, BPF sin privilegios, sin forwarding si no es router (SYS-22..33) | kexec, sysrq, perf, userfaultfd, ptrace=2, sin RA IPv6 si no hay SLAAC (SYS-34..40) | sin user namespaces (SYS-41..43) | inmediato (sysctl -w) + persistente |
| Filesystems (25) | FS raros (cramfs, hfs…), sticky bit | dccp/sctp/rds/tipc, /dev/shm y /tmp nodev,nosuid, /var/tmp | usb-storage/firewire/thunderbolt, /tmp noexec, /home nodev | = máximo | módulos: inmediato p/ nuevas cargas; montajes: remount + fstab; /tmp tmpfs: **reinicio** |
| SSH (30) | contraseñas vacías, rhosts, MaxAuthTries 4, LogLevel VERBOSE, keepalive, permisos de claves | sin X11, root sólo con clave, banner, sólo claves **si hay admin con authorized_keys**, KEX/cifrados/MACs modernos (RHEL: crypto-policy) | root no (si hay admin no-root), sin forwarding/túneles, MaxSessions, RSA ≥ 3072, moduli ≥ 3072 | AllowUsers=admins, MaxAuthTries 3, LoginGraceTime 30 | recarga sshd (no corta sesiones); crypto-policy RHEL: **reinicio** de servicios |
| Firewall (40) | sólo aviso | ufw/firewalld/nft: deny entrante, SSH + puertos en escucha | además límite SSH y **salida restringida** (53/123/80/443/DHCP) | **lockdown nft**: sólo SSH desde IP admin, todo lo demás DROP (entrada, salida y forward) | inmediato (reversión automática) |
| Usuarios/PAM (50) | permisos passwd/shadow/cron, sudo use_pty + log, UID 0 | contraseñas vacías, pwquality (≥14), faillock 5/900 s, login.defs, umask 027 | shells de sistema nologin, inactividad 45 d, `su` restringido, TMOUT, homes 750, world-writable | faillock 3/1800 s, **bloqueo de usuarios humanos no admin** | inmediato / nuevas sesiones (PAM, login.defs, umask, TMOUT) |
| Servicios (60) | informe de puertos abiertos | telnet/rsh/tftp…, avahi, cups-browsed | lista ampliada, desinstala clientes legados | para todo lo no esencial (allowlist) | inmediato |
| Logging (70) | journald persistente | permisos /var/log, auditd + reglas tipo CIS, syslog remoto (si se configura) | auditd.conf, `audit=1` en GRUB, reglas inmutables `-e 2` | reglas execve/connect | recarga journald/auditd/rsyslog; `audit=1` y `-e 2`: **reinicio** |
| MAC (80) | aviso de estado | AppArmor / SELinux activo (SELinux escalonado: permissive + autorelabel) | perfiles a enforce / SELinux enforcing si no hay AVC | = máximo | SELinux disabled→permissive: **reinicio**; enforce: inmediato |
| Integridad (85) | – | – | AIDE (base en segundo plano) + chequeo diario | `aide --check` a evidencias | inmediato (base AIDE en segundo plano) |
| Varios (90) | core dumps off, ctrl-alt-del | banners legales ES/EN, grub.cfg 600, sincronización horaria | cron.allow/at.allow | = máximo | inmediato / nuevas sesiones (core dumps) |
| Lockdown (99) | – | – | – | `kernel.modules_disabled` (opt-in) y guía de respuesta a incidentes | inmediato; modules_disabled hasta reiniciar |

La columna **Efecto** resume si hace falta reiniciar; el detalle por control está en `--list-controls`
(columna "¿Reinicio?") y en [GUIA.md → "Reinicio, recarga o efecto inmediato"](GUIA.md#reinicio-recarga-o-efecto-inmediato).

Referencia aproximada: básico ≈ "seguro en cualquier servidor", medio ≈ CIS L1 Server, máximo ≈ CIS L2 Server + ideas STIG, pánico = contención de incidente (no es un estado para operar normalmente).

## Backups y rollback

- Cada ejecución real crea `/var/backups/hardening/<AAAAMMDD-HHMMSS>-<nivel>/` con:
  `files/` (copias con permisos), `MANIFEST`, `rollback.sh` (autónomo), `harden.log`, reportes y, en pánico, `evidence/`.
- `MANIFEST` (una línea por acción, se revierte en orden inverso):
  `FILE` (fichero/directorio modificado → restaurar), `NEW`/`NEWDIR` (creado → borrar), `SVC_DISABLED/STOPPED/MASKED/ENABLED`,
  `USER_LOCKED`, `USER_SHELL`, `GROUP_ADDED`, `NFT_TABLE`, `FW_STATE|backend|activo|habilitado`, `CRYPTO_POLICY`, `PKG_INSTALLED/REMOVED` (informativo).
- `--rollback last|all|<dir>`; `all` revierte todas las ejecuciones de la más nueva a la más antigua. También se puede ejecutar `rollback.sh` directamente (útil si el repo ya no está).
- Tras restaurar se recargan sysctl, sshd (validando `sshd -t`), reglas de auditd, journald y ufw.
- `--dry-run` y `--audit` usan `/tmp/hardening-<ts>-dryrun|audit` y **no escriben nada en /etc**.

## Abstracción de distribución

| Aspecto | Debian/Ubuntu | RHEL/Rocky/Alma |
|---|---|---|
| Detección | `/etc/os-release` (`ID`, `ID_LIKE`) leído con awk, sin `source` | ídem |
| Paquetes | apt-get / dpkg | dnf / rpm |
| Firewall | ufw (fallback nftables) | firewalld (fallback nftables) |
| Auto-updates | unattended-upgrades (sólo security) | dnf-automatic (`upgrade_type=security`) |
| PAM faillock | perfiles `pam-auth-update` | `authselect … with-faillock` |
| Cripto SSH | algoritmos explícitos en drop-in | `update-crypto-policies` (DEFAULT:NO-SHA1) |
| MAC | AppArmor | SELinux |
| Permisos shadow | 640 root:shadow | 000 root:root |
| GRUB | drop-in en `/etc/default/grub.d` + update-grub | `grubby --update-kernel=ALL` |

Los contenedores (`IN_CONTAINER`, forzable con `HARDENING_CONTAINER=0|1`) y sistemas sin systemd marcan como OMITIDO lo que no aplica (sysctl de kernel, servicios, montajes).
