# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado [SemVer](https://semver.org/lang/es/).

## [1.1.0] — 2026-11-15

### Añadido
- `--list-controls` (sin root, sin cambios): tabla de todos los controles con niveles, riesgo, si requieren reinicio,
  qué afectan y qué pueden romper. Filtros `--level`, `--only`, `--skip` y formatos `--format text|md|json|csv`.
- Metadatos por control (`ctl_meta`) declarados en cada módulo como fuente única de verdad, y `tests/check-meta.sh`.
- **Pre-check de cargas críticas** (bases de datos, Docker/containerd/Podman/Kubernetes, web, libvirt, NFS/Samba,
  VPN, correo, LDAP/SSSD, agentes de monitorización, puertos en escucha). Se ejecuta siempre; `--precheck` lo ejecuta solo.
- **Modo `--safe`**: omite o suaviza los controles que chocan con las cargas detectadas y lo documenta en el reporte.
  Confirmación extra al aplicar con conflictos sin `--safe`.
- **Trazabilidad de archivos**: SHA-256, permisos y propietario antes/después y diff unificado (`changes.diff`,
  `changes.tsv`, secciones en `report.md` / `report.json`). Diff de lo que *se aplicaría* en `--dry-run`.
  Los archivos secretos sólo muestran hashes.
- Resumen final **"Requiere reinicio / Servicios recargados / Efectivo inmediatamente / Nuevas sesiones"** y aviso
  `/run/reboot-required` cuando procede.
- Nuevas opciones de configuración: `SAFE_MODE`, `FW_AUTO_ALLOW_MAXLEVEL`, `KEEP_SHELL_USERS`, `DIFF_CONSOLE_LINES`.
- CI con GitHub Actions: ShellCheck, `--list-controls` y dry-run/audit sin root.

### Corregido
- `useradd -D` (USR-11) dejaba `/etc/default/useradd` con modo 600 por el `umask 077` del script.
- El rollback de pánico no falla si la tabla nftables de lockdown ya no existe.
- Las consultas de estado de servicios (habilitado/existe) funcionan sin systemd como PID 1, evitando que el rollback
  deshabilitara firewalld en entornos sin systemd.
- Los scripts auxiliares se invocan siempre con `bash`, así que funcionan aunque se pierda el bit de ejecución.

## [1.0.0] — 2026-11-15

### Añadido
- Primera versión: `harden.sh` modular en Bash puro para Debian/Ubuntu y RHEL/Rocky/Alma.
- Cuatro niveles acumulativos: básico, medio (≈ CIS L1), máximo (≈ CIS L2 + STIG) y pánico (lockdown de incidente).
- 13 módulos: evidencias, actualizaciones, sysctl, filesystems, SSH, firewall, usuarios/PAM, servicios, logging/auditd,
  MAC (AppArmor/SELinux), integridad (AIDE), varios y lockdown.
- Modos `--audit` y `--dry-run`, menú interactivo, reporte por control (texto/Markdown/JSON) con índice de cumplimiento.
- Backups con MANIFEST y `rollback.sh` autónomo; `--rollback DIR|last|all`.
- Salvaguardas anti-bloqueo: validación `sshd -t`, claves antes de desactivar contraseñas, reversión automática del
  firewall, IP admin obligatoria en pánico y palabra de confirmación `LOCKDOWN`.
