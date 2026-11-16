# Investigación: cómo endurecen Linux las herramientas y guías de referencia (2024-2026)

> Objetivo: decidir *qué* controles aplicar en cada nivel y *cómo* aplicarlos sin
> romper sistemas. Fuentes consultadas en noviembre de 2026; las URLs se verificaron.

## Resumen ejecutivo

- **CIS Benchmarks** son la referencia de facto: perfiles **Level 1** (seguro "sin romper", base de cualquier servidor) y **Level 2** (defensa en profundidad, puede afectar funcionalidad), cada uno en variante **Server** y **Workstation**. → Nuestros niveles *básico/medio* ≈ L1 Server y *máximo* ≈ L2 Server.
- **OpenSCAP + SCAP Security Guide (ComplianceAsCode)** implementan CIS, STIG, PCI-DSS, ANSSI… como contenido ejecutable (auditoría XCCDF/OVAL + remediaciones Bash/Ansible). Son la mejor forma de **validar** lo que hace el script.
- **Ubuntu Security Guide (USG)** es la vía oficial (Ubuntu Pro) para CIS/STIG en Ubuntu: `usg audit` / `usg fix` con perfiles `cis_level1_server`, `cis_level2_server`, etc. y *tailoring*.
- **DISA STIG** es más estricto (militar); aporta reglas de auditd, banners, bloqueo de cuentas y FIPS. Tomamos ideas para *máximo*, no el conjunto completo.
- **Lynis** sólo audita (no cambia nada) y da un "hardening index": ideal como verificación externa antes/después.
- Los scripts comunitarios (**konstruktoid/hardening**, **ovh/debian-cis**, **dev-sec**) enseñan patrones prácticos: un check por control con estado *audit/apply*, drop-ins en lugar de editar ficheros, admitir IP de administración en el firewall, y que la idempotencia es imprescindible (konstruktoid reconoce no serlo).
- **ssh-audit** y sus guías definen la criptografía SSH moderna (curve25519/sntrup/ML-KEM, AES-GCM/ChaCha20, MACs *etm*, moduli ≥ 3072, RSA ≥ 3072).
- Ninguna fuente cubre un **modo pánico/respuesta a incidentes**: lo diseñamos a partir de prácticas de IR (capturar evidencia **antes** de cambiar nada, aislar red salvo IP admin, bloquear cuentas, auditd inmutable).

## Detalle por fuente

### 1. CIS Benchmarks (Ubuntu 24.04 LTS, RHEL 9)
- **Enfoque**: guía prescriptiva con cientos de recomendaciones (filesystems, servicios, red, logging/auditd, accesos, PAM, SSH, permisos). Cada una con *rationale*, *audit* y *remediation*. Perfiles L1/L2 × Server/Workstation.
- **Fortalezas**: consenso de la industria; base de auditorías (PCI, ISO 27001); muy detallado.
- **Debilidades**: PDF largo; algunas reglas son agresivas para servidores reales (particiones separadas, `noexec` en /tmp, auditd que *detiene* el sistema si se llena el disco); no trae automatización propia (la versión automatizada es CIS-CAT/USG/SSG).
- **Qué tomamos**: la mayoría de controles de sysctl, módulos de kernel, permisos, PAM (pwquality/faillock), login.defs, auditd (reglas de identidad, sudoers, tiempo, red, módulos, privilegiados), SSH, cron/at, banners. Mapeo: básico/medio ≈ L1 Server, máximo ≈ L2 Server.
- **Desviaciones conscientes**: `admin_space_left_action = suspend` (CIS pide `halt`); no se reparticiona el disco (sólo se endurecen opciones de montaje si ya existen las particiones).
- URLs: https://www.cisecurity.org/benchmark/ubuntu_linux · https://www.cisecurity.org/benchmark/red_hat_linux

### 2. OpenSCAP + SCAP Security Guide (ComplianceAsCode/content)
- **Enfoque**: contenido SCAP (data streams XCCDF/OVAL) generado desde reglas en YAML; perfiles CIS, STIG, PCI-DSS, HIPAA, ANSSI…; genera *fix scripts* Bash y *playbooks* Ansible. `oscap xccdf eval --profile … --remediate`.
- **Fortalezas**: estándar NIST, informes HTML, trazabilidad regla→benchmark, soporte oficial en RHEL (`scap-security-guide`), tailoring.
- **Debilidades**: curva de aprendizaje; remediación "todo o nada" que puede romper cosas; en Debian/Ubuntu el contenido va por detrás.
- **Qué tomamos**: verificación posterior (README) y la idea de IDs estables por control con reporte por estado.
- URLs: https://www.open-scap.org/security-policies/scap-security-guide/ · https://github.com/ComplianceAsCode/content

### 3. Ubuntu Security Guide (USG)
- **Enfoque**: herramienta oficial de Canonical (Ubuntu Pro) basada en SSG: `usg audit cis_level1_server`, `usg fix …`, `usg generate-tailoring` para personalizar.
- **Fortalezas**: soporte oficial; perfiles CIS L1/L2 Server/Workstation y DISA STIG para 24.04.
- **Debilidades**: requiere suscripción Pro; sólo Ubuntu; `fix` aplica mucho de golpe.
- **Qué tomamos**: el modelo "auditar → personalizar → aplicar" y su uso como validación.
- URLs: https://documentation.ubuntu.com/security/compliance/usg/cis-comply/ · https://documentation.ubuntu.com/security/compliance/usg/cis-benchmarks/ · https://documentation.ubuntu.com/security/compliance/usg/cis-customize/

### 4. DISA STIG
- **Enfoque**: guías del Departamento de Defensa de EE. UU. (RHEL 9 STIG, Ubuntu 22.04/24.04 STIG) con severidades CAT I/II/III.
- **Fortalezas**: muy estrictas; foco en auditoría, autenticación, FIPS, banners legales, bloqueo de sesión.
- **Debilidades**: pensadas para entornos gubernamentales; algunas medidas (FIPS, smartcard) no aplican a la mayoría.
- **Qué tomamos**: reglas auditd adicionales, `audit=1` en arranque, `-e 2` (inmutable), TMOUT, cuentas inactivas, banners.
- URL: https://public.cyber.mil/stigs/

### 5. Lynis (CISOfy)
- **Enfoque**: auditoría local *sin cambios* en shell; cientos de tests; "hardening index" y sugerencias.
- **Fortalezas**: portable, sin dependencias, rápido, multi-distro. ~16.7k estrellas.
- **Debilidades**: no remedia; las sugerencias son genéricas.
- **Qué tomamos**: modo `--audit` sin cambios con índice de cumplimiento, y Lynis como verificación externa.
- URLs: https://cisofy.com/lynis/ · https://github.com/CISOfy/lynis

### 6. konstruktoid/hardening
- **Enfoque**: script Bash para Ubuntu 22.04/24.04 con módulos (sysctl, ssh, auditd, ufw, PAM…), configurable por variables (`FW_ADMIN`, `SSH_GRPS`, `SSH_PORT`).
- **Fortalezas**: práctico y completo; variable de IP admin para no quedarse fuera.
- **Debilidades**: su README advierte que **no es idempotente** y no está mantenido activamente (recomienda su colección Ansible); sólo Ubuntu; sin dry-run real ni rollback.
- **Qué tomamos**: idea de `--admin-ip`, módulos numerados, drop-ins de sysctl/modprobe. Corregimos: idempotencia, dry-run y rollback.
- URL: https://github.com/konstruktoid/hardening

### 7. ovh/debian-cis
- **Enfoque**: un script por control CIS (Debian 11/12/13), cada uno con estado `disabled|audit|enabled` y resumen de conformidad; usado en producción por OVH.
- **Fortalezas**: granularidad, modo auditoría, configuración por control, ~1.1k estrellas.
- **Debilidades**: sólo Debian; cientos de ficheros; sin backups/rollback integrados.
- **Qué tomamos**: el motor *check/apply* por control, el modo audit y el índice de conformidad final.
- URL: https://github.com/ovh/debian-cis

### 8. dev-sec (ansible-collection-hardening)
- **Enfoque**: roles Ansible `os_hardening`, `ssh_hardening`, `nginx_hardening`, `mysql_hardening`, con tests InSpec (baselines).
- **Fortalezas**: idempotente, multi-distro, valores por defecto sensatos y probados; ~5.5k estrellas.
- **Debilidades**: requiere Ansible; no es un script autónomo.
- **Qué tomamos**: valores SSH/sysctl razonables, drop-ins, separación por roles y atención a no romper (p. ej. no tocar forwarding en routers/Docker).
- URL: https://github.com/dev-sec/ansible-collection-hardening

### 9. trimstray/the-practical-linux-hardening-guide
- **Enfoque**: guía didáctica que explica el *porqué* de cada medida (basada en CIS/STIG), con políticas por área. ~10.9k estrellas; última actividad nov-2024.
- **Fortalezas**: explicación clara; buena para comentarios del código.
- **Debilidades**: no es una herramienta; parte del contenido es antiguo.
- **Qué tomamos**: el estilo de explicar el riesgo de cada control (cada control del script lleva su "por qué").
- URL: https://github.com/trimstray/the-practical-linux-hardening-guide

### 10. ssh-audit (jtesta) y guías de hardening SSH
- **Enfoque**: auditor de servidores/clientes SSH (algoritmos, claves, CVEs) con guías por distro.
- **Guía Ubuntu 24.04**: KEX `sntrup761x25519`, `curve25519`, DH group16/18; cifrados AES-GCM/ChaCha20 (prioridad AES-256); MACs `*-etm`; `RequiredRSASize 3072`; eliminar moduli < 3072 bits.
- **Qué tomamos**: listas de algoritmos (más `mlkem768x25519-sha256` de OpenSSH 9.9+), intersectadas con `ssh -Q` para no romper versiones antiguas; limpieza de moduli; en RHEL se respeta *crypto-policies* en lugar de fijar algoritmos a mano.
- URLs: https://github.com/jtesta/ssh-audit · https://www.ssh-audit.com/hardening_guides.html

## Principios de diseño derivados
1. **Nunca dejar al administrador fuera**: validación `sshd -t`, no deshabilitar contraseñas sin claves, firewall con temporizador de reversión automática, IP admin siempre permitida.
2. **Auditar antes de aplicar**: `--audit` y `--dry-run` con diff de cada fichero.
3. **Drop-ins y backups**: no editar ficheros del paquete; todo cambio se registra en un MANIFEST reversible.
4. **Idempotencia**: cada control comprueba antes de actuar; relanzar sólo informa "YA_CUMPLE".
5. **Gradualidad**: 4 niveles acumulativos, con advertencias explícitas de qué puede romper cada uno.
