#!/usr/bin/env bash
# =============================================================================
#  harden.sh — Hardening modular de Linux por niveles
#  Debian 11/12/13, Ubuntu 22.04/24.04, RHEL/Rocky/Alma 8/9/10
#
#  Niveles (acumulativos: cada nivel incluye los anteriores):
#    1 basico  : bajo riesgo, sin downtime (sysctl seguros, permisos, SSH
#                 básico, logs persistentes, sudo con log, core dumps...).
#    2 medio   : equilibrio (firewall con puertos en uso, auditd, política de
#                 contraseñas, faillock, crypto SSH moderna, servicios legacy fuera,
#                 actualizaciones automáticas de seguridad, MAC en enforcing).
#    3 maximo  : agresivo, tipo CIS Level 2 (salida filtrada, /tmp noexec,
#                 USB-storage fuera, AIDE, auditd inmutable, root SSH fuera...).
#    4 panico  : LOCKDOWN para incidentes (evidencias primero, firewall cerrado
#                 salvo SSH desde IP admin con rollback automático, servicios
#                 mínimos, cuentas no-admin bloqueadas...).
#
#  Inspirado en: CIS Benchmarks, OpenSCAP/SSG, Ubuntu USG, DISA STIG, Lynis,
#  konstruktoid/hardening, ovh/debian-cis, dev-sec, ssh-audit (ver INVESTIGACION.md)
# =============================================================================
set -Eeuo pipefail
umask 077

BASE_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
# shellcheck source=lib/all.sh
source "$BASE_DIR/lib/all.sh"

CONFIG_FILE="$BASE_DIR/conf/hardening.conf"
ROLLBACK_DIR=""
ACTION="harden"

# --- Manejo de errores ----------------------------------------------------------
# set -E hace que el trap ERR se herede en funciones y subshells: cada fallo
# deja traza con archivo:línea y comando. Los controles se aíslan en subshells,
# así que un fallo puntual no detiene el resto del hardening.
# shellcheck disable=SC2329  # invocada desde trap
on_err() {
  local rc=$1 line=$2 cmd=$3 src=${4:-?}
  # Códigos de retorno intencionados de los controles (3=omitido, 4=pendiente) no son errores
  case "$cmd" in "return "*|"( set -e; "*) return 0 ;; esac
  log_error "Comando fallido (código $rc) en ${src##*/}:${line}: ${cmd}"
}
trap 'on_err $? $LINENO "$BASH_COMMAND" "${BASH_SOURCE[0]}"' ERR

# shellcheck disable=SC2329  # invocada desde trap
cleanup() {
  local rc=$?
  [[ -n "${RUN_TMP:-}" && -d "$RUN_TMP" ]] && rm -rf "$RUN_TMP"
  exit "$rc"
}
trap cleanup EXIT
trap 'log_error "Interrumpido por el usuario"; exit 130' INT TERM

usage() {
  cat <<USAGE
${C_BLD}harden.sh v${HARDENING_VERSION}${C_RST} — hardening modular de Linux por niveles

Uso: sudo ./harden.sh [opciones]
     sudo ./harden.sh                      (menú interactivo)

Niveles:
  -l, --level NIVEL       basico | medio | maximo | panico

Modos:
  -n, --dry-run           Muestra qué haría (diffs incluidos) sin cambiar nada
  -a, --audit             Sólo comprueba y reporta el cumplimiento del nivel
      --rollback DIR      Revierte una ejecución (DIR = /var/backups/hardening/<ts>-<nivel>,
                          'last' = la última, 'all' = todas en orden inverso)
      --confirm-firewall  Confirma el firewall y cancela su rollback automático
      --precheck          Sólo el pre-check de cargas críticas (BD, Docker, K8s, VPN, web...)
      --list-controls     Lista qué tocaría cada nivel (sin root, sin cambios). Con --level X
                          sólo ese nivel; admite --only/--skip y --format
      --format F          Formato de --list-controls: text (defecto) | md | json | csv
      --list-backups      Lista ejecuciones previas con backup
      --list-modules      Lista los módulos disponibles

Seguridad operativa:
      --safe              Omite o suaviza los controles que chocan con las cargas detectadas
                          (reenvío para Docker/VPN, user namespaces para rootless, puertos en
                          escucha, salidas de réplica/LDAP, /tmp exec para Elasticsearch...)

Selección:
      --only m1,m2        Ejecuta sólo esos módulos   (ej: --only ssh,sysctl)
      --skip m1,m2        Omite esos módulos
      --skip-control IDs  Omite controles concretos   (ej: --skip-control SSH-09,FS-05)

Parámetros:
      --admin-ip CIDR     IP/red de administración (obligatorio en pánico si no se detecta)
      --admin-user U      Usuario(s) administradores que nunca se bloquean (coma)
      --ssh-port P        Puerto(s) SSH (por defecto: autodetectado con sshd -T)
      --allow-in LIST     Puertos entrantes a permitir, ej: "80/tcp,443/tcp"
      --fw-timeout SEG    Segundos para confirmar el firewall antes del rollback (0=off)
      --config FILE       Archivo de configuración (por defecto conf/hardening.conf)
      --report FILE       Copia del reporte (.txt, .md o .json según extensión)

Otros:
  -y, --yes               No interactivo (pánico requiere HARDENING_CONFIRM_WORD=LOCKDOWN)
      --no-backup         NO copia archivos antes de modificarlos (desaconsejado)
      --force             Permite distribuciones no soportadas
  -v, --verbose           Más detalle
  -h, --help              Esta ayuda

Ejemplos:
  ./harden.sh --list-controls --level medio            (sin root)
  ./harden.sh --list-controls --format json > controles.json
  sudo ./harden.sh --precheck --level maximo
  sudo ./harden.sh --level maximo --safe --dry-run
  sudo ./harden.sh --level basico --dry-run
  sudo ./harden.sh --level medio --audit --report /root/audit.md
  sudo ./harden.sh --level maximo --skip firewall --yes
  sudo ./harden.sh --level panico --admin-ip 203.0.113.10/32
  sudo ./harden.sh --rollback /var/backups/hardening/20261115-180000-medio
USAGE
}

# --- Configuración --------------------------------------------------------------
# Primero el archivo de config, después los flags (los flags mandan).
preload_config() {
  local i args=("$@")
  for (( i=0; i<${#args[@]}; i++ )); do
    if [[ "${args[$i]}" == "--config" ]]; then CONFIG_FILE="${args[$((i+1))]:-}"; fi
  done
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=conf/hardening.conf
    source "$CONFIG_FILE"
  fi
}

parse_args() {
  while (( $# )); do
    case "$1" in
      -l|--level)   LEVEL="${2:-}"; shift ;;
      --level=*)    LEVEL="${1#*=}" ;;
      -n|--dry-run) DRY_RUN=1 ;;
      -a|--audit)   AUDIT=1 ;;
      -y|--yes)     ASSUME_YES=1 ;;
      --no-backup)  NO_BACKUP=1 ;;
      --only)       ONLY_MODULES="${2:-}"; shift ;;
      --skip)       SKIP_MODULES="${2:-}"; shift ;;
      --skip-control) SKIP_CONTROLS="${2:-}"; shift ;;
      --admin-ip)   ADMIN_IPS="${ADMIN_IPS:+$ADMIN_IPS }${2//,/ }"; shift ;;
      --admin-user) ADMIN_USERS="${ADMIN_USERS:+$ADMIN_USERS }${2//,/ }"; shift ;;
      --ssh-port)   SSH_PORTS="${2//,/ }"; shift ;;
      --allow-in)   FW_ALLOW_IN="${FW_ALLOW_IN:+$FW_ALLOW_IN }${2//,/ }"; shift ;;
      --fw-timeout) FW_CONFIRM_TIMEOUT="${2:-120}"; shift ;;
      --report)     REPORT_FILE="${2:-}"; shift ;;
      --config)     shift ;;   # ya procesado en preload_config
      --rollback)   ACTION=rollback; ROLLBACK_DIR="${2:-}"; shift ;;
      --confirm-firewall) ACTION=confirm_fw ;;
      --list-backups) ACTION=list_backups ;;
      --list-modules) ACTION=list_modules ;;
      --list-controls) ACTION=list_controls ;;
      --format)     LIST_FORMAT="${2:-text}"; shift ;;
      --format=*)   LIST_FORMAT="${1#*=}" ;;
      --precheck)   ACTION=precheck ;;
      --safe)       SAFE_MODE=1 ;;
      --force)      FORCE_UNSUPPORTED=1 ;;
      -v|--verbose) VERBOSE=1 ;;
      -h|--help)    usage; exit 0 ;;
      *) usage; die "Opción desconocida: $1" ;;
    esac
    shift
  done
  [[ "$FW_CONFIRM_TIMEOUT" =~ ^[0-9]+$ ]] || die "--fw-timeout debe ser un número de segundos"
  case "$LIST_FORMAT" in text|md|json|csv) ;; *) die "--format inválido: $LIST_FORMAT (text|md|json|csv)" ;; esac
  local p
  for p in $SSH_PORTS; do
    if ! [[ "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then die "Puerto SSH inválido: $p"; fi
  done
  for p in $ADMIN_IPS; do valid_cidr "$p" || die "IP/CIDR de administración inválida: $p"; done
}

valid_cidr() {
  local ip=${1%/*} mask=${1#*/}
  [[ "$1" == */* ]] || mask=""
  if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    local o; for o in "${BASH_REMATCH[@]:1}"; do (( o <= 255 )) || return 1; done
    [[ -z "$mask" ]] || { [[ "$mask" =~ ^[0-9]+$ ]] && (( mask <= 32 )); }
  elif [[ "$ip" =~ ^[0-9a-fA-F:]+$ && "$ip" == *:* ]]; then
    [[ -z "$mask" ]] || { [[ "$mask" =~ ^[0-9]+$ ]] && (( mask <= 128 )); }
  else
    return 1
  fi
}

# --- Menú interactivo -------------------------------------------------------------
interactive_menu() {
  local opt
  cat >&2 <<MENU

${C_BLD}=== Hardening de Linux — selecciona nivel ===${C_RST}
  1) ${C_GRN}Básico / Ligero${C_RST}  - bajo riesgo, sin downtime
  2) ${C_BLU}Medio${C_RST}            - equilibrio seguridad/usabilidad
  3) ${C_YLW}Máximo${C_RST}           - agresivo, tipo CIS Level 2
  4) ${C_RED}PÁNICO / Lockdown${C_RST} - incidente: casi todo cerrado
  q) Salir
MENU
  read -r -p "Nivel [1-4]: " opt
  case "$opt" in 1|2|3|4) LEVEL=$opt ;; *) exit 0 ;; esac
  if (( ! DRY_RUN && ! AUDIT )); then
    cat >&2 <<MODE
  Modo:
  a) Auditoría (sólo comprobar, no cambia nada)
  d) Dry-run   (mostrar los cambios exactos, no cambia nada)
  x) Aplicar   (con backup y rollback)
MODE
    read -r -p "Modo [a/d/x] (por defecto d): " opt
    case "$opt" in a|A) AUDIT=1 ;; x|X) : ;; *) DRY_RUN=1 ;; esac
  fi
}

# --- Advertencias por nivel ---------------------------------------------------------
show_warnings() {
  local n=$1
  printf '\n%s=== QUÉ PUEDE ROMPERSE en nivel %s ===%s\n' "$C_BLD$C_YLW" "$(level_name "$n")" "$C_RST" >&2
  cat >&2 <<'W1'
 [básico]  Riesgo bajo. Ojo con: sysctl de red (si el host es router/VPN se detecta
           y se respeta ip_forward); journald persistente usa disco (/var/log/journal);
           sudo pasará a requerir TTY (use_pty) -> scripts con "sudo" sin TTY siguen
           funcionando, pero algunos pipelines raros podrían notarlo.
W1
  (( n >= 2 )) && cat >&2 <<'W2'
 [medio]   * Firewall activado: sólo SSH + puertos YA en escucha (+ --allow-in). Servicios
             que arranquen después en otros puertos quedarán bloqueados.
           * SSH: root sólo con clave; PasswordAuthentication=no SOLO si existe un admin
             con authorized_keys (si no, se omite). Algoritmos legacy fuera: clientes
             muy antiguos (PuTTY < 0.68, Java/jsch viejos) no conectarán.
           * PAM: política de contraseñas (14+ caracteres) y bloqueo tras 5 fallos (15 min).
           * auditd instalado (uso de disco y algo de CPU); avahi/cups-browsed/telnet/tftp fuera.
           * SELinux permisivo->enforcing (sólo si no hay denegaciones AVC recientes).
           * Actualizaciones automáticas de seguridad (sin reinicio automático).
W2
  (( n >= 3 )) && cat >&2 <<'W3'
 [máximo]  * Salida filtrada en el firewall (sólo DNS, NTP, HTTP/S + --allow-out).
           * Root no puede entrar por SSH; reenvíos TCP/agente/X11 deshabilitados
             (rompe túneles SSH, VS Code Remote "port forwarding", Ansible con ProxyJump).
           * /tmp y /dev/shm con noexec (algunos instaladores/JIT fallan); USB-storage,
             firewire, udf (¡Azure usa udf para provisión!) deshabilitados.
           * Reglas de auditd INMUTABLES (-e 2): cambiarlas exige reiniciar.
           * su restringido a un grupo vacío (usa sudo); cron/at sólo root y admins.
           * Cuentas de sistema sin shell; TMOUT=900 en shells; ptrace bloqueado (gdb/strace).
           * AIDE: la base inicial puede tardar >1h en discos grandes (se lanza en segundo plano).
           * Requiere REINICIO para ser completo (parámetros de kernel, GRUB, /tmp).
W3
  (( n >= 4 )) && cat >&2 <<'W4'
 [PÁNICO]  * Se captura evidencia forense (ps, ss, who, last, crontabs, hashes) ANTES de tocar nada.
           * FIREWALL CERRADO entrada y salida: sólo SSH desde --admin-ip / tu IP actual.
             Se arma un ROLLBACK AUTOMÁTICO del firewall si no confirmas a tiempo.
           * Se PARAN todos los servicios que no estén en la lista de esenciales (web, BD,
             Docker, etc. CAERÁN). Cuentas humanas no-admin BLOQUEADAS (incl. claves SSH).
           * user namespaces deshabilitados (contenedores rootless, Chrome sandbox).
           * Pensado para contener un incidente, NO como estado permanente.
W4
  printf '\n' >&2
}

# --- Utilidades de backups ----------------------------------------------------------
list_backups() {
  [[ -d "$BACKUP_ROOT" ]] || { log_info "No hay backups en $BACKUP_ROOT"; return 0; }
  local d
  for d in "$BACKUP_ROOT"/*/; do
    [[ -f "$d/MANIFEST" ]] || continue
    printf '%s  (%s acciones)  %s\n' "${d%/}" "$(grep -vc '^#' "$d/MANIFEST")" "$(sed -n '2p' "$d/MANIFEST")"
  done
}

# --rollback DIR | last (la última ejecución) | all (todas, de la más nueva a la más antigua)
rollback_dispatch() {
  local target=$1 d rc=0
  local -a dirs=()
  case "$target" in
    last|all)
      mapfile -t dirs < <(for d in "$BACKUP_ROOT"/*/; do [[ -f "$d/MANIFEST" ]] && echo "${d%/}"; done | sort -r)
      (( ${#dirs[@]} )) || die "No hay backups en $BACKUP_ROOT"
      [[ "$target" == last ]] && dirs=("${dirs[0]}") ;;
    *) dirs=("$target") ;;
  esac
  log_info "Se revertirán (en este orden): ${dirs[*]}"
  confirm "¿Continuar con el rollback?" || die "Cancelado."
  for d in "${dirs[@]}"; do do_rollback "$d" || rc=$?; done
  return "$rc"
}

acquire_lock() {
  have flock || return 0
  local lock=/run/hardening.lock
  [[ -w /run ]] || lock="${TMPDIR:-/tmp}/hardening.lock"
  exec 9>"$lock"
  flock -n 9 || die "Otra ejecución de harden.sh está en curso."
}

# --- Módulos -----------------------------------------------------------------------
# Cada módulo se registra con register_module (lib/control.sh).

load_modules() {
  local f
  for f in "$BASE_DIR"/modules/*.sh; do
    # shellcheck source=/dev/null
    source "$f"
  done
  mapfile -t MODULES < <(printf '%s\n' "${MODULES[@]}" | sort -t'|' -k1,1n)
}

module_selected() {
  local name=$1
  if [[ -n "$ONLY_MODULES" ]] && ! in_list "$name" "$ONLY_MODULES"; then return 1; fi
  if [[ -n "$SKIP_MODULES" ]] && in_list "$name" "$SKIP_MODULES"; then return 1; fi
  return 0
}

run_modules() {
  local entry order name minlvl desc rc
  for entry in "${MODULES[@]}"; do
    IFS='|' read -r order name minlvl desc <<<"$entry"
    (( LEVEL_NUM >= minlvl )) || continue
    module_selected "$name" || { log_info "Módulo $name omitido por --only/--skip"; continue; }
    log_step "[$order] $name — $desc"
    CURRENT_MODULE=$name
    set +e
    ( set -e; "module_${name//-/_}" )
    rc=$?
    set -e
    if (( rc != 0 )); then
      record_result "MOD-$name" "$minlvl" FALLÓ "Módulo $name abortado" "código $rc, ver harden.log"
      log_error "El módulo $name terminó con error ($rc); se continúa con el resto."
    fi
  done
  CURRENT_MODULE=""
}

# --level opcional (para --list-controls / --precheck): sin él, todos los niveles
parse_level_optional() {
  [[ -n "$LEVEL" ]] || { LEVEL_NUM=0; return 0; }
  LEVEL_NUM=$(level_to_num "$LEVEL")
  (( LEVEL_NUM > 0 )) || die "Nivel inválido: $LEVEL (usa basico|medio|maximo|panico)"
  LEVEL=$(level_name "$LEVEL_NUM")
}

# --- Programa principal ----------------------------------------------------------------
main() {
  preload_config "$@"
  parse_args "$@"
  detect_os

  case "$ACTION" in
    rollback)     [[ -n "$ROLLBACK_DIR" ]] || die "--rollback requiere un directorio, 'last' o 'all'"
                  rollback_dispatch "$ROLLBACK_DIR"; exit $? ;;
    confirm_fw)   is_root || die "Requiere root"; fw_disarm_rollback; exit 0 ;;
    list_backups) list_backups; exit 0 ;;
    list_modules) load_modules; printf '%s\n' "${MODULES[@]}" | awk -F'|' '{printf "%-4s %-12s nivel>=%s  %s\n",$1,$2,$3,$4}'; exit 0 ;;
    list_controls) parse_level_optional; load_modules; list_controls; exit 0 ;;
    precheck)
      parse_level_optional; load_modules; detect_context; print_context
      if (( LEVEL_NUM > 0 )); then log_info "Impactos evaluados para el nivel ${LEVEL} (acumulativo)"
      else log_info "Impactos evaluados para todos los niveles (use --level para filtrar)"; fi
      is_root || log_warn "Sin root la detección es parcial (procesos/puertos de otros usuarios)."
      run_precheck; exit 0 ;;
  esac

  if [[ "$OS_FAMILY" == unknown ]]; then
    (( FORCE_UNSUPPORTED )) || die "Distribución no soportada ($OS_NAME). Usa --force bajo tu responsabilidad."
    log_warn "Distribución no soportada: se continúa por --force."
  fi

  if [[ -z "$LEVEL" ]]; then
    [[ -t 0 ]] || die "Indica --level (basico|medio|maximo|panico) en modo no interactivo."
    interactive_menu
  fi
  LEVEL_NUM=$(level_to_num "$LEVEL")
  (( LEVEL_NUM > 0 )) || die "Nivel inválido: $LEVEL (usa basico|medio|maximo|panico)"
  LEVEL=$(level_name "$LEVEL_NUM")

  if ! is_root; then
    if (( DRY_RUN || AUDIT )); then
      log_warn "No eres root: algunas comprobaciones (shadow, sshd -T, auditctl...) serán incompletas."
    else
      die "Se requiere root para aplicar cambios (usa sudo, o --dry-run / --audit)."
    fi
  fi
  (( NO_BACKUP && ! DRY_RUN && ! AUDIT )) && log_warn "--no-backup: NO podrás hacer rollback de los archivos modificados."

  RUN_TMP=$(mktemp -d "${TMPDIR:-/tmp}/hardening.XXXXXX")
  CTRL_NOTE_FILE="$RUN_TMP/note"; : >"$CTRL_NOTE_FILE"
  acquire_lock
  backup_init
  detect_context
  log_step "harden.sh v${HARDENING_VERSION} — nivel ${C_BLD}${LEVEL}${C_RST} — modo $(run_mode_name)$( ((SAFE_MODE)) && echo ' — --safe')"
  print_context
  load_modules
  # Pre-check de cargas críticas: siempre (también en dry-run y auditoría)
  run_precheck

  if (( ! AUDIT )); then
    show_warnings "$LEVEL_NUM"
    if (( ! DRY_RUN )); then
      local nconf; nconf=$(precheck_conflicts)
      if (( nconf > 0 )); then
        log_warn "El pre-check encontró ${nconf} conflicto(s) con cargas en ejecución y NO se usa --safe."
        confirm "¿Continuar SIN --safe? (responda no y relance con --safe para adaptarlos)" \
          || die "Cancelado. Nada se ha modificado. Sugerencia: añada --safe."
      fi
      if (( LEVEL_NUM == 4 )); then
        confirm_word LOCKDOWN "${C_RED}MODO PÁNICO: servicios y accesos se cortarán.${C_RST}" \
          || die "Confirmación no recibida. Nada se ha modificado."
      else
        confirm "¿Aplicar el nivel ${LEVEL}? (backup en ${RUN_DIR})" || die "Cancelado. Nada se ha modificado."
      fi
    fi
  fi

  run_modules

  (( DRY_RUN || AUDIT )) || changes_collect_apply
  compute_effects
  print_report
  write_report_files
  if (( ! DRY_RUN && ! AUDIT )) && [[ -s "$RUN_DIR/effects.tsv" ]] && grep -q '^reinicio' "$RUN_DIR/effects.tsv"; then
    mark_reboot_required "$(_effect_ids reinicio)"
  fi
  if (( ! DRY_RUN && ! AUDIT )); then
    printf '\n%sRollback:%s sudo bash %s --rollback %s   (o: sudo bash %s/rollback.sh)\n' \
      "$C_BLD" "$C_RST" "$BASE_DIR/harden.sh" "$RUN_DIR" "$RUN_DIR"
    grep -q $'\tPENDIENTE\t' "$RESULTS_FILE" && log_warn "Hay controles PENDIENTES: se recomienda reiniciar en una ventana de mantenimiento."
    printf 'Valida con: %slynis audit system%s  y/o  %soscap xccdf eval --profile cis_server_l1 ...%s (ver README)\n' \
      "$C_BLD" "$C_RST" "$C_BLD" "$C_RST"
  fi
  if grep -q $'\tFALLÓ\t' "$RESULTS_FILE"; then EXIT_CODE=2; fi
  return 0
}

EXIT_CODE=0
main "$@"
exit "$EXIT_CODE"
