# shellcheck shell=bash
# shellcheck disable=SC2034  # variables globales usadas por otros archivos
# =============================================================================
# lib/common.sh — Variables globales, colores, logging y ejecución segura.
#
# POR QUÉ: toda acción que modifica el sistema pasa por run_cmd/write_file.
# Así el modo --dry-run es fiable: si una función no usa estos wrappers, es un
# bug. Esta es la lección principal de scripts "monolíticos" de hardening que
# no tienen forma de previsualizar cambios.
# =============================================================================

HARDENING_VERSION="1.1.0"

# --- Opciones (se sobreescriben con flags o con conf/hardening.conf) ---------
LEVEL="${LEVEL:-}"                 # basico|medio|maximo|panico
LEVEL_NUM="${LEVEL_NUM:-0}"        # 1..4
DRY_RUN="${DRY_RUN:-0}"            # 1 = no cambia nada, sólo muestra
AUDIT="${AUDIT:-0}"                # 1 = sólo comprueba y reporta cumplimiento
ASSUME_YES="${ASSUME_YES:-0}"      # 1 = no interactivo
NO_BACKUP="${NO_BACKUP:-0}"        # 1 = sin copias (desaconsejado)
VERBOSE="${VERBOSE:-0}"
ONLY_MODULES="${ONLY_MODULES:-}"   # lista separada por comas
SKIP_MODULES="${SKIP_MODULES:-}"
REPORT_FILE="${REPORT_FILE:-}"
FORCE_UNSUPPORTED="${FORCE_UNSUPPORTED:-0}"
SAFE_MODE="${SAFE_MODE:-0}"        # 1 = --safe: omitir/suavizar controles que chocan con cargas detectadas
LIST_FORMAT="${LIST_FORMAT:-text}" # --format para --list-controls: text|md|json|csv
DIFF_CONSOLE_LINES="${DIFF_CONSOLE_LINES:-40}"  # líneas de diff por archivo en consola (los archivos van completos)

# --- Parámetros de entorno (conf/hardening.conf documenta cada uno) ----------
ADMIN_USERS="${ADMIN_USERS:-}"             # usuarios que NUNCA se bloquean
ADMIN_IPS="${ADMIN_IPS:-}"                 # IP/CIDR de administración (pánico)
SSH_PORTS="${SSH_PORTS:-}"                 # autodetectado si vacío
SSH_ALLOW_GROUPS="${SSH_ALLOW_GROUPS:-}"   # AllowGroups (máximo) si se define
FW_ALLOW_IN="${FW_ALLOW_IN:-}"             # p.ej. "80/tcp 443/tcp"
FW_ALLOW_OUT="${FW_ALLOW_OUT:-}"           # salidas extra en nivel máximo
FW_AUTO_ALLOW_LISTENING="${FW_AUTO_ALLOW_LISTENING:-1}" # medio: permitir puertos ya en escucha
FW_AUTO_ALLOW_MAXLEVEL="${FW_AUTO_ALLOW_MAXLEVEL:-2}"   # hasta qué nivel se auto-permiten (--safe lo sube a 3)
KEEP_SHELL_USERS="${KEEP_SHELL_USERS:-}"   # cuentas de sistema que conservan su shell (USR-10), p.ej. "postgres"
FW_CONFIRM_TIMEOUT="${FW_CONFIRM_TIMEOUT:-120}"  # seg. antes de revertir firewall (0=desactivar)
LOG_REMOTE_HOST="${LOG_REMOTE_HOST:-}"     # host:puerto para rsyslog remoto
SERVICES_KEEP="${SERVICES_KEEP:-}"         # servicios que nunca se deshabilitan
PANIC_KEEP_SERVICES="${PANIC_KEEP_SERVICES:-}"
PANIC_KILL_SESSIONS="${PANIC_KILL_SESSIONS:-0}"
PANIC_DISABLE_MODULE_LOADING="${PANIC_DISABLE_MODULE_LOADING:-0}"
PANIC_UPDATE="${PANIC_UPDATE:-0}"
PANIC_ALLOW_OUT="${PANIC_ALLOW_OUT:-}"     # p.ej. "udp/53 tcp/443"
PANIC_ALLOW_NO_SSH="${PANIC_ALLOW_NO_SSH:-0}"
AIDE_INIT="${AIDE_INIT:-1}"
ALLOW_USB_STORAGE="${ALLOW_USB_STORAGE:-0}"
IS_ROUTER="${IS_ROUTER:-auto}"             # auto|0|1 (ip_forward/Docker/K8s)

# --- Rutas --------------------------------------------------------------------
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/hardening}"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RUN_DIR:-}"       # directorio de esta ejecución (backups+reportes)
BACKUP_DIR="${BACKUP_DIR:-}" # = RUN_DIR cuando hay backups
RUN_TMP="${RUN_TMP:-}"
LOG_FILE="${LOG_FILE:-}"

# --- Colores (desactivables con NO_COLOR=1 o si no es TTY) -------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YLW=$'\e[33m'; C_BLU=$'\e[34m'
  C_MAG=$'\e[35m'; C_CYN=$'\e[36m'; C_BLD=$'\e[1m'; C_RST=$'\e[0m'
else
  C_RED=''; C_GRN=''; C_YLW=''; C_BLU=''; C_MAG=''; C_CYN=''; C_BLD=''; C_RST=''
fi

# --- Logging ------------------------------------------------------------------
_log() { # _log <color> <etiqueta> <mensaje...>
  local color=$1 tag=$2; shift 2
  printf '%s%-7s%s %s\n' "$color" "$tag" "$C_RST" "$*" >&2
  if [[ -n "$LOG_FILE" && -w "$(dirname "$LOG_FILE")" ]]; then
    printf '%s %-7s %s\n' "$(date '+%F %T')" "$tag" "$*" >>"$LOG_FILE" 2>/dev/null || true
  fi
}
log_info()  { _log "$C_BLU" "[INFO]" "$@"; }
log_ok()    { _log "$C_GRN" "[ OK ]" "$@"; }
log_warn()  { _log "$C_YLW" "[AVISO]" "$@"; }
log_error() { _log "$C_RED" "[ERROR]" "$@"; }
log_dry()   { _log "$C_MAG" "[DRY]" "$@"; }
log_debug() { if (( VERBOSE )); then _log "$C_CYN" "[DEBUG]" "$@"; fi; }
log_step()  { printf '\n%s==> %s%s\n' "$C_BLD$C_CYN" "$*" "$C_RST" >&2
              [[ -n "$LOG_FILE" ]] && printf '\n==> %s\n' "$*" >>"$LOG_FILE" 2>/dev/null || true; }
die()       { log_error "$@"; exit 1; }

# --- Ejecución ----------------------------------------------------------------
# run_cmd: ejecuta un comando o, en dry-run/auditoría, sólo lo muestra.
# Uso: run_cmd systemctl disable --now avahi-daemon
run_cmd() {
  if (( DRY_RUN || AUDIT )); then
    log_dry "$(printf '%q ' "$@")"
    return 0
  fi
  log_debug "+ $*"
  "$@"
}

# run_sh: igual que run_cmd pero para una línea de shell (tuberías, redirecciones).
run_sh() {
  if (( DRY_RUN || AUDIT )); then log_dry "sh -c '$1'"; return 0; fi
  log_debug "+ sh -c $1"
  bash -c "$1"
}

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

# Nivel numérico a partir del nombre (acepta sinónimos y tildes).
level_to_num() {
  case "${1,,}" in
    1|basico|básico|ligero|basic|low) echo 1 ;;
    2|medio|medium|moderado)          echo 2 ;;
    3|maximo|máximo|max|alto|high)    echo 3 ;;
    4|panico|pánico|panic|lockdown)   echo 4 ;;
    *) echo 0 ;;
  esac
}
level_name() {
  case "$1" in 1) echo basico;; 2) echo medio;; 3) echo maximo;; 4) echo panico;; *) echo "?";; esac
}

# Pregunta s/N. Con --yes devuelve "sí" automáticamente.
confirm() { # confirm "pregunta"
  local ans
  if (( ASSUME_YES )); then return 0; fi
  if [[ ! -t 0 ]]; then return 1; fi
  read -r -p "$1 [s/N]: " ans || return 1
  [[ "${ans,,}" =~ ^(s|si|sí|y|yes)$ ]]
}

# Pide escribir una palabra exacta (para acciones peligrosas como el modo pánico).
confirm_word() { # confirm_word PALABRA "mensaje"
  local ans
  if (( ASSUME_YES )) && [[ "${HARDENING_CONFIRM_WORD:-}" == "$1" ]]; then return 0; fi
  if [[ ! -t 0 ]]; then return 1; fi
  read -r -p "$2 Escribe ${C_BLD}$1${C_RST} para continuar: " ans || return 1
  [[ "$ans" == "$1" ]]
}

# Comprueba si un elemento está en una lista separada por espacios o comas.
in_list() { # in_list <elemento> <lista>
  local item=$1 list=${2//,/ } x
  for x in $list; do [[ "$x" == "$item" ]] && return 0; done
  return 1
}

# Ejecuta una función sin abortar por set -e; devuelve su código.
safe_call() { local rc=0; "$@" || rc=$?; return "$rc"; }

trim() { local s=$1; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }
