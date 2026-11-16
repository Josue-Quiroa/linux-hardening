# shellcheck shell=bash
# =============================================================================
# lib/control.sh — Motor de "controles": comprobar -> (aplicar) -> verificar.
#
# POR QUÉ (inspirado en ovh/debian-cis y OpenSCAP): cada control tiene una
# función de COMPROBACIÓN (sin efectos secundarios) y una de APLICACIÓN.
#   * --audit   : sólo se ejecutan las comprobaciones  -> YA_CUMPLE / NO_CUMPLE
#   * --dry-run : comprobación + aplicación "simulada" -> DRY-RUN (muestra qué haría)
#   * normal    : comprobación, aplicación y RE-comprobación -> APLICADO / PENDIENTE / FALLÓ
# Esto da idempotencia (lo que ya cumple no se toca) y un reporte honesto.
#
# Convención de códigos de retorno:
#   check : 0 = cumple, 1 = no cumple, 2 = no aplica (OMITIDO; usar note "motivo")
#   apply : 0 = ok, 3 = omitido por una salvaguarda (note "motivo"),
#           4 = aplicado pero requiere reinicio/acción, otro = FALLÓ
# La aplicación se ejecuta en un subshell con `set -e`: cualquier comando que
# falle aborta SOLO ese control (no todo el hardening) y se reporta FALLÓ.
# =============================================================================

CURRENT_MODULE="${CURRENT_MODULE:-}"
CTRL_NOTE_FILE="${CTRL_NOTE_FILE:-}"
SKIP_CONTROLS="${SKIP_CONTROLS:-}"

# note "texto": añade un detalle al control en curso (aparece en el reporte).
note() {
  if [[ -n "$CTRL_NOTE_FILE" ]]; then printf '%s; ' "$*" >>"$CTRL_NOTE_FILE"; fi
  log_debug "nota: $*"
}
_take_note() {
  local n=""
  if [[ -n "$CTRL_NOTE_FILE" && -s "$CTRL_NOTE_FILE" ]]; then n=$(<"$CTRL_NOTE_FILE"); fi
  [[ -n "$CTRL_NOTE_FILE" ]] && : >"$CTRL_NOTE_FILE"
  n=${n%; }
  printf '%s' "${n//$'\t'/ }"
}

# level_in_spec "2" (>=2) | "2-3" (rango) | "4" ...
level_in_spec() {
  local spec=$1 lo hi
  if [[ "$spec" == *-* ]]; then lo=${spec%-*}; hi=${spec#*-}; else lo=$spec; hi=4; fi
  (( LEVEL_NUM >= lo && LEVEL_NUM <= hi ))
}

# control <ID> <niveles> <descripción> <fn_check> <fn_apply>
control() {
  local id=$1 spec=$2 desc=$3 chk=$4 app=$5 rc=0 arc=0
  level_in_spec "$spec" || return 0
  if in_list "$id" "$SKIP_CONTROLS"; then
    record_result "$id" "$spec" OMITIDO "$desc" "excluido con --skip-control"; return 0
  fi
  _safe_gate "$id" "$spec" "$desc" && return 0
  [[ -n "$CTRL_NOTE_FILE" ]] && : >"$CTRL_NOTE_FILE"
  "$chk" || rc=$?
  case $rc in
    0) record_result "$id" "$spec" YA_CUMPLE "$desc" "$(_take_note)"
       log_ok "[$id] $desc"; return 0 ;;
    2) record_result "$id" "$spec" OMITIDO "$desc" "$(_take_note)"
       log_info "[$id] $desc -> no aplica"; return 0 ;;
  esac
  if (( AUDIT )); then
    record_result "$id" "$spec" NO_CUMPLE "$desc" "$(_take_note)"
    log_warn "[$id] $desc -> NO CUMPLE"; return 0
  fi
  log_info "[$id] $desc -> $( ((DRY_RUN)) && echo 'simulando' || echo 'aplicando')"
  set +e
  ( set -e; "$app" )
  arc=$?
  set -e
  case $arc in
    0)
      if (( DRY_RUN )); then
        record_result "$id" "$spec" DRY-RUN "$desc" "$(_take_note)"
      elif "$chk"; then
        record_result "$id" "$spec" APLICADO "$desc" "$(_take_note)"
      else
        record_result "$id" "$spec" PENDIENTE "$desc" "$(_take_note) (verificar/reiniciar)"
      fi ;;
    3) record_result "$id" "$spec" OMITIDO "$desc" "$(_take_note)"
       log_warn "[$id] omitido por salvaguarda" ;;
    4) record_result "$id" "$spec" "$( ((DRY_RUN)) && echo DRY-RUN || echo PENDIENTE)" "$desc" "$(_take_note) (requiere reinicio)" ;;
    *) record_result "$id" "$spec" FALLÓ "$desc" "$(_take_note) (código $arc)"
       log_error "[$id] $desc -> FALLÓ (código $arc)" ;;
  esac
  return 0
}

# advise <ID> <niveles> <descripción> <fn_check>
# Recomendación que NO se automatiza (riesgo alto o requiere decisión humana).
advise() {
  local id=$1 spec=$2 desc=$3 chk=$4 rc=0
  level_in_spec "$spec" || return 0
  [[ -n "$CTRL_NOTE_FILE" ]] && : >"$CTRL_NOTE_FILE"
  "$chk" || rc=$?
  case $rc in
    0) record_result "$id" "$spec" YA_CUMPLE "$desc" "$(_take_note)"; log_ok "[$id] $desc" ;;
    2) record_result "$id" "$spec" OMITIDO "$desc" "$(_take_note)" ;;
    *) record_result "$id" "$spec" MANUAL "$desc" "$(_take_note)"; log_warn "[$id] $desc -> revisión MANUAL" ;;
  esac
}

# register_module <orden> <nombre> <nivel_min> <descripción>
# El módulo debe definir la función module_<nombre> (guiones -> guiones bajos).
MODULES=()
_META_MODULE=""
register_module() { MODULES+=("$1|$2|$3|$4"); _META_MODULE=$2; }

# -----------------------------------------------------------------------------
# METADATOS DE CONTROLES (fuente única de verdad para --list-controls, el
# pre-check de cargas críticas y el resumen "requiere reinicio / recarga").
# Cada módulo declara, junto a su código, una línea por control:
#
#   ctl_meta ID NIVELES TIPO RIESGO EFECTO "descripción" "afecta" "puede romper"
#
#   NIVELES : igual que en control ("2" = nivel>=2, "2-3" = rango)
#   TIPO    : cambio | aviso   (aviso = sólo informa, nunca modifica)
#   RIESGO  : bajo | medio | alto
#   EFECTO  : inmediato | sesion (nuevos inicios de sesión) | recarga:<servicio>
#             | reinicio | ninguno ; tras ';' puede ir una aclaración
#   afecta  : archivos / servicios / paquetes que toca
# -----------------------------------------------------------------------------
declare -gA CMETA_LVL=() CMETA_TYPE=() CMETA_RISK=() CMETA_EFFECT=() CMETA_DESC=() \
  CMETA_FILES=() CMETA_BREAKS=() CMETA_MOD=()
CMETA_ORDER=()
# shellcheck disable=SC2034  # los CMETA_* se leen en listing.sh, workloads.sh y report.sh
ctl_meta() {
  local id=$1
  [[ -n "${CMETA_LVL[$id]+x}" ]] || CMETA_ORDER+=("$id")
  CMETA_LVL[$id]=$2; CMETA_TYPE[$id]=$3; CMETA_RISK[$id]=$4; CMETA_EFFECT[$id]=$5
  CMETA_DESC[$id]=$6; CMETA_FILES[$id]=${7:-}; CMETA_BREAKS[$id]=${8:-}
  CMETA_MOD[$id]=${_META_MODULE:-general}
}
# Categoría de efecto de un control: inmediato|sesion|recarga|reinicio|ninguno
meta_effect_cat() { local e=${CMETA_EFFECT[$1]:-inmediato}; e=${e%%;*}; printf '%s' "${e%%:*}"; }
meta_effect_svc() { local e=${CMETA_EFFECT[$1]:-}; e=${e%%;*}; [[ "$e" == recarga:* ]] && printf '%s' "${e#recarga:}"; return 0; }

# --- Modo --safe ---------------------------------------------------------------
# SAFE_SKIP[ID]="motivo" lo rellena lib/workloads.sh según las cargas detectadas.
# Con --safe el control se omite (OMITIDO, motivo en el reporte); sin --safe se
# ejecuta normalmente pero el pre-check ya avisó del conflicto.
declare -gA SAFE_SKIP=()
# ctl_excluded <id>: excluido por --skip-control o por --safe (para módulos que
# construyen un archivo compartido y deben dejar fuera esa clave)
ctl_excluded() { in_list "$1" "$SKIP_CONTROLS" || { (( SAFE_MODE )) && [[ -n "${SAFE_SKIP[$1]:-}" ]]; }; }
_safe_gate() { # _safe_gate <id> <spec> <desc>: 0 = omitido por --safe
  (( SAFE_MODE )) || return 1
  [[ -n "${SAFE_SKIP[$1]:-}" ]] || return 1
  record_result "$1" "$2" OMITIDO "$3" "modo --safe: ${SAFE_SKIP[$1]}"
  log_warn "[$1] omitido por --safe: ${SAFE_SKIP[$1]}"
  return 0
}

# control_batch <fn_check> <fn_apply> "ID|niveles|descripción|clave" ...
# Para controles que comparten UN archivo (sysctl.d, sshd_config.d): cada clave
# se comprueba y reporta por separado, pero el archivo se escribe UNA sola vez.
# fn_check lee la clave en $_BKEY; fn_apply recibe las claves pendientes en
# el array global _BFAILING.
_BKEY=""; _BFAILING=()
control_batch() {
  local chk=$1 app=$2 item id spec desc key rc arc=0
  shift 2
  local -a items=() notes=()
  _BFAILING=()
  for item in "$@"; do
    IFS='|' read -r id spec desc key <<<"$item"
    level_in_spec "$spec" || continue
    if in_list "$id" "$SKIP_CONTROLS"; then
      record_result "$id" "$spec" OMITIDO "$desc" "excluido con --skip-control"; continue
    fi
    _safe_gate "$id" "$spec" "$desc" && continue
    [[ -n "$CTRL_NOTE_FILE" ]] && : >"$CTRL_NOTE_FILE"
    _BKEY=$key; rc=0; "$chk" || rc=$?
    case $rc in
      0) record_result "$id" "$spec" YA_CUMPLE "$desc" "$(_take_note)"; log_ok "[$id] $desc" ;;
      2) record_result "$id" "$spec" OMITIDO "$desc" "$(_take_note)" ;;
      *) if (( AUDIT )); then
           record_result "$id" "$spec" NO_CUMPLE "$desc" "$(_take_note)"; log_warn "[$id] $desc -> NO CUMPLE"
         else
           items+=("$item"); notes+=("$(_take_note)"); _BFAILING+=("$key")
           log_info "[$id] $desc -> pendiente"
         fi ;;
    esac
  done
  (( ${#items[@]} )) || return 0
  [[ -n "$CTRL_NOTE_FILE" ]] && : >"$CTRL_NOTE_FILE"
  set +e
  ( set -e; "$app" )
  arc=$?
  set -e
  local gnote i det
  gnote=$(_take_note)
  for i in "${!items[@]}"; do
    IFS='|' read -r id spec desc key <<<"${items[$i]}"
    det="${notes[$i]}"
    # La nota común de la aplicación se adjunta sólo al primer elemento
    (( i == 0 )) && [[ -n "$gnote" ]] && det+="${det:+; }${gnote:0:400}"
    if (( DRY_RUN )); then record_result "$id" "$spec" DRY-RUN "$desc" "$det"; continue; fi
    case $arc in
      0) _BKEY=$key
         if "$chk" >/dev/null 2>&1; then record_result "$id" "$spec" APLICADO "$desc" "$det"
         else record_result "$id" "$spec" PENDIENTE "$desc" "$det (verificar/reiniciar)"; fi ;;
      3) record_result "$id" "$spec" OMITIDO "$desc" "$det" ;;
      4) record_result "$id" "$spec" PENDIENTE "$desc" "$det (requiere reinicio)" ;;
      *) record_result "$id" "$spec" FALLÓ "$desc" "$det (código $arc)" ;;
    esac
  done
  [[ -n "$CTRL_NOTE_FILE" ]] && : >"$CTRL_NOTE_FILE"
  return 0
}
