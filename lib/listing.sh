# shellcheck shell=bash
# =============================================================================
# lib/listing.sh — --list-controls: qué tocaría cada nivel, SIN root y SIN
# modificar nada. Se genera a partir de los metadatos (ctl_meta) que cada
# módulo declara junto a su código: no hay una lista mantenida a mano.
#   Formatos: text (por defecto, agrupado por módulo) | md | json | csv
# =============================================================================

# ¿Incluye la especificación de niveles el nivel n?  spec_has_level "2-3" 3
spec_has_level() {
  local spec=$1 n=$2 lo hi
  if [[ "$spec" == *-* ]]; then lo=${spec%-*}; hi=${spec#*-}; else lo=$spec; hi=4; fi
  (( n >= lo && n <= hi ))
}

# Texto legible del efecto: "no (inmediato)", "sí", "no (recarga sshd)"...
effect_human() {
  local id=$1 cat svc note
  cat=$(meta_effect_cat "$id"); svc=$(meta_effect_svc "$id")
  note=${CMETA_EFFECT[$id]:-}; [[ "$note" == *";"* ]] && note=${note#*;} || note=""
  case $cat in
    reinicio) printf 'sí' ;;
    recarga)  printf 'no (se recarga %s)' "$svc" ;;
    sesion)   printf 'no (nuevas sesiones)' ;;
    ninguno)  printf 'no (no modifica nada)' ;;
    *)        printf 'no (inmediato)' ;;
  esac
  [[ -n "$note" ]] && printf ' — %s' "$note"
  return 0
}

_lvl_marks() { # "B M - -"
  local spec=$1 n out="" marks=(B M X P)
  for n in 1 2 3 4; do
    if spec_has_level "$spec" "$n"; then out+="${marks[$((n-1))]} "; else out+="- "; fi
  done
  printf '%s' "${out% }"
}

# IDs a listar, en orden de módulo, filtrados por nivel y --only/--skip
listed_control_ids() {
  local entry name id
  for entry in "${MODULES[@]}"; do
    IFS='|' read -r _ name _ <<<"$entry"
    module_selected "$name" || continue
    for id in "${CMETA_ORDER[@]}"; do
      [[ "${CMETA_MOD[$id]}" == "$name" ]] || continue
      if (( LEVEL_NUM > 0 )) && ! spec_has_level "${CMETA_LVL[$id]}" "$LEVEL_NUM"; then continue; fi
      echo "$id"
    done
  done
}

_csv() { local s=${1//\"/\"\"}; printf '"%s"' "$s"; }

list_controls() {
  local -a ids=()
  mapfile -t ids < <(listed_control_ids)
  local id n_change=0 n_adv=0 n_high=0 n_boot=0 lvl_label
  for id in "${ids[@]}"; do
    [[ "${CMETA_TYPE[$id]}" == aviso ]] && n_adv=$((n_adv+1)) || n_change=$((n_change+1))
    [[ "${CMETA_RISK[$id]}" == alto ]] && n_high=$((n_high+1))
    [[ "$(meta_effect_cat "$id")" == reinicio ]] && n_boot=$((n_boot+1))
  done
  if (( LEVEL_NUM > 0 )); then lvl_label="$(level_name "$LEVEL_NUM") (acumulativo)"; else lvl_label="todos"; fi
  case "$LIST_FORMAT" in
    json) _list_json "$lvl_label" "${ids[@]}" ;;
    md)   _list_md "$lvl_label" "${ids[@]}" ;;
    csv)  _list_csv "${ids[@]}" ;;
    text|*) _list_text "$lvl_label" "${ids[@]}" ;;
  esac
  if [[ "$LIST_FORMAT" == text ]]; then
    printf '\nTotal: %d controles (%d cambian algo, %d sólo informan) | riesgo alto: %d | requieren reinicio: %d\n' \
      "${#ids[@]}" "$n_change" "$n_adv" "$n_high" "$n_boot"
    printf 'Leyenda niveles: B=básico M=medio X=máximo P=pánico. Formatos: --format text|md|json|csv\n'
  fi
}

_list_text() {
  local label=$1; shift
  local id last="" entry order name desc
  printf '%sControles de harden.sh v%s — nivel: %s%s\n' "$C_BLD" "$HARDENING_VERSION" "$label" "$C_RST"
  for id in "$@"; do
    if [[ "${CMETA_MOD[$id]}" != "$last" ]]; then
      last=${CMETA_MOD[$id]}
      for entry in "${MODULES[@]}"; do
        IFS='|' read -r order name _ desc <<<"$entry"
        [[ "$name" == "$last" ]] && printf '\n%s[%s %s] %s%s\n' "$C_BLD" "$order" "$name" "$desc" "$C_RST"
      done
    fi
    local rc=$C_GRN
    case ${CMETA_RISK[$id]} in medio) rc=$C_YLW ;; alto) rc=$C_RED ;; esac
    printf '  %-7s %s  %-7s riesgo:%s%-5s%s reinicio: %s\n' "$id" "$(_lvl_marks "${CMETA_LVL[$id]}")" \
      "${CMETA_TYPE[$id]}" "$rc" "${CMETA_RISK[$id]}" "$C_RST" "$(effect_human "$id")"
    printf '          %s\n' "${CMETA_DESC[$id]}"
    [[ "${CMETA_FILES[$id]}" != "-" && -n "${CMETA_FILES[$id]}" ]] && printf '          afecta: %s\n' "${CMETA_FILES[$id]}"
    [[ "${CMETA_TYPE[$id]}" == aviso ]] || printf '          puede romper: %s\n' "${CMETA_BREAKS[$id]}"
  done
}

_list_md() {
  local label=$1; shift
  local id d
  echo "# Controles de harden.sh v${HARDENING_VERSION} — nivel: ${label}"
  echo
  echo "Leyenda niveles: B=básico, M=medio, X=máximo, P=pánico (– = no incluido)."
  echo
  echo "| ID | Módulo | Niveles | Tipo | Riesgo | ¿Reinicio? | Descripción | Afecta | Puede romper |"
  echo "|---|---|---|---|---|---|---|---|---|"
  for id in "$@"; do
    d=$(_lvl_marks "${CMETA_LVL[$id]}"); d=${d//-/–}
    printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' "$id" "${CMETA_MOD[$id]}" "$d" "${CMETA_TYPE[$id]}" \
      "${CMETA_RISK[$id]}" "$(effect_human "$id" | sed 's/|/\\|/g')" "${CMETA_DESC[$id]//|/\\|}" \
      "${CMETA_FILES[$id]//|/\\|}" "${CMETA_BREAKS[$id]//|/\\|}"
  done
}

_list_csv() {
  local id n
  echo "id,modulo,niveles,basico,medio,maximo,panico,tipo,riesgo,efecto,servicio_recarga,requiere_reinicio,descripcion,afecta,puede_romper"
  for id in "$@"; do
    printf '%s,%s,%s' "$id" "${CMETA_MOD[$id]}" "$(_csv "${CMETA_LVL[$id]}")"
    for n in 1 2 3 4; do spec_has_level "${CMETA_LVL[$id]}" "$n" && printf ',1' || printf ',0'; done
    printf ',%s,%s,%s,%s,%s,%s,%s,%s\n' "${CMETA_TYPE[$id]}" "${CMETA_RISK[$id]}" "$(meta_effect_cat "$id")" \
      "$(meta_effect_svc "$id")" "$([[ "$(meta_effect_cat "$id")" == reinicio ]] && echo si || echo no)" \
      "$(_csv "${CMETA_DESC[$id]}")" "$(_csv "${CMETA_FILES[$id]}")" "$(_csv "${CMETA_BREAKS[$id]}")"
  done
}

_list_json() {
  local label=$1; shift
  local id first=1 n names=(basico medio maximo panico) lv
  printf '{"version":"%s","level":"%s","controls":[' "$HARDENING_VERSION" "$(_json_escape "$label")"
  for id in "$@"; do
    (( first )) || printf ','
    first=0
    lv=""
    for n in 1 2 3 4; do
      lv+="\"${names[$((n-1))]}\":$(spec_has_level "${CMETA_LVL[$id]}" "$n" && echo true || echo false),"
    done
    printf '{"id":"%s","module":"%s","levels_spec":"%s","levels":{%s},"type":"%s","risk":"%s","effect":"%s","reload_service":"%s","reboot_required":%s,"effect_human":"%s","description":"%s","affects":"%s","breaks":"%s"}' \
      "$id" "${CMETA_MOD[$id]}" "${CMETA_LVL[$id]}" "${lv%,}" "${CMETA_TYPE[$id]}" "${CMETA_RISK[$id]}" \
      "$(meta_effect_cat "$id")" "$(meta_effect_svc "$id")" \
      "$([[ "$(meta_effect_cat "$id")" == reinicio ]] && echo true || echo false)" \
      "$(_json_escape "$(effect_human "$id")")" "$(_json_escape "${CMETA_DESC[$id]}")" \
      "$(_json_escape "${CMETA_FILES[$id]}")" "$(_json_escape "${CMETA_BREAKS[$id]}")"
  done
  printf ']}\n'
}
