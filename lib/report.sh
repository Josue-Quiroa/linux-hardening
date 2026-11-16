# shellcheck shell=bash
# =============================================================================
# lib/report.sh — Registro de resultados y reporte final (texto, Markdown, JSON).
#
# POR QUÉ: Lynis demuestra el valor de un "hardening index" y de explicar cada
# hallazgo. Aquí cada control deja una línea con su estado:
#   APLICADO   cambio realizado y verificado
#   YA_CUMPLE  no hacía falta tocar nada
#   NO_CUMPLE  (modo --audit) el sistema no cumple
#   DRY-RUN    se habría aplicado (modo --dry-run)
#   PENDIENTE  aplicado pero requiere reinicio o verificación
#   OMITIDO    no aplica o se omitió por una salvaguarda (ver detalle)
#   MANUAL     recomendación que requiere decisión humana
#   FALLÓ      error al aplicar (ver harden.log)
# =============================================================================

RESULTS_FILE="${RESULTS_FILE:-}"

record_result() { # record_result <id> <niveles> <estado> <desc> <detalle>
  [[ -n "$RESULTS_FILE" ]] || return 0
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${CURRENT_MODULE:-general}" "$1" "$2" "$3" "${4//$'\t'/ }" "${5//$'\t'/ }" >>"$RESULTS_FILE"
}

_status_color() {
  case $1 in
    APLICADO|YA_CUMPLE) printf '%s' "$C_GRN" ;;
    NO_CUMPLE|FALLÓ)    printf '%s' "$C_RED" ;;
    DRY-RUN)            printf '%s' "$C_MAG" ;;
    PENDIENTE|MANUAL)   printf '%s' "$C_YLW" ;;
    *)                  printf '%s' "$C_CYN" ;;
  esac
}

_count_status() { awk -F'\t' -v s="$1" '$4==s{n++} END{print n+0}' "$RESULTS_FILE"; }

print_report() {
  [[ -s "$RESULTS_FILE" ]] || { log_warn "No hay resultados que reportar."; return 0; }
  local mod id spec st desc det last=""
  printf '\n%s======================= REPORTE DE HARDENING =======================%s\n' "$C_BLD" "$C_RST"
  printf 'Host: %s | SO: %s | Nivel: %s | Modo: %s | Fecha: %s\n' \
    "$(hostname)" "$OS_NAME" "$(level_name "$LEVEL_NUM")" "$(run_mode_name)" "$(date '+%F %T')"
  while IFS=$'\t' read -r mod id spec st desc det; do
    if [[ "$mod" != "$last" ]]; then printf '\n%s[%s]%s\n' "$C_BLD" "$mod" "$C_RST"; last=$mod; fi
    printf '  %s%-10s%s %-8s %s' "$(_status_color "$st")" "$st" "$C_RST" "$id" "$desc"
    [[ -n "$det" ]] && printf ' %s(%s)%s' "$C_CYN" "$det" "$C_RST"
    printf '\n'
  done <"$RESULTS_FILE"
  print_report_extras
  print_summary
}

run_mode_name() { if (( AUDIT )); then echo auditoria; elif (( DRY_RUN )); then echo dry-run; else echo aplicar; fi; }

print_summary() {
  local s total ok bad
  printf '\n%sResumen:%s ' "$C_BLD" "$C_RST"
  for s in APLICADO YA_CUMPLE NO_CUMPLE DRY-RUN PENDIENTE OMITIDO MANUAL FALLÓ; do
    printf '%s%s=%s%s  ' "$(_status_color "$s")" "$s" "$(_count_status "$s")" "$C_RST"
  done
  printf '\n'
  ok=$(( $(_count_status YA_CUMPLE) + $(_count_status APLICADO) ))
  bad=$(( $(_count_status NO_CUMPLE) + $(_count_status FALLÓ) + $(_count_status MANUAL) + $(_count_status PENDIENTE) + $(_count_status DRY-RUN) ))
  total=$(( ok + bad ))
  if (( total > 0 )); then
    printf '%sÍndice de cumplimiento (nivel %s): %d%% (%d/%d controles)%s\n' \
      "$C_BLD" "$(level_name "$LEVEL_NUM")" $(( ok * 100 / total )) "$ok" "$total" "$C_RST"
  fi
  printf 'Detalles: %s\n' "$RUN_DIR"
}

_json_escape() { local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/ }; printf '%s' "$s"; }

write_report_files() {
  [[ -s "$RESULTS_FILE" ]] || return 0
  local mod id spec st desc det first=1
  # Texto plano (sin colores)
  NO_COLOR=1 C_RED='' C_GRN='' C_YLW='' C_MAG='' C_CYN='' C_BLD='' C_RST='' print_report >"$RUN_DIR/report.txt" 2>&1 || true
  # Markdown
  {
    echo "# Reporte de hardening — $(hostname)"
    echo
    echo "- **SO:** ${OS_NAME}  "
    echo "- **Nivel:** $(level_name "$LEVEL_NUM") — **Modo:** $(run_mode_name) — **Fecha:** $(date '+%F %T %Z')"
    echo
    echo "| Módulo | ID | Estado | Control | Detalle |"
    echo "|---|---|---|---|---|"
    while IFS=$'\t' read -r mod id spec st desc det; do
      printf '| %s | %s | **%s** | %s | %s |\n' "$mod" "$id" "$st" "${desc//|/\\|}" "${det//|/\\|}"
    done <"$RESULTS_FILE"
    _md_extra_sections
  } >"$RUN_DIR/report.md"
  # JSON
  {
    printf '{"host":"%s","os":"%s","level":"%s","mode":"%s","date":"%s","version":"%s","results":[' \
      "$(_json_escape "$(hostname)")" "$(_json_escape "$OS_NAME")" "$(level_name "$LEVEL_NUM")" \
      "$(run_mode_name)" "$(date -Is)" "$HARDENING_VERSION"
    while IFS=$'\t' read -r mod id spec st desc det; do
      (( first )) || printf ','
      first=0
      printf '{"module":"%s","id":"%s","levels":"%s","status":"%s","control":"%s","detail":"%s"}' \
        "$(_json_escape "$mod")" "$(_json_escape "$id")" "$spec" "$st" "$(_json_escape "$desc")" "$(_json_escape "$det")"
    done <"$RESULTS_FILE"
    printf ']'
    _json_extra_fields
    printf '}\n'
  } >"$RUN_DIR/report.json"
  if [[ -n "$REPORT_FILE" ]]; then
    case "$REPORT_FILE" in
      *.json) cp "$RUN_DIR/report.json" "$REPORT_FILE" ;;
      *.md)   cp "$RUN_DIR/report.md" "$REPORT_FILE" ;;
      *)      cp "$RUN_DIR/report.txt" "$REPORT_FILE" ;;
    esac && log_info "Reporte guardado en $REPORT_FILE"
  fi
}

# =============================================================================
# Efecto de los cambios: reinicio / recarga de servicio / inmediato / sesión.
# Se calcula con los metadatos ctl_meta de cada control y el estado obtenido.
#   aplicar : APLICADO y PENDIENTE (PENDIENTE siempre cuenta como reinicio)
#   dry-run : DRY-RUN  (= lo que pasaría si se aplicara)
#   audit   : NO_CUMPLE (= lo que pasaría al corregirlo)
# =============================================================================
compute_effects() {
  [[ -s "$RESULTS_FILE" ]] || return 0
  local mod id spec st desc det cat svc
  : >"$RUN_DIR/effects.tsv"
  while IFS=$'\t' read -r mod id spec st desc det; do
    case "$st" in
      APLICADO|PENDIENTE) (( DRY_RUN || AUDIT )) && continue ;;
      DRY-RUN)   (( DRY_RUN )) || continue ;;
      NO_CUMPLE) (( AUDIT )) || continue ;;
      *) continue ;;
    esac
    [[ -n "${CMETA_LVL[$id]:-}" ]] || continue
    cat=$(meta_effect_cat "$id"); svc=$(meta_effect_svc "$id")
    [[ "$st" == PENDIENTE ]] && cat=reinicio
    [[ "$cat" == ninguno ]] && continue
    printf '%s\t%s\t%s\n' "$cat" "$svc" "$id" >>"$RUN_DIR/effects.tsv"
  done <"$RESULTS_FILE"
}

_effect_ids() { awk -F'\t' -v c="$1" '$1==c{print $3}' "$RUN_DIR/effects.tsv" | awk '!s[$0]++' | paste -sd, - | sed 's/,/, /g'; }
_effect_count() { awk -F'\t' -v c="$1" '$1==c' "$RUN_DIR/effects.tsv" | wc -l; }
_effect_reloads() { # "sshd (SSH-01, SSH-02); auditd (LOG-04)"
  awk -F'\t' '$1=="recarga"{a[$2]=a[$2] (a[$2]?", ":"") $3} END{for(k in a) printf "%s (%s); ", k, a[k]}' "$RUN_DIR/effects.tsv" | sed 's/; $//'
}

print_effects_summary() {
  [[ -s "$RUN_DIR/effects.tsv" ]] || return 0
  local pre="" reb
  if (( AUDIT )); then pre=" (si se corrigiera lo que NO CUMPLE)"; elif (( DRY_RUN )); then pre=" (si se aplicara)"; fi
  printf '\n%s=== EFECTO DE LOS CAMBIOS%s ===%s\n' "$C_BLD" "$pre" "$C_RST"
  reb=$(_effect_ids reinicio)
  printf '%sRequiere reinicio%s (%d): %s\n' "$C_YLW" "$C_RST" "$(_effect_count reinicio)" "${reb:-ninguno}" | fold -s -w 120
  printf '%sServicios recargados%s: %s\n' "$C_CYN" "$C_RST" "$(_effect_reloads | sed 's/^$/ninguno/')" | fold -s -w 120
  printf '%sEfectivo inmediatamente%s (%d): %s\n' "$C_GRN" "$C_RST" "$(_effect_count inmediato)" "$(_effect_ids inmediato | sed 's/^$/ninguno/')" | fold -s -w 120
  printf '%sEfectivo en nuevas sesiones de login%s (%d): %s\n' "$C_GRN" "$C_RST" "$(_effect_count sesion)" "$(_effect_ids sesion | sed 's/^$/ninguno/')" | fold -s -w 120
  return 0
}

# Extras del reporte de texto: --safe, archivos cambiados (sin diff) y efectos
print_report_extras() {
  local path act sa sb ma mb oa ob sec lines nota
  if (( ${#SAFE_ADJUSTMENTS[@]} )); then
    printf '\n%sModo --safe — omitido/suavizado:%s\n' "$C_BLD" "$C_RST"
    printf '  - %s\n' "${SAFE_ADJUSTMENTS[@]}"
  fi
  if [[ -s "$RUN_DIR/changes.tsv" ]]; then
    printf '\n%sArchivos %s:%s %d (diff completo: %s/changes.diff)\n' "$C_BLD" \
      "$( ((DRY_RUN)) && echo 'que se modificarían' || echo modificados)" "$C_RST" "$(wc -l <"$RUN_DIR/changes.tsv")" "$RUN_DIR"
    while IFS=$'\t' read -r path act sa sb ma mb oa ob sec lines nota; do
      printf '  %-22s %s  sha256 %s → %s' "[$act]" "$path" "${sa:0:12}" "${sb:0:12}"
      [[ "$ma" != "$mb" || "$oa" != "$ob" ]] && printf '  (%s %s → %s %s)' "$ma" "$oa" "$mb" "$ob"
      (( sec )) && printf '  [secreto: sin diff]'
      printf '\n'
    done <"$RUN_DIR/changes.tsv"
  fi
  print_effects_summary
}

# Aviso estándar de "reinicio requerido" (Debian/Ubuntu: motd y needrestart lo
# leen; en RHEL queda en /run/hardening-reboot-required). /run se vacía al reiniciar.
mark_reboot_required() {
  local d=/run
  [[ -d "$d" && -w "$d" ]] || return 0
  [[ -e "$d/reboot-required" ]] || printf '*** System restart required ***\n' >"$d/reboot-required"
  grep -qx hardening "$d/reboot-required.pkgs" 2>/dev/null || echo hardening >>"$d/reboot-required.pkgs"
  printf 'harden.sh %s (%s): reiniciar para completar: %s\n' "$(date '+%F %T')" "$RUN_DIR" "$1" >"$d/hardening-reboot-required"
  log_warn "Reinicio requerido: aviso creado en $d/reboot-required y $d/hardening-reboot-required"
}

# Secciones extra de report.md
_md_extra_sections() {
  local path act sa sb ma mb oa ob sec lines nota
  if [[ -s "$RUN_DIR/precheck.tsv" ]]; then
    echo; echo "## Pre-check: cargas de trabajo críticas"; echo
    echo "| Carga | Evidencia | Controles | Acción | ¿Adaptado por --safe? | Motivo |"
    echo "|---|---|---|---|---|---|"
    awk -F'\t' '{gsub(/\|/,"\\|"); printf "| %s | %s | %s | %s | %s | %s |\n",$2,$3,$4,$5,($6==1?"sí":"no"),$7}' "$RUN_DIR/precheck.tsv"
  fi
  if (( ${#SAFE_ADJUSTMENTS[@]} )); then
    echo; echo "## Modo --safe: controles omitidos o suavizados"; echo
    printf -- '- %s\n' "${SAFE_ADJUSTMENTS[@]}"
  fi
  if [[ -s "$RUN_DIR/effects.tsv" ]]; then
    echo; echo "## Efecto de los cambios"; echo
    echo "- **Requiere reinicio:** $(_effect_ids reinicio | sed 's/^$/ninguno/')"
    echo "- **Servicios recargados:** $(_effect_reloads | sed 's/^$/ninguno/')"
    echo "- **Efectivo inmediatamente:** $(_effect_ids inmediato | sed 's/^$/ninguno/')"
    echo "- **Efectivo en nuevas sesiones:** $(_effect_ids sesion | sed 's/^$/ninguno/')"
  fi
  if [[ -s "$RUN_DIR/changes.tsv" ]]; then
    echo; echo "## Cambios en archivos"; echo
    echo "| Archivo | Acción | SHA-256 antes | SHA-256 después | Permisos antes → después | Diff | Nota |"
    echo "|---|---|---|---|---|---|---|"
    while IFS=$'\t' read -r path act sa sb ma mb oa ob sec lines nota; do
      # shellcheck disable=SC2016  # las comillas invertidas son Markdown
      printf '| `%s` | %s | `%s` | `%s` | %s %s → %s %s | %s | %s |\n' "$path" "$act" "$sa" "$sb" "$ma" "$oa" "$mb" "$ob" \
        "$( ((sec)) && echo 'omitido (secreto)' || echo "$lines líneas")" "${nota//|/\\|}"
    done <"$RUN_DIR/changes.tsv"
    if [[ -s "$RUN_DIR/changes.diff" ]]; then
      echo; echo "### Diff unificado (también en changes.diff)"; echo
      echo '```diff'; cat "$RUN_DIR/changes.diff"; echo '```'
    fi
  fi
}

_json_extra_fields() {
  local first path act sa sb ma mb oa ob sec lines nota key label ev ids act2 applied why det
  printf ',"changes":['
  first=1
  if [[ -s "$RUN_DIR/changes.tsv" ]]; then
    while IFS=$'\t' read -r path act sa sb ma mb oa ob sec lines nota; do
      (( first )) || printf ','
      first=0
      printf '{"path":"%s","action":"%s","sha256_before":"%s","sha256_after":"%s","mode_before":"%s","mode_after":"%s","owner_before":"%s","owner_after":"%s","secret":%s,"diff_lines":%s,"note":"%s"}' \
        "$(_json_escape "$path")" "$(_json_escape "$act")" "$sa" "$sb" "$ma" "$mb" "$oa" "$ob" \
        "$( ((sec)) && echo true || echo false)" "${lines:-0}" "$(_json_escape "$nota")"
    done <"$RUN_DIR/changes.tsv"
  fi
  printf '],"diff_file":"%s"' "$( [[ -s "$RUN_DIR/changes.diff" ]] && _json_escape "$RUN_DIR/changes.diff")"
  printf ',"workloads":['
  first=1
  if [[ -s "$RUN_DIR/precheck.tsv" ]]; then
    while IFS=$'\t' read -r key label ev ids act2 applied why det; do
      (( first )) || printf ','
      first=0
      printf '{"workload":"%s","label":"%s","evidence":"%s","controls":"%s","safe_action":"%s","safe_applied":%s,"reason":"%s","detail":"%s"}' \
        "$key" "$(_json_escape "$label")" "$(_json_escape "$ev")" "$ids" "$(_json_escape "$act2")" \
        "$( [[ "$applied" == 1 ]] && echo true || echo false)" "$(_json_escape "$why")" "$(_json_escape "$det")"
    done <"$RUN_DIR/precheck.tsv"
  fi
  printf '],"safe_mode":%s,"safe_adjustments":[' "$( ((SAFE_MODE)) && echo true || echo false)"
  first=1
  for key in "${SAFE_ADJUSTMENTS[@]}"; do (( first )) || printf ','; first=0; printf '"%s"' "$(_json_escape "$key")"; done
  printf '],"effects":{"reboot":"%s","reload":"%s","immediate":"%s","session":"%s"}' \
    "$( [[ -s "$RUN_DIR/effects.tsv" ]] && _effect_ids reinicio)" "$( [[ -s "$RUN_DIR/effects.tsv" ]] && _json_escape "$(_effect_reloads)")" \
    "$( [[ -s "$RUN_DIR/effects.tsv" ]] && _effect_ids inmediato)" "$( [[ -s "$RUN_DIR/effects.tsv" ]] && _effect_ids sesion)"
}
