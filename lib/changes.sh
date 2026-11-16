# shellcheck shell=bash
# =============================================================================
# lib/changes.sh — Trazabilidad de cambios en archivos: SHA-256 antes/después,
# permisos/propietario y diff unificado.
#
# POR QUÉ: "qué cambió exactamente" es lo primero que pregunta un auditor o un
# compañero tras un hardening. Ya existe la copia de cada archivo en el backup,
# así que al final se compara copia vs. actual. En --dry-run el contenido
# candidato que write_file habría escrito se compara con el actual.
#
# Archivos generados en el directorio de la ejecución:
#   changes.tsv   una fila por archivo (hashes, permisos, nº de líneas de diff)
#   changes.diff  diff unificado COMPLETO de todos los archivos
# La consola muestra los diffs truncados a DIFF_CONSOLE_LINES líneas.
# Los archivos secretos (/etc/shadow, gshadow, opasswd, claves privadas...)
# NUNCA se incluyen en diffs: sólo hashes y una nota.
# =============================================================================

SECRET_FILE_RE='^/etc/(g?shadow-?|security/opasswd|sudoers\.d/.*\.secret)$|^/etc/ssh/ssh_host_[a-z0-9]+_key$|\.(key|pem|p12|pfx)$|^/boot/grub2?/user\.cfg$|^/etc/grub\.d/|/private/|^/var/lib/aide/'

is_secret_file() { [[ "$1" =~ $SECRET_FILE_RE ]]; }

_sha() { # hash de archivo; '-' si no existe; 'dir' si es directorio
  if [[ -d "$1" ]]; then echo dir
  elif [[ -e "$1" ]]; then sha256sum "$1" 2>/dev/null | awk '{print $1}' || echo '?'
  else echo -; fi
}
_perm() { [[ -e "$1" ]] && stat -c '%a' "$1" 2>/dev/null || echo -; }
_owner() { [[ -e "$1" ]] && stat -c '%U:%G' "$1" 2>/dev/null || echo -; }

# _diff_files <ruta_lógica> <antes> <después>: diff -u con etiquetas a/ b/
_diff_files() {
  local path=$1 a=$2 b=$3
  [[ -e "$a" ]] || a=/dev/null
  [[ -e "$b" ]] || b=/dev/null
  if [[ -d "$a" || -d "$b" ]]; then
    diff -ruN "$a" "$b" 2>/dev/null | sed -e '/^diff -ruN /d' -e "s#^--- ${a}#--- a${path}#" -e "s#^+++ ${b}#+++ b${path}#" || true
  else
    diff -u --label "a${path}" --label "b${path}" "$a" "$b" 2>/dev/null || true
  fi
}

# _emit_change <ruta> <acción> <sha_a> <sha_b> <modo_a> <modo_b> <prop_a> <prop_b> <archivo_diff|""> <nota>
_emit_change() {
  local path=$1 act=$2 sa=$3 sb=$4 ma=$5 mb=$6 oa=$7 ob=$8 dfile=$9 nota=${10:-} secret=0 lines=0
  is_secret_file "$path" && secret=1
  [[ -n "${RUN_DIR:-}" ]] || return 0
  if (( secret )); then
    nota="${nota:+$nota; }archivo secreto: diff omitido, sólo hashes"
  elif [[ -n "$dfile" && -s "$dfile" ]]; then
    lines=$(wc -l <"$dfile")
    { printf '# ===== %s (%s) =====\n' "$path" "$act"; cat "$dfile"; printf '\n'; } >>"$RUN_DIR/changes.diff"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$act" "$sa" "$sb" "$ma" "$mb" "$oa" "$ob" "$secret" "$lines" "$nota" \
    >>"$RUN_DIR/changes.tsv"
  # Consola: resumen + diff truncado
  printf '        %s[%s]%s %s  sha256 %s → %s' "$C_CYN" "$act" "$C_RST" "$path" "${sa:0:12}" "${sb:0:12}" >&2
  [[ "$ma" != "$mb" || "$oa" != "$ob" ]] && printf '  permisos %s %s → %s %s' "$ma" "$oa" "$mb" "$ob" >&2
  printf '\n' >&2
  if (( secret )); then
    printf '          (secreto: no se muestra el contenido)\n' >&2
  elif (( lines > 0 && DIFF_CONSOLE_LINES > 0 )); then
    sed -n "1,${DIFF_CONSOLE_LINES}p" "$dfile" | sed 's/^/          /' >&2
    (( lines > DIFF_CONSOLE_LINES )) && printf '          … (%d líneas más en %s/changes.diff)\n' "$((lines - DIFF_CONSOLE_LINES))" "$RUN_DIR" >&2
  fi
  return 0
}

# --- dry-run: lo llama write_file con el contenido candidato -------------------
changes_record_dry() { # <destino> <temporal_candidato> <modo> <propietario>
  local dest=$1 cand=$2 mode=$3 owner=$4 d act ma oa sb
  sb=$(_sha "$cand")
  # Varios controles pueden proponer el MISMO contenido final (p. ej. modprobe.d): mostrarlo una vez
  if [[ -s "${RUN_DIR:-}/changes.tsv" ]] && awk -F'\t' -v p="$dest" -v h="$sb" '$1==p && $4==h {f=1} END{exit !f}' "$RUN_DIR/changes.tsv"; then
    printf '        (mismo contenido propuesto que ya se mostró para %s)\n' "$dest" >&2; return 0
  fi
  d=$(mktemp "${RUN_TMP:-/tmp}/cd.XXXXXX")
  if [[ -e "$dest" ]]; then act=modificar; ma=$(_perm "$dest"); oa=$(_owner "$dest")
  else act=crear; ma=-; oa=-; fi
  is_secret_file "$dest" || _diff_files "$dest" "$dest" "$cand" >"$d"
  _emit_change "$dest" "$act (propuesto)" "$(_sha "$dest")" "$sb" "$ma" "$(printf '%o' "$((8#$mode))")" "$oa" "$owner" "$d" "contenido candidato"
  rm -f "$d"
}
changes_record_dry_perms() { # <ruta> <modo_nuevo> <prop_nuevo>
  local f=$1 m=$2 o=${3:-}
  [[ -n "${RUN_DIR:-}" ]] || return 0
  m=$(printf '%o' "$((8#$m))")
  [[ -n "$o" ]] || o=$(_owner "$f")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "permisos (propuesto)" "$(_sha "$f")" "$(_sha "$f")" \
    "$(_perm "$f")" "$m" "$(_owner "$f")" "$o" "$(is_secret_file "$f" && echo 1 || echo 0)" 0 "" >>"$RUN_DIR/changes.tsv"
}

# --- aplicación real: compara backup vs actual a partir del MANIFEST ----------
changes_collect_apply() {
  [[ -n "${BACKUP_DIR:-}" && -f "$BACKUP_DIR/MANIFEST" ]] || return 0
  local type path before d act sa sb ma mb oa ob nota n=0
  local -A seen=()
  : >"$RUN_DIR/changes.tsv"; : >"$RUN_DIR/changes.diff"
  printf '\n%s=== CAMBIOS EN ARCHIVOS (sha256, permisos y diff; completo en %s/changes.diff) ===%s\n' "$C_BLD" "$RUN_DIR" "$C_RST" >&2
  d=$(mktemp "${RUN_TMP:-/tmp}/cd.XXXXXX")
  while IFS='|' read -r type path _; do
    [[ "$type" == FILE || "$type" == NEW ]] || continue
    [[ -n "${seen[$path]:-}" ]] && continue
    seen[$path]=1
    before="$BACKUP_DIR/files$path"; nota=""
    if [[ "$type" == NEW ]]; then before=/nonexistent; fi
    if [[ "$type" == FILE && ! -e "$before" && ! -L "$before" ]]; then nota="sin copia (--no-backup)"; fi
    sa=$(_sha "$before"); sb=$(_sha "$path")
    ma=$(_perm "$before"); mb=$(_perm "$path"); oa=$(_owner "$before"); ob=$(_owner "$path")
    if [[ "$type" == NEW ]]; then act=creado
    elif [[ ! -e "$path" ]]; then act=eliminado
    elif [[ "$sa" == "$sb" && "$ma" == "$mb" && "$oa" == "$ob" && "$sa" != dir ]]; then continue   # se respaldó pero no cambió
    elif [[ "$sa" == "$sb" && "$sa" != dir ]]; then act=permisos
    else act=modificado; fi
    : >"$d"
    if ! is_secret_file "$path" && [[ -z "$nota" ]]; then _diff_files "$path" "$before" "$path" >"$d"; fi
    if [[ "$sa" == dir && ! -s "$d" ]]; then
      [[ "$ma" == "$mb" && "$oa" == "$ob" ]] && continue
      act=permisos
    fi
    _emit_change "$path" "$act" "$sa" "$sb" "$ma" "$mb" "$oa" "$ob" "$d" "$nota"
    n=$((n+1))
  done <"$BACKUP_DIR/MANIFEST"
  rm -f "$d"
  (( n )) || printf '        (ningún archivo modificado)\n' >&2
  return 0
}

# Resumen de changes.tsv para el reporte en consola de dry-run
changes_print_dry_summary() {
  [[ -s "${RUN_DIR:-}/changes.tsv" ]] || return 0
  printf '\n%sArchivos que se modificarían:%s %d (diffs completos en %s/changes.diff)\n' "$C_BLD" "$C_RST" \
    "$(wc -l <"$RUN_DIR/changes.tsv")" "$RUN_DIR"
}
