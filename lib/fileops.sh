# shellcheck shell=bash
# =============================================================================
# lib/fileops.sh — Escritura de archivos idempotente, atómica y con backup.
#
# POR QUÉ:
#  * Idempotente: si el contenido ya es el deseado no se toca (ni se respalda).
#  * Atómica: se escribe en un temporal del mismo directorio y se hace mv, así
#    nunca queda un sshd_config o un PAM a medio escribir.
#  * Preferimos archivos "drop-in" (sshd_config.d, sysctl.d, modprobe.d,
#    journald.conf.d, sudoers.d...) en lugar de editar el archivo principal:
#    sobreviven a actualizaciones de paquetes y el rollback es borrar un archivo.
# =============================================================================

# write_file <ruta> <modo> [propietario:grupo]   (contenido por stdin)
write_file() {
  local dest=$1 mode=$2 owner=${3:-root:root} tmp
  tmp=$(mktemp "${RUN_TMP:-/tmp}/wf.XXXXXX")
  cat >"$tmp"
  if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    ensure_perms "$dest" "$mode" "$owner"
    return 0
  fi
  if (( DRY_RUN || AUDIT )); then
    log_dry "escribir $dest (modo $mode, $owner)"
    # Diff de lo que SE APLICARÍA (contenido candidato vs actual): consola
    # truncada, completo en changes.diff; nunca contenido de archivos secretos.
    if (( DRY_RUN )); then changes_record_dry "$dest" "$tmp" "$mode" "$owner"; fi
    rm -f "$tmp"
    return 0
  fi
  # Primero el directorio (NEWDIR) y luego el archivo (NEW/FILE): el rollback
  # procesa en orden inverso, así borra el archivo antes de intentar rmdir.
  ensure_dir "$(dirname "$dest")"
  backup_file "$dest" || { rm -f "$tmp"; return 1; }
  install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$tmp" "${dest}.hardening-tmp" \
    && mv -f "${dest}.hardening-tmp" "$dest"
  local rc=$?
  rm -f "$tmp"
  have restorecon && restorecon -q "$dest" 2>/dev/null || true
  (( rc == 0 )) && log_ok "Escrito $dest"
  return "$rc"
}

# ensure_dir <dir>: crea directorios con 755 (el script corre con umask 077) y
# registra los que no existían para que el rollback los elimine si quedan vacíos.
ensure_dir() {
  local d=$1 p missing=()
  p=$d
  while [[ -n "$p" && "$p" != / && ! -d "$p" ]]; do missing=("$p" "${missing[@]}"); p=$(dirname "$p"); done
  (( ${#missing[@]} )) || return 0
  for p in "${missing[@]}"; do
    mkdir -m 755 "$p" || return 1
    record_action NEWDIR "$p"
  done
}

# remove_file <ruta>: elimina (con backup) un archivo.
remove_file() {
  [[ -e "$1" ]] || return 0
  if (( DRY_RUN || AUDIT )); then log_dry "eliminar $1"; return 0; fi
  backup_file "$1" && rm -f "$1"
}

# ensure_perms <ruta> <modo> [propietario:grupo]
ensure_perms() {
  local f=$1 mode=$2 owner=${3:-} cur_mode cur_owner
  [[ -e "$f" ]] || return 0
  cur_mode=$(stat -c '%a' "$f"); cur_owner=$(stat -c '%U:%G' "$f")
  if [[ "$((8#$cur_mode))" -ne "$((8#$mode))" ]]; then
    if (( DRY_RUN || AUDIT )); then log_dry "chmod $mode $f (actual $cur_mode)"
      (( DRY_RUN )) && changes_record_dry_perms "$f" "$mode" "$owner"
    else backup_file "$f"; chmod "$mode" "$f"; fi
  fi
  if [[ -n "$owner" && "$cur_owner" != "$owner" ]]; then
    if (( DRY_RUN || AUDIT )); then log_dry "chown $owner $f (actual $cur_owner)"
      (( DRY_RUN )) && changes_record_dry_perms "$f" "$mode" "$owner"
    else backup_file "$f"; chown "$owner" "$f"; fi
  fi
}

# perms_ok <ruta> <modo_max> [propietario:grupo]: ¿permisos iguales o más estrictos?
perms_ok() {
  local f=$1 maxmode=$2 owner=${3:-} cur
  [[ -e "$f" ]] || return 0
  cur=$(stat -c '%a' "$f")
  # Ningún bit presente en cur que no esté en maxmode
  (( (8#$cur & ~8#$maxmode) == 0 )) || return 1
  [[ -z "$owner" || "$(stat -c '%U:%G' "$f")" == "$owner" ]]
}

# get_config_value <archivo> <clave> [separador_regex]
# Devuelve el ÚLTIMO valor no comentado (case-insensitive en la clave).
get_config_value() {
  local file=$1 key=$2 sep=${3:-'[[:space:]=]+'}
  [[ -r "$file" ]] || return 1
  awk -v k="$key" -v s="$sep" '
    BEGIN{found=0; re="^[[:space:]]*" tolower(k) s}
    match(tolower($0), re) {
      val=substr($0, RSTART+RLENGTH); sub(/[[:space:]]+#.*$/, "", val); sub(/[[:space:]]+$/, "", val)
      found=1
    }
    END{ if(found){print val} else {exit 1} }' "$file"
}

# set_config_value <archivo> <clave> <valor> [separador_salida] [modo]
# Reemplaza la primera línea activa "clave<sep>valor"; elimina duplicados
# activos posteriores; si no existe la añade al final. No toca comentarios.
set_config_value() {
  local file=$1 key=$2 val=$3 osep=${4:-" "} mode=${5:-} owner="root:root" new
  if [[ -e "$file" ]]; then
    mode=${mode:-$(stat -c '%a' "$file")}; owner=$(stat -c '%U:%G' "$file")
  fi
  mode=${mode:-644}
  new=$(awk -v k="$key" -v v="$val" -v o="$osep" '
    BEGIN{done=0; re="^[[:space:]]*" tolower(k) "([[:space:]]|=|$)"}
    tolower($0) ~ re {
      if(!done){ print k o v; done=1 }
      next
    }
    {print}
    END{ if(!done) print k o v }' "$file" 2>/dev/null || printf '%s%s%s\n' "$key" "$osep" "$val")
  printf '%s\n' "$new" | write_file "$file" "$mode" "$owner"
}

# file_has_line <archivo> <regex ERE>
file_has_line() { [[ -r "$1" ]] && grep -Eq -- "$2" "$1"; }

# Opciones de montaje actuales de un punto de montaje (vacío si no es mount).
mount_opts() { # opciones del montaje superior (si hay montajes apilados, el último manda)
  local o; o=$(findmnt -n -o OPTIONS -M "$1" 2>/dev/null | tail -n1 || true)
  [[ -n "$o" ]] || o=$(findmnt -n -o OPTIONS --target "$1" 2>/dev/null | tail -n1 || true)
  printf '%s' "$o"
}
is_mountpoint() { findmnt -n "$1" >/dev/null 2>&1; }
mount_has_opts() { # mount_has_opts <punto> opt1,opt2...
  local opts o; opts=",$(mount_opts "$1"),"
  for o in ${2//,/ }; do [[ "$opts" == *",$o,"* ]] || return 1; done
}
