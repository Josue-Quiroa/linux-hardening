# shellcheck shell=bash
# =============================================================================
# lib/backup.sh — Copias de seguridad, manifiesto y registro para rollback.
#
# POR QUÉ: un hardening sin vuelta atrás es un riesgo operativo. Cada archivo
# se copia ANTES de tocarlo (una sola vez por ejecución, preservando permisos,
# propietario y contexto SELinux con cp -a) y cada acción no-archivo (servicio
# deshabilitado, usuario bloqueado, tabla nft creada...) queda en MANIFEST.
# El script rollback.sh generado en el directorio del backup lo deshace todo
# aunque el repositorio del hardening ya no exista.
#
# Formato de MANIFEST (una acción por línea, separador '|'):
#   FILE|/ruta            -> existía; copia en files/ruta
#   NEW|/ruta             -> lo creamos nosotros; el rollback lo borra
#   NEWDIR|/dir           -> directorio creado; se borra si queda vacío
#   SVC_DISABLED|unidad   -> se re-habilita
#   SVC_STOPPED|unidad    -> se vuelve a arrancar
#   SVC_MASKED|unidad     -> se desenmascara
#   SVC_ENABLED|unidad    -> se deshabilita
#   USER_LOCKED|usuario   -> se desbloquea
#   USER_SHELL|usuario|shell_anterior
#   NFT_TABLE|familia nombre -> se elimina
#   FW_STATE|backend|activo_antes(0/1)|habilitado_antes(0/1)
#   GROUP_ADDED|grupo     -> se elimina
#   CRYPTO_POLICY|política_anterior -> update-crypto-policies --set
#   PKG_INSTALLED|paq / PKG_REMOVED|paq -> sólo informativo
# =============================================================================

backup_init() {
  if (( DRY_RUN || AUDIT )); then
    RUN_DIR="${RUN_DIR:-${TMPDIR:-/tmp}/hardening-${TS}-$( ((AUDIT)) && echo audit || echo dryrun )}"
    mkdir -p "$RUN_DIR"; chmod 700 "$RUN_DIR"
    BACKUP_DIR=""
  else
    RUN_DIR="${BACKUP_ROOT}/${TS}-$(level_name "$LEVEL_NUM")"
    mkdir -p "$RUN_DIR/files" "$RUN_DIR/evidence"
    chmod 700 "$BACKUP_ROOT" "$RUN_DIR"
    BACKUP_DIR="$RUN_DIR"
    {
      echo "# MANIFEST hardening v${HARDENING_VERSION}"
      echo "# fecha=$(date -Is) nivel=$(level_name "$LEVEL_NUM") host=$(hostname) os=${OS_NAME}"
    } >"$RUN_DIR/MANIFEST"
    install -m 700 "${_HARDENING_LIB_DIR}/rollback-template.sh" "$RUN_DIR/rollback.sh"
  fi
  LOG_FILE="$RUN_DIR/harden.log"
  : >"$LOG_FILE"
  RESULTS_FILE="$RUN_DIR/results.tsv"
  : >"$RESULTS_FILE"
}

# backup_file <ruta>: copia el archivo (una vez por ejecución) antes de cambiarlo.
backup_file() {
  local f=$1
  [[ -n "$BACKUP_DIR" ]] || return 0
  if grep -qxF -e "FILE|$f" -e "NEW|$f" "$BACKUP_DIR/MANIFEST" 2>/dev/null; then return 0; fi
  if [[ -e "$f" || -L "$f" ]]; then
    if (( ! NO_BACKUP )); then
      cp -a --parents "$f" "$BACKUP_DIR/files/" || { log_error "No se pudo respaldar $f"; return 1; }
    fi
    echo "FILE|$f" >>"$BACKUP_DIR/MANIFEST"
  else
    echo "NEW|$f" >>"$BACKUP_DIR/MANIFEST"
  fi
}

# Respaldar las bases de cuentas antes de usermod/groupadd/passwd: así el
# rollback deja passwd/shadow/group (y sus copias "-") exactamente como estaban.
backup_account_db() {
  local f
  for f in /etc/passwd /etc/passwd- /etc/shadow /etc/shadow- /etc/group /etc/group- /etc/gshadow /etc/gshadow- /etc/default/useradd /etc/default/useradd-; do
    backup_file "$f"
  done
}

# record_action <TIPO> <arg...>: registra una acción no-archivo para rollback.
record_action() {
  [[ -n "$BACKUP_DIR" ]] || return 0
  local IFS='|'
  echo "$*" >>"$BACKUP_DIR/MANIFEST"
}

# Ejecuta el rollback de un directorio de backup.
do_rollback() {
  local dir=$1
  [[ -f "$dir/MANIFEST" ]] || die "No existe $dir/MANIFEST: ¿directorio de backup correcto?"
  is_root || die "El rollback requiere root."
  log_step "Rollback desde $dir"
  local script="$dir/rollback.sh"
  [[ -f "$script" ]] || script="${_HARDENING_LIB_DIR}/rollback-template.sh"
  if (( DRY_RUN )); then
    bash "$script" --dry-run "$dir"
  else
    bash "$script" "$dir"
  fi
}
