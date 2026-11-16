# shellcheck shell=bash
# shellcheck disable=SC2034  # variables globales usadas por otros archivos
# =============================================================================
# lib/distro.sh — Detección de distribución y abstracción de paquetes/servicios.
#
# POR QUÉ: Debian/Ubuntu y RHEL/Rocky difieren en gestor de paquetes (apt vs
# dnf), nombre de servicios (ssh vs sshd), firewall por defecto (ufw vs
# firewalld), MAC (AppArmor vs SELinux) y PAM (pam-auth-update vs authselect).
# Los módulos NUNCA llaman a apt/dnf directamente: usan estas funciones.
# =============================================================================

OS_ID=""; OS_VERSION=""; OS_LIKE=""; OS_NAME=""; OS_FAMILY=""; PKG_MGR=""
HAS_SYSTEMD=0; IN_CONTAINER=0; ARCH="$(uname -m)"
_APT_UPDATED=0

detect_os() {
  local f=/etc/os-release
  [[ -r $f ]] || f=/usr/lib/os-release
  [[ -r $f ]] || die "No se encuentra /etc/os-release: distribución no soportada."
  # Se LEE (no se hace source) para no ejecutar código de un archivo externo.
  _osr() { awk -v k="$1" -v q="'" 'index($0, k "=")==1 { v=substr($0, length(k)+2); gsub("^[\"" q "]|[\"" q "]$", "", v); print v; exit }' "$f"; }
  OS_ID=$(_osr ID); OS_VERSION=$(_osr VERSION_ID); OS_LIKE=$(_osr ID_LIKE)
  OS_NAME=$(_osr PRETTY_NAME); OS_NAME=${OS_NAME:-$OS_ID}

  case " $OS_ID $OS_LIKE " in
    *" debian "*|*" ubuntu "*) OS_FAMILY=debian; PKG_MGR=apt ;;
    *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*|*" ol "*)
      OS_FAMILY=rhel
      if have dnf; then PKG_MGR=dnf; else PKG_MGR=yum; fi ;;
    *) OS_FAMILY=unknown; PKG_MGR="" ;;
  esac

  [[ -d /run/systemd/system ]] && HAS_SYSTEMD=1
  # HARDENING_CONTAINER=0|1 fuerza la detección (p.ej. contenedores LXC "de sistema").
  if [[ -n "${HARDENING_CONTAINER:-}" ]]; then IN_CONTAINER=$HARDENING_CONTAINER
  elif have systemd-detect-virt && systemd-detect-virt -cq 2>/dev/null; then IN_CONTAINER=1
  elif [[ -f /.dockerenv || -f /run/.containerenv ]]; then IN_CONTAINER=1
  elif grep -qaE 'container=(docker|podman|lxc)' /proc/1/environ 2>/dev/null; then IN_CONTAINER=1
  fi
}

is_debian() { [[ $OS_FAMILY == debian ]]; }
is_rhel()   { [[ $OS_FAMILY == rhel ]]; }

# Versión mayor (p.ej. "9" de "9.4", "24" de "24.04")
os_major() { echo "${OS_VERSION%%.*}"; }

# ---------------------------------------------------------------------------
# Paquetes
# ---------------------------------------------------------------------------
pkg_installed() { # pkg_installed <paquete>
  case $PKG_MGR in
    apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed" ;;
    dnf|yum) rpm -q "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

pkg_install() { # pkg_install <paq1> [paq2...]  (sólo instala los que faltan)
  local p missing=()
  for p in "$@"; do pkg_installed "$p" || missing+=("$p"); done
  (( ${#missing[@]} )) || return 0
  case $PKG_MGR in
    apt)
      if (( ! _APT_UPDATED )) && ! (( DRY_RUN || AUDIT )); then
        run_cmd env DEBIAN_FRONTEND=noninteractive apt-get update -qq || return 1
        _APT_UPDATED=1
      fi
      run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        --no-install-recommends -o Dpkg::Options::=--force-confold "${missing[@]}" || return 1 ;;
    dnf|yum) run_cmd "$PKG_MGR" -y -q install "${missing[@]}" || return 1 ;;
    *) log_error "Gestor de paquetes desconocido"; return 1 ;;
  esac
  for p in "${missing[@]}"; do record_action PKG_INSTALLED "$p"; done
}

pkg_remove() { # pkg_remove <paq...> (sólo los instalados)
  local p present=()
  for p in "$@"; do pkg_installed "$p" && present+=("$p"); done
  (( ${#present[@]} )) || return 0
  case $PKG_MGR in
    apt) run_cmd env DEBIAN_FRONTEND=noninteractive apt-get purge -y -q "${present[@]}" || return 1 ;;
    dnf|yum) run_cmd "$PKG_MGR" -y -q remove "${present[@]}" || return 1 ;;
  esac
  for p in "${present[@]}"; do record_action PKG_REMOVED "$p"; done
}

# ---------------------------------------------------------------------------
# Servicios (systemd). En contenedores/chroots sin systemd todo devuelve "no".
# ---------------------------------------------------------------------------
# exists/enabled/masked funcionan sin systemd en ejecución (leen los unit files);
# active necesita systemd como PID 1.
svc_exists()  { have systemctl && [[ -n "$(systemctl list-unit-files "$1" --no-legend 2>/dev/null)" ]]; }
svc_active()  { (( HAS_SYSTEMD )) && systemctl is-active --quiet "$1" 2>/dev/null; }
svc_enabled() { have systemctl && systemctl is-enabled --quiet "$1" 2>/dev/null; }
svc_masked()  { have systemctl && [[ "$(systemctl is-enabled "$1" 2>/dev/null)" == masked ]]; }

svc_disable_now() { # deshabilita y para, registrando para rollback
  local u=$1
  svc_exists "$u" || return 0
  if svc_enabled "$u"; then record_action SVC_DISABLED "$u"; fi
  if svc_active "$u"; then record_action SVC_STOPPED "$u"; fi
  run_cmd systemctl disable --now "$u"
}
svc_stop() {
  local u=$1
  svc_active "$u" || return 0
  record_action SVC_STOPPED "$u"
  run_cmd systemctl stop "$u"
}
svc_mask() {
  local u=$1
  svc_masked "$u" && return 0
  record_action SVC_MASKED "$u"
  run_cmd systemctl mask "$u"
}
svc_enable_now() {
  local u=$1
  if (( ! HAS_SYSTEMD )); then log_warn "Sin systemd: no se puede habilitar $u"; return 0; fi
  if (( DRY_RUN )); then run_cmd systemctl enable --now "$u"; return 0; fi
  svc_exists "$u" || { log_warn "Unidad $u no existe"; return 1; }
  if ! svc_enabled "$u"; then record_action SVC_ENABLED "$u"; fi
  run_cmd systemctl enable --now "$u"
}
svc_reload_or_restart() {
  local u=$1
  svc_active "$u" || return 0
  run_cmd systemctl try-reload-or-restart "$u"
}

# Nombre del servicio SSH según distro
ssh_service_name() { if is_debian; then echo ssh; else echo sshd; fi; }
