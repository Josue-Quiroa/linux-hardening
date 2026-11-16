# shellcheck shell=bash
# =============================================================================
# 20-sysctl — Parámetros del kernel (red y memoria)
#
# POR QUÉ: muchos ataques locales (fugas de direcciones del kernel, ptrace de
# procesos ajenos, eBPF sin privilegios, enlaces simbólicos en /tmp) y de red
# (redirects ICMP, source routing, spoofing, SYN flood) se neutralizan con
# sysctl. Fuentes: CIS 3.3.x / 1.5.x, KSPP (Kernel Self Protection Project),
# DISA STIG, Lynis (KRNL-6000), konstruktoid/hardening misc/sysctl.conf.
#
# Diseño: se escribe UN archivo /etc/sysctl.d/60-hardening.conf con
# comentarios y se aplica en caliente cada clave (sysctl -w). No se toca
# /etc/sysctl.conf. Salvaguardas:
#   * Si el host enruta (ip_forward=1, Docker, Kubernetes) NO se desactiva el
#     reenvío ni send_redirects, y rp_filter usa modo "loose" (2), salvo pánico.
#   * accept_ra=0 (máximo) se omite si hay IPv6 configurada por SLAAC.
#   * Claves inexistentes en este kernel se omiten (OMITIDO).
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 20 sysctl 1 "Parámetros del kernel (sysctl)"

SYSCTL_FILE=/etc/sysctl.d/60-hardening.conf

# ID|nivel|clave|valor|flags|por qué       flags: R=respeta router, RA=respeta SLAAC
SYSCTL_RULES=(
"SYS-01|1|kernel.randomize_va_space|2||ASLR completo: dificulta exploits de memoria"
"SYS-02|1|fs.protected_hardlinks|1||evita ataques TOCTOU con hardlinks a archivos ajenos"
"SYS-03|1|fs.protected_symlinks|1||evita seguir symlinks maliciosos en directorios sticky (/tmp)"
"SYS-04|1|fs.protected_regular|2||impide abrir con O_CREAT archivos ajenos en dirs sticky"
"SYS-05|1|fs.protected_fifos|1||igual que el anterior para FIFOs"
"SYS-05|3|fs.protected_fifos|2||versión estricta"
"SYS-06|1|fs.suid_dumpable|0||los binarios SUID no generan core dumps (pueden contener secretos)"
"SYS-07|1|kernel.dmesg_restrict|1||sólo root lee dmesg (fugas de direcciones del kernel)"
"SYS-08|1|kernel.kptr_restrict|1||oculta punteros del kernel en /proc a usuarios"
"SYS-08|2|kernel.kptr_restrict|2||oculta punteros del kernel incluso a root"
"SYS-09|1|net.ipv4.tcp_syncookies|1||mitiga SYN flood"
"SYS-10|1|net.ipv4.conf.all.accept_source_route|0||rechaza paquetes con source routing (spoofing)"
"SYS-11|1|net.ipv4.conf.default.accept_source_route|0||idem para interfaces nuevas"
"SYS-12|1|net.ipv6.conf.all.accept_source_route|0||idem IPv6"
"SYS-13|1|net.ipv6.conf.default.accept_source_route|0||idem IPv6 interfaces nuevas"
"SYS-14|1|net.ipv4.conf.all.accept_redirects|0||ignora ICMP redirect (MITM por cambio de rutas)"
"SYS-15|1|net.ipv4.conf.default.accept_redirects|0||idem interfaces nuevas"
"SYS-16|1|net.ipv6.conf.all.accept_redirects|0||idem IPv6"
"SYS-17|1|net.ipv6.conf.default.accept_redirects|0||idem IPv6 interfaces nuevas"
"SYS-18|1|net.ipv4.icmp_echo_ignore_broadcasts|1||evita ataques smurf"
"SYS-19|1|net.ipv4.icmp_ignore_bogus_error_responses|1||no llena los logs con ICMP falsos"
"SYS-20|1|net.ipv4.conf.all.send_redirects|0|R|un host que no es router no debe enviar redirects"
"SYS-21|1|net.ipv4.conf.default.send_redirects|0|R|idem interfaces nuevas"
"SYS-22|2|net.ipv4.conf.all.secure_redirects|0||ignora incluso redirects de gateways conocidos"
"SYS-23|2|net.ipv4.conf.default.secure_redirects|0||idem interfaces nuevas"
"SYS-24|2|net.ipv4.conf.all.log_martians|1||registra paquetes con direcciones imposibles"
"SYS-25|2|net.ipv4.conf.default.log_martians|1||idem interfaces nuevas"
"SYS-26|2|net.ipv4.conf.all.rp_filter|1|R|filtro de ruta inversa estricto (anti-spoofing)"
"SYS-27|2|net.ipv4.conf.default.rp_filter|1|R|idem interfaces nuevas"
"SYS-28|2|kernel.yama.ptrace_scope|1||sólo se puede depurar (ptrace) a procesos hijos"
"SYS-28|3|kernel.yama.ptrace_scope|2||sólo root puede usar ptrace (rompe gdb/strace de usuario)"
"SYS-29|2|kernel.unprivileged_bpf_disabled|1||eBPF sin privilegios es una fuente frecuente de CVEs"
"SYS-30|2|net.core.bpf_jit_harden|2||endurece el JIT de BPF contra JIT-spraying"
"SYS-31|2|dev.tty.ldisc_autoload|0||evita cargar disciplinas de línea vulnerables desde usuario"
"SYS-32|2|net.ipv4.ip_forward|0|R|no reenviar paquetes si no es router"
"SYS-33|2|net.ipv6.conf.all.forwarding|0|R|idem IPv6"
"SYS-34|3|kernel.kexec_load_disabled|1||impide cargar otro kernel en caliente (persistencia/rootkits)"
"SYS-35|3|kernel.sysrq|0||desactiva SysRq (evita reinicios/volcados desde teclado o /proc)"
"SYS-36|3|kernel.perf_event_paranoid|3||restringe perf a root (fugas laterales)"
"SYS-37|3|vm.unprivileged_userfaultfd|0||userfaultfd se usa para explotar condiciones de carrera"
"SYS-38|3|net.ipv6.conf.all.accept_ra|0|RA|ignora Router Advertisements (rogue RA)"
"SYS-39|3|net.ipv6.conf.default.accept_ra|0|RA|idem interfaces nuevas"
"SYS-40|3|net.ipv4.tcp_rfc1337|1||protege contra TIME-WAIT assassination"
"SYS-41|4|user.max_user_namespaces|0||sin user namespaces: elimina gran superficie de escalada (rompe contenedores rootless)"
"SYS-42|4|kernel.unprivileged_userns_clone|0||idem (parche Debian/Ubuntu)"
"SYS-43|4|kernel.apparmor_restrict_unprivileged_userns|1||Ubuntu 24.04+: restringe userns sin perfil"
)

# --- Metadatos derivados de SYSCTL_RULES (fuente única) ----------------------
# Qué puede romper cada clave (las no listadas: nada habitual)
declare -gA SYSCTL_BREAKS=(
  [kernel.kptr_restrict]="perf/herramientas de profiling que leen símbolos del kernel"
  [kernel.dmesg_restrict]="usuarios no root que leían dmesg"
  [net.ipv4.conf.all.send_redirects]="routers (se respeta si se detecta enrutamiento)"
  [net.ipv4.conf.all.rp_filter]="enrutamiento asimétrico, multi-homing, VPN (con router detectado se usa modo loose)"
  [net.ipv4.ip_forward]="Docker, Kubernetes, libvirt NAT, VPN gateway (se respeta si se detectan)"
  [net.ipv6.conf.all.forwarding]="idem IPv6"
  [kernel.yama.ptrace_scope]="gdb/strace sobre procesos ajenos (nivel 2: también los propios)"
  [kernel.unprivileged_bpf_disabled]="herramientas eBPF ejecutadas sin root"
  [kernel.kexec_load_disabled]="kdump/kexec en caliente"
  [kernel.sysrq]="SysRq desde consola para emergencias"
  [kernel.perf_event_paranoid]="perf y agentes de observabilidad sin root (algunos APM/eBPF)"
  [vm.unprivileged_userfaultfd]="CRIU/migración en caliente de procesos sin root"
  [net.ipv6.conf.all.accept_ra]="IPv6 por SLAAC (se omite si se detecta)"
  [user.max_user_namespaces]="contenedores rootless (podman), Chrome/Electron sandbox, flatpak, bubblewrap"
  [kernel.unprivileged_userns_clone]="idem"
  [kernel.apparmor_restrict_unprivileged_userns]="aplicaciones sin perfil AppArmor que crean userns"
)
_sysctl_register_meta() {
  local r id lvl key val flags why risk
  declare -A seen=()
  for r in "${SYSCTL_RULES[@]}"; do
    IFS='|' read -r id lvl key val flags why <<<"$r"
    if [[ -n "${seen[$id]:-}" ]]; then   # misma clave endurecida en un nivel superior
      CMETA_DESC[$id]+=" (nivel ${lvl}+: $val)"; continue
    fi
    seen[$id]=1
    case $lvl in 1|2) risk=bajo ;; 3) risk=medio ;; *) risk=alto ;; esac
    [[ "$flags" == R* ]] && risk=medio
    ctl_meta "$id" "$lvl" cambio "$risk" "inmediato;sysctl -w + persistente" "sysctl $key = $val — $why" \
      "$SYSCTL_FILE" "${SYSCTL_BREAKS[$key]:-${SYSCTL_BREAKS[${key/.default./.all.}]:-Nada habitual}}"
  done
}
_sysctl_register_meta

# -g: los módulos se cargan desde una función; sin -g serían locales
declare -gA SYSCTL_DESIRED=() SYSCTL_WHY=() SYSCTL_LEVEL=() SYSCTL_ID=()
SYSCTL_ORDER=()

sysctl_build_desired() {
  local r id lvl key val flags why slaac=0
  if ip -6 addr show scope global dynamic 2>/dev/null | grep -q inet6; then slaac=1; fi
  for r in "${SYSCTL_RULES[@]}"; do
    IFS='|' read -r id lvl key val flags why <<<"$r"
    (( LEVEL_NUM >= lvl )) || continue
    if [[ "$flags" == R ]] && (( ROUTER_DETECTED && LEVEL_NUM < 4 )); then
      if [[ "$key" == *rp_filter ]]; then val=2; why="$why (modo loose: host enrutador detectado)"
      else continue; fi
    fi
    if [[ "$flags" == RA ]] && (( slaac )); then continue; fi
    [[ -n "${SYSCTL_DESIRED[$key]+x}" ]] || SYSCTL_ORDER+=("$key")
    SYSCTL_DESIRED[$key]=$val; SYSCTL_WHY[$key]=$why; SYSCTL_LEVEL[$key]=$lvl; SYSCTL_ID[$key]=$id
  done
}

sysctl_file_content() {
  local k
  echo "# Gestionado por harden.sh (nivel $(level_name "$LEVEL_NUM")). Rollback: borrar y 'sysctl --system'."
  echo "# Cada parámetro incluye el POR QUÉ. No editar a mano: re-ejecutar harden.sh."
  for k in "${SYSCTL_ORDER[@]}"; do
    [[ -e "/proc/sys/${k//.//}" ]] || continue
    printf '\n# %s\n%s = %s\n' "${SYSCTL_WHY[$k]}" "$k" "${SYSCTL_DESIRED[$k]}"
  done
}

sysctl_key_check() {
  local _SK=$_BKEY _SV=${SYSCTL_DESIRED[$_BKEY]}
  if [[ ! -e "/proc/sys/${_SK//.//}" ]]; then note "no existe en este kernel"; return 2; fi
  local cur; cur=$(sysctl -n "$_SK" 2>/dev/null | tr -s '[:space:]' ' ')
  cur=$(trim "$cur")
  [[ "$cur" == "$_SV" ]] || { note "actual=$cur deseado=$_SV"; return 1; }
  # Además debe ser persistente
  file_has_line "$SYSCTL_FILE" "^[[:space:]]*${_SK//./\\.}[[:space:]]*=[[:space:]]*${_SV}[[:space:]]*$" \
    || { note "valor en caliente correcto pero no persistente"; return 1; }
}
sysctl_apply() {
  local k nf=0
  sysctl_file_content | write_file "$SYSCTL_FILE" 644
  for k in "${_BFAILING[@]}"; do
    run_cmd sysctl -q -w "${k}=${SYSCTL_DESIRED[$k]}" 2>/dev/null || nf=$((nf+1))
  done
  (( nf == 0 )) || note "$nf claves no se pudieron aplicar en caliente (quedan persistentes en $SYSCTL_FILE; efectivas al reiniciar)"
}

module_sysctl() {
  if (( IN_CONTAINER )); then
    record_result SYS-00 1 OMITIDO "Parámetros del kernel" "contenedor: los sysctl los controla el host"
    return 0
  fi
  sysctl_build_desired
  if (( ROUTER_DETECTED && LEVEL_NUM < 4 )); then
    log_warn "Host enrutador/Docker/K8s detectado: se mantiene ip_forward y send_redirects; rp_filter=2."
  fi
  local k items=()
  for k in "${SYSCTL_ORDER[@]}"; do
    # Una clave excluida con --skip-control tampoco se escribe en el archivo
    if ctl_excluded "${SYSCTL_ID[$k]}"; then unset "SYSCTL_DESIRED[$k]"; fi
    items+=("${SYSCTL_ID[$k]}|${SYSCTL_LEVEL[$k]}|sysctl $k = ${SYSCTL_DESIRED[$k]:-omitido}|$k")
  done
  local -a order=()
  for k in "${SYSCTL_ORDER[@]}"; do [[ -n "${SYSCTL_DESIRED[$k]+x}" ]] && order+=("$k"); done
  SYSCTL_ORDER=("${order[@]}")
  control_batch sysctl_key_check sysctl_apply "${items[@]}"
}
