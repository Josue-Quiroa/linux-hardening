# shellcheck shell=bash
# =============================================================================
# 25-filesystems — Módulos del kernel, opciones de montaje y permisos de disco
#
# POR QUÉ:
#  * Sistemas de archivos raros (cramfs, hfs, jffs2...) y protocolos poco usados
#    (dccp, sctp, rds, tipc) han tenido CVEs de escalada de privilegios y se
#    cargan automáticamente al montar una imagen o abrir un socket. Si no se
#    usan, impedir su carga elimina esa superficie (CIS 1.1.1.x y 3.2.x).
#  * USB-storage/firewire: exfiltración de datos e introducción de malware
#    (CIS 1.1.1.x L1-Workstation/L2).
#  * nodev/nosuid/noexec en /tmp y /dev/shm: impide ejecutar binarios o crear
#    dispositivos en directorios donde cualquier usuario escribe (CIS 1.1.2.x).
#  * Bit sticky en directorios escribibles por todos (CIS 1.1.x / Lynis FILE-6362).
# Se usa "install <mod> /bin/false" + "blacklist" en /etc/modprobe.d (método CIS).
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 25 filesystems 1 "Módulos del kernel, montajes y permisos de disco"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta FS-01 1 cambio bajo "inmediato;módulos ya cargados siguen hasta reiniciar" "Bloquear sistemas de archivos raros (cramfs, freevxfs, hfs, hfsplus, jffs2...)" \
  "/etc/modprobe.d/60-hardening.conf" "Montar imágenes/discos con esos sistemas de archivos"
ctl_meta FS-02 2 cambio bajo "inmediato;módulos ya cargados siguen hasta reiniciar" "Bloquear protocolos de red raros (dccp, sctp, rds, tipc)" \
  "/etc/modprobe.d/60-hardening.conf" "SCTP en telecom/Kubernetes (algunos CNI), clústeres con RDS/TIPC"
ctl_meta FS-03 3 cambio medio "inmediato;módulos ya cargados siguen hasta reiniciar" "Bloquear usb-storage, uas, firewire, thunderbolt, udf (y squashfs sin snap)" \
  "/etc/modprobe.d/60-hardening.conf" "Pendrives/discos USB, docks thunderbolt, provisión de Azure (udf), AppImage/squashfs"
ctl_meta FS-04 2 cambio medio "inmediato;remount en caliente, fstab al reiniciar" "/dev/shm con nodev,nosuid,noexec" \
  "/etc/fstab (validado con findmnt --verify)" "Software que ejecuta código desde /dev/shm (raro: algunos JIT/navegadores)"
ctl_meta FS-05 2 cambio alto "reinicio;medio: remount en caliente; máximo: tmpfs al reiniciar" "/tmp nodev,nosuid (medio); tmpfs separado con noexec (máximo)" \
  "/etc/fstab o /etc/systemd/system/tmp.mount(.d/60-hardening.conf)" "Instaladores y scripts que ejecutan en /tmp, JNA/Elasticsearch, algunas compilaciones; /tmp pasa a RAM (máximo)"
ctl_meta FS-06 2 cambio medio "inmediato;remount, fstab al reiniciar" "/var/tmp nodev,nosuid (+noexec en máximo) si es partición" \
  "/etc/fstab" "Software que ejecuta desde /var/tmp (máximo)"
ctl_meta FS-07 3 cambio bajo "inmediato;remount, fstab al reiniciar" "/home nodev,nosuid si es partición" "/etc/fstab" "Binarios SUID en /home (muy raro)"
ctl_meta FS-08 1 cambio bajo inmediato "Bit sticky en directorios escribibles por todos" "directorios world-writable (chmod +t)" "Nada habitual"


MODPROBE_FILE=/etc/modprobe.d/60-hardening.conf

# Grupos de módulos por nivel. squashfs NO se toca si hay snapd (los snaps lo usan).
kmod_group() { # kmod_group <grupo> -> lista de módulos
  case $1 in
    fs)    echo "cramfs freevxfs jffs2 hfs hfsplus" ;;
    net)   echo "dccp sctp rds tipc" ;;
    max)   local m="firewire-core firewire-ohci thunderbolt udf"
           (( ALLOW_USB_STORAGE )) || m+=" usb-storage uas"
           have snap || pkg_installed snapd || m+=" squashfs"
           echo "$m" ;;
  esac
}

kmod_wanted() { # todos los módulos que deberían estar bloqueados en este nivel
  local l
  l="$(kmod_group fs)"
  (( LEVEL_NUM >= 2 )) && l+=" $(kmod_group net)"
  (( LEVEL_NUM >= 3 )) && l+=" $(kmod_group max)"
  echo "$l"
}

kmod_is_blocked() { # ¿está bloqueado por configuración de modprobe?
  local m=${1//-/_} cfg
  cfg=$(modprobe --showconfig 2>/dev/null | tr '-' '_') || return 1
  grep -Eq "^install ${m} /(usr/)?bin/(false|true)" <<<"$cfg"
}

_KG=""
kmod_check() {
  have modprobe || { note "modprobe no disponible"; return 2; }
  local m bad=""
  for m in $(kmod_group "$_KG"); do
    kmod_is_blocked "$m" || bad+="$m "
  done
  [[ -z "$bad" ]] || { note "cargables: ${bad% }"; return 1; }
}
kmod_apply() {
  local m
  {
    echo "# Gestionado por harden.sh (nivel $(level_name "$LEVEL_NUM"))."
    echo "# 'install X /bin/false' impide la carga (incluso automática); 'blacklist' evita la carga por alias."
    echo "# Si necesitas alguno (p.ej. udf en Azure, usb-storage para un pendrive) bórralo de aquí o usa --skip-control."
    for m in $(kmod_wanted); do
      printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m"
    done
  } | write_file "$MODPROBE_FILE" 644
  for m in $(kmod_group "$_KG"); do
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "${m//-/_}"; then
      if (( DRY_RUN )); then log_dry "modprobe -r $m"
      elif ! modprobe -r "$m" 2>/dev/null; then note "$m en uso: se bloqueará tras reiniciar"; fi
    fi
  done
}

# ----------------------------------------------------------------------------
# fstab: añadir opciones de montaje de forma segura
# ----------------------------------------------------------------------------
fstab_has_entry() { awk -v mp="$1" '$1!~/^#/ && $2==mp {f=1} END{exit !f}' /etc/fstab 2>/dev/null; }

fstab_ensure_opts() { # fstab_ensure_opts <punto> <opts> [linea_si_no_existe]
  local mp=$1 opts=$2 newline=${3:-} tmp before after
  tmp=$(mktemp "${RUN_TMP:-/tmp}/fstab.XXXXXX")
  awk -v mp="$mp" -v add="$opts" -v nl="$newline" '
    BEGIN{OFS="\t"; n=split(add, A, ",")}
    $1!~/^#/ && $2==mp && NF>=4 {
      o=","$4","
      for(i=1;i<=n;i++) if (index(o, ","A[i]",")==0) $4=$4","A[i]
      found=1
    }
    {print}
    END{ if(!found && nl!="") print nl }' "$( [[ -f /etc/fstab ]] && echo /etc/fstab || echo /dev/null)" >"$tmp"
  # Validación: el nuevo fstab no debe tener MÁS errores de sintaxis que el actual
  if have findmnt; then
    before=$(findmnt --verify --tab-file /etc/fstab 2>&1 | grep -c '\[E\]' || true)
    after=$(findmnt --verify --tab-file "$tmp" 2>&1 | grep -c '\[E\]' || true)
    if (( after > before )); then rm -f "$tmp"; note "validación de fstab falló; sin cambios"; return 1; fi
  fi
  write_file /etc/fstab 644 <"$tmp"
  rm -f "$tmp"
}

# /dev/shm -----------------------------------------------------------------
shm_check() {
  (( IN_CONTAINER )) && { note "contenedor"; return 2; }
  is_mountpoint /dev/shm || { note "/dev/shm no montado"; return 2; }
  mount_has_opts /dev/shm nodev,nosuid,noexec || { note "opciones: $(mount_opts /dev/shm)"; return 1; }
  fstab_has_entry /dev/shm || { note "no persistente en fstab"; return 1; }
}
shm_apply() {
  fstab_ensure_opts /dev/shm nodev,nosuid,noexec $'tmpfs\t/dev/shm\ttmpfs\tdefaults,nodev,nosuid,noexec\t0\t0'
  run_cmd mount -o remount,nodev,nosuid,noexec /dev/shm
}

# /tmp -------------------------------------------------------------------------
_TMP_OPTS=""
tmp_check() {
  (( IN_CONTAINER )) && { note "contenedor"; return 2; }
  if ! is_mountpoint /tmp; then note "/tmp no es un montaje separado"; return 1; fi
  mount_has_opts /tmp "$_TMP_OPTS" || { note "opciones: $(mount_opts /tmp)"; return 1; }
}
tmp_apply() {
  if is_mountpoint /tmp && fstab_has_entry /tmp; then
    fstab_ensure_opts /tmp "$_TMP_OPTS"
    run_cmd mount -o "remount,${_TMP_OPTS}" /tmp
  elif (( HAS_SYSTEMD )) && { svc_exists tmp.mount || [[ -f /usr/share/systemd/tmp.mount ]]; }; then
    # /tmp como tmpfs gestionado por systemd (Debian 13/RHEL ya lo traen).
    if (( LEVEL_NUM < 3 )) && ! is_mountpoint /tmp; then
      note "convertir /tmp en tmpfs se hace en nivel máximo (usa RAM y requiere reinicio)"; return 3
    fi
    if ! svc_exists tmp.mount && [[ -f /usr/share/systemd/tmp.mount ]]; then
      write_file /etc/systemd/system/tmp.mount 644 </usr/share/systemd/tmp.mount
    fi
    write_file /etc/systemd/system/tmp.mount.d/60-hardening.conf 644 <<CONF
# Gestionado por harden.sh: /tmp en tmpfs con opciones restrictivas.
[Mount]
Options=mode=1777,strictatime,size=50%,${_TMP_OPTS}
CONF
    run_cmd systemctl daemon-reload
    if is_mountpoint /tmp; then
      run_cmd mount -o "remount,${_TMP_OPTS}" /tmp
    else
      run_cmd systemctl enable tmp.mount
      note "tmpfs /tmp activo tras reiniciar (no se monta en caliente para no ocultar archivos en uso)"
      return 4
    fi
  else
    note "/tmp no es partición separada: crea una partición o tmpfs manualmente"; return 3
  fi
}

# Otros montajes (sólo si ya son separados) ------------------------------------
_MP=""; _MP_OPTS=""
mp_check() {
  (( IN_CONTAINER )) && { note "contenedor"; return 2; }
  is_mountpoint "$_MP" || { note "$_MP no es un montaje separado (recomendado por CIS)"; return 2; }
  mount_has_opts "$_MP" "$_MP_OPTS" || { note "opciones: $(mount_opts "$_MP")"; return 1; }
}
mp_apply() {
  fstab_has_entry "$_MP" || { note "$_MP no está en fstab"; return 3; }
  fstab_ensure_opts "$_MP" "$_MP_OPTS"
  run_cmd mount -o "remount,${_MP_OPTS}" "$_MP"
}

# Sticky bit en directorios escribibles por todos --------------------------------
sticky_list() {
  local fs
  fs=$(findmnt -n -l -o TARGET -t ext2,ext3,ext4,xfs,btrfs 2>/dev/null | tr '\n' ' ')
  # shellcheck disable=SC2086
  [[ -n "$fs" ]] && { find $fs -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null || true; } | head -n 200
  return 0
}
sticky_check() { local l; l=$(sticky_list); [[ -z "$l" ]] || { note "$(wc -l <<<"$l") directorios"; return 1; }; }
sticky_apply() { local d; while IFS= read -r d; do [[ -n "$d" ]] && run_cmd chmod +t "$d"; done < <(sticky_list); }

module_filesystems() {
  _KG=fs;  control FS-01 1 "Bloquear sistemas de archivos poco comunes (cramfs, hfs, jffs2...)" kmod_check kmod_apply
  _KG=net; control FS-02 2 "Bloquear protocolos de red poco comunes (dccp, sctp, rds, tipc)" kmod_check kmod_apply
  _KG=max; control FS-03 3 "Bloquear USB-storage, firewire, thunderbolt, udf$(have snap || echo ', squashfs')" kmod_check kmod_apply
  control FS-04 2 "/dev/shm con nodev,nosuid,noexec" shm_check shm_apply
  _TMP_OPTS=nodev,nosuid;        control FS-05 2-2 "/tmp con nodev,nosuid" tmp_check tmp_apply
  _TMP_OPTS=nodev,nosuid,noexec; control FS-05 3 "/tmp separado (tmpfs) con nodev,nosuid,noexec" tmp_check tmp_apply
  _MP=/var/tmp; _MP_OPTS=nodev,nosuid
  if (( LEVEL_NUM >= 3 )); then _MP_OPTS+=",noexec"; fi
  control FS-06 2 "/var/tmp con $_MP_OPTS (si es partición)" mp_check mp_apply
  _MP=/home;    _MP_OPTS=nodev,nosuid; control FS-07 3 "/home con nodev,nosuid (si es partición)" mp_check mp_apply
  control FS-08 1 "Bit sticky en todos los directorios escribibles por todos" sticky_check sticky_apply
}
