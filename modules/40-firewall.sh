# shellcheck shell=bash
# =============================================================================
# 40-firewall — Firewall de host (ufw / firewalld / nftables) y LOCKDOWN
#
# POR QUÉ: "denegar por defecto" es el control de red más eficaz (CIS 4.x,
# STIG). Se usa la herramienta nativa de cada familia para no pelear con ella:
#   Debian/Ubuntu -> ufw   |   RHEL/Rocky -> firewalld   |   resto -> nftables
#   basico : sólo se comprueba que haya un firewall activo (no se activa: riesgo de corte)
#   medio  : deny entrante; se permiten SSH + puertos YA en escucha + --allow-in
#   maximo : deny entrante (sólo SSH + --allow-in) y deny SALIENTE salvo DNS/NTP/HTTP(S)/DHCP
#   panico : tabla nftables "hardening_lockdown" con prioridad -10 (se evalúa
#            antes que ufw/firewalld): todo DROP salvo SSH desde las IP admin,
#            DHCP y respuestas a conexiones salientes permitidas. Docker/forward: DROP.
# SALVAGUARDAS: el puerto SSH real (sshd -T) siempre se permite; reversión
# automática programada antes de aplicar (lib/fwsafety.sh); validación nft -c.
# AVISO: Docker publica puertos con sus propias reglas y SE SALTA ufw/firewalld.
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 40 firewall 1 "Firewall de host y lockdown de red"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta FW-01 1-1 aviso bajo ninguno "Comprobar si hay firewall de host activo" "-" "Nada"
ctl_meta FW-02 2-3 cambio alto "inmediato;con reversión automática si no se confirma" "Firewall de host deny entrante: SSH + puertos en escucha (medio) + --allow-in; máximo: límite de conexiones SSH" \
  "ufw (/etc/default/ufw, /etc/ufw/*.rules) | firewalld (/etc/firewalld) | nft (/etc/hardening/firewall.nft); servicio ufw/firewalld/nftables" \
  "Servicios que empiecen a escuchar después en otros puertos; en máximo los puertos no listados explícitamente; Docker publica puertos saltándose el firewall"
ctl_meta FW-03 3-3 cambio alto "inmediato;con reversión automática" "Salida restringida: sólo DNS, NTP, HTTP/S, DHCP (+FW_ALLOW_OUT)" \
  "reglas ufw salientes | política firewalld hardening-out | nft" \
  "SMTP saliente, réplicas de BD, LDAP/Kerberos, VPN cliente, agentes de monitorización, git por SSH, cualquier API en otro puerto"
ctl_meta FW-04 4 cambio alto "inmediato;con reversión automática" "LOCKDOWN nft: todo DROP salvo SSH desde IP admin (entrada, salida y forward)" \
  "tabla nft inet hardening_lockdown, /etc/hardening/lockdown.nft, hardening-lockdown.service" "TODO el tráfico de red salvo tu SSH de administración (web, BD, Docker, DNS, actualizaciones)"
ctl_meta FW-05 2 aviso bajo ninguno "Docker publica puertos saltándose ufw/firewalld" "-" "Nada (recomendación: cadena DOCKER-USER)"


LOCKDOWN_TABLE="hardening_lockdown"
LOCKDOWN_FILE=/etc/hardening/lockdown.nft
NFTFW_TABLE="hardening_fw"
NFTFW_FILE=/etc/hardening/firewall.nft
FW_OUT_DEFAULT="53/udp 53/tcp 123/udp 80/tcp 443/tcp 67/udp"

fw_backend() {
  if is_rhel; then echo firewalld
  elif have ufw || [[ "$OS_ID" == ubuntu ]]; then echo ufw
  elif have firewall-cmd; then echo firewalld
  elif is_debian; then echo ufw
  else echo nft; fi
}

fw_any_active() {
  { have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; } && { note "ufw activo"; return 0; }
  svc_active firewalld && { note "firewalld activo"; return 0; }
  { have nft && nft list ruleset 2>/dev/null | grep -qE 'hook input.*policy drop'; } && { note "nftables con política drop"; return 0; }
  { have iptables && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; } && { note "iptables INPUT DROP"; return 0; }
  return 1
}

# Puertos en escucha accesibles desde fuera (formato puerto/proto)
listening_ports() {
  have ss || return 0
  ss -H -tuln 2>/dev/null | awk '
    { proto=($1 ~ /tcp/) ? "tcp" : "udp"; addr=$5
      if (addr ~ /^(127\.|\[::1\]|::1|\[?fe80)/ || addr ~ /%lo:/) next
      n=split(addr, a, ":"); port=a[n]
      if (port ~ /^[0-9]+$/ && port!=68 && port!=546 && port!=5353 && port!=323) print port"/"proto }' | sort -u
}

fw_allowed_in() { # lista final de puertos de entrada permitidos
  local p list=""
  for p in $SSH_PORTS; do list+="$p/tcp "; done
  for p in $FW_ALLOW_IN; do [[ "$p" == */* ]] || p="$p/tcp"; list+="$p "; done
  if (( LEVEL_NUM >= 2 && LEVEL_NUM <= FW_AUTO_ALLOW_MAXLEVEL && FW_AUTO_ALLOW_LISTENING )); then list+="$(listening_ports | tr '\n' ' ')"; fi
  tr ' ' '\n' <<<"$list" | awk 'NF' | sort -u | tr '\n' ' '
}

fw_allowed_out() {
  local p list="$FW_OUT_DEFAULT"
  for p in $FW_ALLOW_OUT; do [[ "$p" == */* ]] || p="$p/tcp"; list+=" $p"; done
  echo "$list"
}

# ---------------------------------------------------------------------------
# Script de reversión (se ejecuta por el temporizador si no confirmas)
# ---------------------------------------------------------------------------
fw_write_revert() { # fw_write_revert <backend> <estaba_activo 0/1> -> imprime ruta
  local be=$1 was=$2 f="${RUN_DIR}/fw-revert.sh"
  (( DRY_RUN )) && { echo "$f"; return 0; }
  {
    echo '#!/bin/bash'
    echo "# Reversión automática del firewall generada por harden.sh ($(date -Is))"
    echo 'logger -t harden.sh "Revirtiendo firewall (no se confirmó a tiempo)" 2>/dev/null'
    case $be in
      ufw)
        echo "for f in /etc/ufw/user.rules /etc/ufw/user6.rules /etc/default/ufw; do [ -f '${RUN_DIR}/files'\$f ] && cp -a '${RUN_DIR}/files'\$f \$f; done"
        if [[ "$was" == 0 ]]; then echo 'ufw --force disable'; else echo 'ufw reload'; fi ;;
      firewalld)
        echo "[ -d '${RUN_DIR}/files/etc/firewalld' ] && { rm -rf /etc/firewalld; cp -a '${RUN_DIR}/files/etc/firewalld' /etc/firewalld; }"
        if [[ "$was" == 0 ]]; then echo 'systemctl stop firewalld'; else echo 'firewall-cmd --reload'; fi ;;
      nft)
        echo "nft delete table inet ${NFTFW_TABLE} 2>/dev/null"
        echo 'systemctl disable hardening-firewall.service 2>/dev/null' ;;
      lockdown)
        echo "nft delete table inet ${LOCKDOWN_TABLE} 2>/dev/null"
        echo 'systemctl disable hardening-lockdown.service 2>/dev/null' ;;
    esac
    echo "rm -rf ${FW_ROLLBACK_STATE}"
  } >"$f"
  chmod 700 "$f"
  echo "$f"
}

# ---------------------------------------------------------------------------
# UFW
# ---------------------------------------------------------------------------
ufw_check() {
  have ufw || { note "ufw no instalado"; return 1; }
  is_root || { note "requiere root"; return 2; }
  local st p; st=$(ufw status verbose 2>/dev/null)
  grep -q 'Status: active' <<<"$st" || { note "inactivo"; return 1; }
  grep -qE 'Default: deny \(incoming\)' <<<"$st" || { note "política entrante no es deny"; return 1; }
  for p in $SSH_PORTS; do
    grep -qE "^${p}/tcp[[:space:]].*(ALLOW|LIMIT)" <<<"$st" || { note "SSH $p no permitido explícitamente"; return 1; }
  done
}
ufw_apply() {
  pkg_install ufw
  local was=0 p revert
  ufw status 2>/dev/null | grep -q 'Status: active' && was=1
  record_action FW_STATE ufw "$was"
  backup_file /etc/ufw/user.rules; backup_file /etc/ufw/user6.rules; backup_file /etc/default/ufw
  [[ -f /etc/default/ufw ]] && set_config_value /etc/default/ufw IPV6 yes "="
  revert=$(fw_write_revert ufw "$was")
  fw_arm_rollback "$revert"
  # SSH PRIMERO, luego la política (orden anti-bloqueo)
  for p in $SSH_PORTS; do
    if (( LEVEL_NUM >= 3 )); then run_cmd ufw limit "${p}/tcp" comment 'SSH (harden.sh)'
    else run_cmd ufw allow "${p}/tcp" comment 'SSH (harden.sh)'; fi
  done
  for p in $(fw_allowed_in); do
    in_list "${p%/*}" "$SSH_PORTS" && [[ "$p" == */tcp ]] && continue
    run_cmd ufw allow "$p" comment 'harden.sh'
  done
  run_cmd ufw default deny incoming
  if (( ROUTER_DETECTED )); then note "host enrutador: no se cambia la política 'routed'"; else run_cmd ufw default deny routed; fi
  run_cmd ufw logging low
  run_cmd ufw --force enable
  note "entrada permitida: $(fw_allowed_in)"
  fw_wait_confirm
}
ufw_out_check() {
  have ufw && is_root || return 1
  ufw status verbose 2>/dev/null | grep -qE 'deny \(outgoing\)'
}
ufw_out_apply() {
  local p
  for p in $(fw_allowed_out); do run_cmd ufw allow out "$p" comment 'harden.sh salida'; done
  fw_arm_rollback "$(fw_write_revert ufw 1)"
  run_cmd ufw default deny outgoing
  note "salida permitida: $(fw_allowed_out)"
  fw_wait_confirm
}

# ---------------------------------------------------------------------------
# firewalld
# ---------------------------------------------------------------------------
fwd_zone() { firewall-cmd --get-default-zone 2>/dev/null || echo public; }
fwd_check() {
  have firewall-cmd || { note "firewalld no instalado"; return 1; }
  svc_active firewalld || { note "firewalld inactivo"; return 1; }
  local z p; z=$(fwd_zone)
  [[ "$(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null)" != ACCEPT ]] || { note "zona $z con target ACCEPT"; return 1; }
  for p in $SSH_PORTS; do
    if [[ "$p" == 22 ]]; then
      firewall-cmd --zone="$z" --query-service=ssh >/dev/null 2>&1 || firewall-cmd --zone="$z" --query-port=22/tcp >/dev/null 2>&1 || { note "SSH no permitido"; return 1; }
    else
      firewall-cmd --zone="$z" --query-port="$p/tcp" >/dev/null 2>&1 || { note "puerto SSH $p no permitido"; return 1; }
    fi
  done
}
fwd_apply() {
  pkg_install firewalld
  local was=0 wasen=0 z p revert
  svc_active firewalld && was=1
  svc_enabled firewalld && wasen=1
  record_action FW_STATE firewalld "$was" "$wasen"
  backup_file /etc/firewalld
  revert=$(fw_write_revert firewalld "$was")
  fw_arm_rollback "$revert"
  # Si firewalld no corría, se arranca con la configuración permanente: primero
  # añadimos SSH a la config permanente con firewall-offline-cmd.
  if (( ! was )) && have firewall-offline-cmd; then
    for p in $SSH_PORTS; do run_cmd firewall-offline-cmd --add-port="$p/tcp"; done
  fi
  svc_enable_now firewalld
  z=$(fwd_zone)
  for p in $SSH_PORTS; do
    if [[ "$p" == 22 ]]; then run_cmd firewall-cmd --permanent --zone="$z" --add-service=ssh
    else run_cmd firewall-cmd --permanent --zone="$z" --add-port="$p/tcp"; fi
  done
  for p in $(fw_allowed_in); do run_cmd firewall-cmd --permanent --zone="$z" --add-port="$p"; done
  if (( LEVEL_NUM >= 3 )); then
    # cockpit viene abierto por defecto en RHEL: se cierra si no está escuchando
    listening_ports | grep -qx '9090/tcp' || run_cmd firewall-cmd --permanent --zone="$z" --remove-service=cockpit
  fi
  [[ "$(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null)" == ACCEPT ]] && run_cmd firewall-cmd --permanent --zone="$z" --set-target=default
  run_cmd firewall-cmd --reload
  note "zona $z; entrada: $(fw_allowed_in)"
  fw_wait_confirm
}
fwd_out_check() {
  have firewall-cmd && svc_active firewalld || return 1
  firewall-cmd --get-policies 2>/dev/null | grep -qw hardening-out
}
fwd_out_apply() {
  firewall-cmd --get-policies >/dev/null 2>&1 || { note "esta versión de firewalld no soporta políticas (>=0.9)"; return 3; }
  local p
  fw_arm_rollback "$(fw_write_revert firewalld 1)"
  run_cmd firewall-cmd --permanent --new-policy hardening-out
  run_cmd firewall-cmd --permanent --policy hardening-out --add-ingress-zone HOST
  run_cmd firewall-cmd --permanent --policy hardening-out --add-egress-zone ANY
  run_cmd firewall-cmd --permanent --policy hardening-out --set-target REJECT
  for p in $(fw_allowed_out); do run_cmd firewall-cmd --permanent --policy hardening-out --add-port="$p"; done
  run_cmd firewall-cmd --reload
  note "salida permitida: $(fw_allowed_out)"
  fw_wait_confirm
}

# ---------------------------------------------------------------------------
# nftables (fallback y lockdown)
# ---------------------------------------------------------------------------
_nft_ports_set() { # _nft_ports_set <proto> <lista p/proto> -> "{ 22, 80 }" o vacío
  local proto=$1 p out=""
  for p in $2; do [[ "${p#*/}" == "$proto" ]] && out+="${out:+, }${p%/*}"; done
  [[ -n "$out" ]] && echo "{ $out }"
  return 0
}

nft_generate() { # nft_generate <tabla> <modo fw|lockdown> <admin_ips> <in_ports> <out_ports|ANY>
  local table=$1 mode=$2 admins=$3 inp=$4 outp=$5 a v4="" v6="" s e4="" e6=""
  for a in $admins; do if [[ "$a" == *:* ]]; then v6+="${v6:+, }$a"; else v4+="${v4:+, }$a"; fi; done
  [[ -n "$v4" ]] && e4="elements = { $v4 }; "
  [[ -n "$v6" ]] && e6="elements = { $v6 }; "
  echo "# Generado por harden.sh ($(date -Is)) — modo $mode"
  echo "# Prioridad -10: se evalúa ANTES que ufw/firewalld. Un DROP aquí es definitivo."
  echo "table inet $table"
  echo "delete table inet $table"
  echo "table inet $table {"
  echo "  set admin4 { type ipv4_addr; flags interval; ${e4}}"
  echo "  set admin6 { type ipv6_addr; flags interval; ${e6}}"
  echo "  chain input {"
  echo "    type filter hook input priority -10; policy drop;"
  echo '    iif "lo" accept'
  echo '    ct state invalid drop'
  if [[ $mode == lockdown ]]; then
    echo '    # sólo respuestas a conexiones INICIADAS por este host (las sesiones entrantes ajenas mueren)'
    echo '    ct direction reply ct state established,related accept'
    echo '    ct state related meta l4proto { 1, 58 } accept   # 1=icmp 58=ipv6-icmp'
    for s in $SSH_PORTS; do
      echo "    ip saddr @admin4 tcp dport $s accept"
      echo "    ip6 saddr @admin6 tcp dport $s accept"
    done
    echo '    ip saddr @admin4 icmp type echo-request limit rate 5/second accept'
  else
    echo '    ct state established,related accept'
    s=$(_nft_ports_set tcp "$inp"); [[ -n "$s" ]] && echo "    tcp dport $s accept"
    s=$(_nft_ports_set udp "$inp"); [[ -n "$s" ]] && echo "    udp dport $s accept"
    echo '    icmp type echo-request limit rate 10/second accept'
    echo '    icmpv6 type echo-request limit rate 10/second accept'
  fi
  echo '    # DHCP (perder la IP también es perder el acceso) e ICMPv6 imprescindible (ND)'
  echo '    udp sport 67 udp dport 68 accept'
  echo '    udp sport 547 udp dport 546 accept'
  echo '    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept'
  echo "    limit rate 10/minute burst 20 packets log prefix \"harden-${mode}-in: \" level warn"
  echo '  }'
  echo '  chain forward {'
  echo "    type filter hook forward priority -10; policy $( [[ $mode == lockdown ]] && echo drop || echo accept);"
  echo '  }'
  echo '  chain output {'
  if [[ "$outp" == ANY ]]; then
    echo '    type filter hook output priority -10; policy accept;'
  else
    echo '    type filter hook output priority -10; policy drop;'
    echo '    oif "lo" accept'
    echo '    ct state established,related accept'
    echo '    ip daddr @admin4 accept'
    echo '    ip6 daddr @admin6 accept'
    echo '    udp sport 68 udp dport 67 accept'
    echo '    udp sport 546 udp dport 547 accept'
    echo '    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept'
    s=$(_nft_ports_set tcp "$outp"); [[ -n "$s" ]] && echo "    tcp dport $s accept"
    s=$(_nft_ports_set udp "$outp"); [[ -n "$s" ]] && echo "    udp dport $s accept"
    echo "    limit rate 10/minute burst 20 packets log prefix \"harden-${mode}-out: \" level warn"
  fi
  echo '  }'
  echo '}'
}

nft_persist_unit() { # nft_persist_unit <nombre_unidad> <archivo.nft>
  write_file "/etc/systemd/system/$1.service" 644 <<UNIT
# Generado por harden.sh: carga $2 al arrancar, antes de la red.
[Unit]
Description=harden.sh: reglas nftables ($2)
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(command -v nft || echo /usr/sbin/nft) -f $2

[Install]
WantedBy=multi-user.target
UNIT
  if (( HAS_SYSTEMD )); then
    run_cmd systemctl daemon-reload
    svc_enabled "$1.service" || { record_action SVC_ENABLED "$1.service"; run_cmd systemctl enable "$1.service"; }
  fi
}

nft_load() { # nft_load <archivo_contenido_tmp> <destino> <tabla>
  local tmp=$1 dest=$2 table=$3
  if is_root && ! nft -c -f "$tmp" 2>"$tmp.err"; then
    note "nft -c rechazó el ruleset: $(head -n2 "$tmp.err" | tr '\n' ' ')"; return 1
  fi
  write_file "$dest" 600 <"$tmp"
  grep -qxF "NFT_TABLE|inet $table" "${BACKUP_DIR:-/dev/null}/MANIFEST" 2>/dev/null || record_action NFT_TABLE "inet $table"
  run_cmd nft -f "$dest"
}

nftfw_check() { have nft && is_root && nft list table inet "$NFTFW_TABLE" >/dev/null 2>&1; }
nftfw_apply() {
  have nft || pkg_install nftables
  local tmp out=ANY
  (( LEVEL_NUM >= 3 )) && out=$(fw_allowed_out)
  tmp=$(mktemp "${RUN_TMP:-/tmp}/nft.XXXXXX")
  nft_generate "$NFTFW_TABLE" fw "$ADMIN_IPS" "$(fw_allowed_in)" "$out" >"$tmp"
  fw_arm_rollback "$(fw_write_revert nft 0)"
  nft_load "$tmp" "$NFTFW_FILE" "$NFTFW_TABLE"
  nft_persist_unit hardening-firewall "$NFTFW_FILE"
  fw_wait_confirm
}

# Lockdown (pánico) ------------------------------------------------------------
lockdown_admins() {
  local a list="$ADMIN_IPS"
  if [[ -n "$SSH_CLIENT_IP" ]]; then
    if [[ "$SSH_CLIENT_IP" == *:* ]]; then list+=" ${SSH_CLIENT_IP}/128"; else list+=" ${SSH_CLIENT_IP}/32"; fi
  fi
  for a in $list; do echo "$a"; done | sort -u | tr '\n' ' '
}
lockdown_check() {
  have nft || { note "nft no instalado"; return 1; }
  is_root || { note "requiere root"; return 2; }
  nft list table inet "$LOCKDOWN_TABLE" >/dev/null 2>&1
}
lockdown_apply() {
  local admins tmp out=""
  admins=$(lockdown_admins)
  if [[ -z "$(trim "$admins")" ]] && (( ! PANIC_ALLOW_NO_SSH )); then
    note "sin IP de administración: usa --admin-ip CIDR (o PANIC_ALLOW_NO_SSH=1 para sólo consola)"; return 1
  fi
  have nft || pkg_install nftables
  out="$PANIC_ALLOW_OUT"
  [[ -n "$out" ]] || out="none/none"
  tmp=$(mktemp "${RUN_TMP:-/tmp}/lockdown.XXXXXX")
  nft_generate "$LOCKDOWN_TABLE" lockdown "$admins" "" "$out" >"$tmp"
  if (( DRY_RUN )); then sed 's/^/        /' "$tmp" >&2; fi
  fw_arm_rollback "$(fw_write_revert lockdown 0)"
  nft_load "$tmp" "$LOCKDOWN_FILE" "$LOCKDOWN_TABLE"
  nft_persist_unit hardening-lockdown "$LOCKDOWN_FILE"
  note "SSH sólo desde: ${admins:-NADIE (sólo consola)}; salida: ${PANIC_ALLOW_OUT:-ninguna salvo DHCP/admin}"
  fw_wait_confirm
}

docker_check() {
  have docker || [[ -d /var/lib/docker ]] || return 0
  note "Docker inserta reglas propias: los puertos publicados (-p) NO los filtra ufw/firewalld; usa la cadena DOCKER-USER"
  return 1
}

module_firewall() {
  if (( IN_CONTAINER )); then
    record_result FW-00 1 OMITIDO "Firewall de host" "contenedor: el firewall lo gestiona el host"; return 0
  fi
  advise FW-01 1-1 "Hay un firewall de host activo (en básico sólo se comprueba)" fw_any_active
  case "$(fw_backend)" in
    ufw)
      control FW-02 2-3 "ufw activo, deny entrante, SSH (${SSH_PORTS}) permitido" ufw_check ufw_apply
      control FW-03 3-3 "ufw: deny saliente salvo DNS/NTP/HTTP(S)/DHCP" ufw_out_check ufw_out_apply ;;
    firewalld)
      control FW-02 2-3 "firewalld activo, zona restrictiva, SSH (${SSH_PORTS}) permitido" fwd_check fwd_apply
      control FW-03 3-3 "firewalld: política de salida restrictiva" fwd_out_check fwd_out_apply ;;
    *)
      control FW-02 2-3 "nftables: deny entrante, SSH permitido" nftfw_check nftfw_apply ;;
  esac
  control FW-04 4 "LOCKDOWN nftables: todo cerrado salvo SSH desde IP admin" lockdown_check lockdown_apply
  advise FW-05 2 "Docker y firewall de host" docker_check
}
