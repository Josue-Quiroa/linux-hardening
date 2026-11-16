# shellcheck shell=bash
# =============================================================================
# lib/workloads.sh — PRE-CHECK de cargas críticas y modo --safe.
#
# POR QUÉ: el hardening genérico rompe sobre todo cuando choca con lo que el
# servidor HACE: Docker/Kubernetes necesitan ip_forward y sus propias cadenas
# de firewall, una BD replica hacia otros nodos, una VPN enruta, un cliente
# SSSD habla LDAP/Kerberos... Antes de tocar nada se detectan esas cargas (sólo
# lectura: unidades systemd, procesos, binarios, rutas y puertos en escucha)
# y se avisa de qué controles les afectan. Con --safe esos controles se
# OMITEN o se SUAVIZAN automáticamente y el motivo queda en el reporte.
#
# Formato de WL_DEFS: clave|categoría|etiqueta|unidades|procesos|binarios|rutas|puertos
#   (listas separadas por espacios; '-' = vacío; se admiten comodines en
#    unidades y rutas)
# Formato de WL_IMPACTS: clave|IDs (coma)|acción --safe|motivo
#   acciones: skip (omitir) | router (mantener reenvío) | fwin (permitir puertos
#   en escucha también en máximo) | fwout:<puertos> | keep (no deshabilitar sus
#   unidades) | pkeep (no pararlas en pánico) | shell:<usuarios> | warn (sólo aviso)
# =============================================================================

WL_DEFS=(
  "mysql|bd|MySQL/MariaDB|mysql mysqld mariadb|mysqld mariadbd|-|/var/lib/mysql|3306/tcp"
  "postgresql|bd|PostgreSQL|postgresql postgresql@*|postgres|-|/var/lib/postgresql/* /var/lib/pgsql/data|5432/tcp"
  "mongodb|bd|MongoDB|mongod mongodb|mongod|-|/var/lib/mongodb/*|27017/tcp"
  "redis|bd|Redis/Valkey|redis-server redis valkey-server valkey|redis-server valkey-server|-|-|6379/tcp"
  "elastic|bd|Elasticsearch/OpenSearch|elasticsearch opensearch|-|-|/etc/elasticsearch /etc/opensearch|9200/tcp 9300/tcp"
  "docker|contenedores|Docker|docker dockerd|dockerd|dockerd|/var/lib/docker|2375/tcp 2376/tcp"
  "containerd|contenedores|containerd|containerd|containerd|containerd|/var/lib/containerd|-"
  "podman|contenedores|Podman (rootless posible)|podman podman.socket|conmon|podman|-|-"
  "kubernetes|contenedores|Kubernetes (kubelet/k3s/rke2)|kubelet k3s k3s-agent rke2-server rke2-agent|kubelet k3s k3s-server|kubelet k3s|/etc/kubernetes /etc/rancher/k3s /var/lib/kubelet|6443/tcp 10250/tcp"
  "web|web|Servidor web/proxy (nginx/Apache/HAProxy/Caddy)|nginx apache2 httpd haproxy caddy|nginx apache2 httpd haproxy caddy|-|-|80/tcp 443/tcp"
  "libvirt|virtualizacion|libvirt/KVM|libvirtd virtqemud libvirtd.socket|libvirtd virtqemud|-|/etc/libvirt/qemu/*.xml|-"
  "nfs|compartir|Servidor NFS|nfs-server nfs-kernel-server|nfsd|-|-|2049/tcp"
  "samba|compartir|Samba|smbd smb nmbd|smbd|-|-|445/tcp"
  "netfs|compartir|Cliente NFS/SMB (montajes remotos)|-|-|-|-|-"
  "wireguard|vpn|WireGuard|wg-quick@*|-|-|/etc/wireguard/*.conf|51820/udp"
  "openvpn|vpn|OpenVPN|openvpn openvpn@* openvpn-server@* openvpn-client@*|openvpn|-|-|1194/udp 1194/tcp"
  "ipsec|vpn|IPsec (strongSwan/Libreswan)|strongswan strongswan-starter ipsec|charon pluto|-|-|500/udp 4500/udp"
  "overlay|vpn|Tailscale/ZeroTier|tailscaled zerotier-one|tailscaled zerotier-one|-|-|41641/udp 9993/udp"
  "mail|correo|Correo (Postfix/Exim/Sendmail/Dovecot)|postfix exim4 sendmail dovecot|exim4 sendmail dovecot|-|-|25/tcp 465/tcp 587/tcp 993/tcp"
  "ldap|directorio|LDAP/SSSD/Active Directory|sssd slapd winbind|sssd slapd winbindd|-|/etc/sssd/sssd.conf|389/tcp 636/tcp"
  "monitor|monitorizacion|Agentes de monitorización/seguridad|node_exporter prometheus-node-exporter zabbix-agent zabbix-agent2 datadog-agent newrelic-infra wazuh-agent osqueryd filebeat telegraf grafana-agent alloy falco falcon-sensor elastic-agent|node_exporter zabbix_agentd zabbix_agent2 osqueryd wazuh-agentd filebeat telegraf falco falcon-sensor|-|-|9100/tcp 10050/tcp"
)

WL_IMPACTS=(
  "docker|SYS-20,SYS-21,SYS-26,SYS-27,SYS-32,SYS-33|router|ip_forward=0, send_redirects y rp_filter estricto cortan la red de los contenedores"
  "docker|FW-02|warn|Docker publica puertos con sus propias reglas iptables/nft (saltándose ufw/firewalld; filtrar en DOCKER-USER). Recargar el firewall puede borrar reglas de contenedores: reinicie docker si falla la red"
  "docker|SYS-41,SYS-42,SYS-43|skip|sin user namespaces no funciona Docker rootless ni userns-remap"
  "docker|SVC-05|pkeep|pánico pararía Docker y todos los contenedores"
  "docker|PNC-01|skip|sin carga de módulos no se pueden crear redes overlay/bridge nuevas"
  "containerd|SYS-32,SYS-33|router|los pods/contenedores necesitan reenvío de paquetes"
  "containerd|SVC-05|pkeep|pánico pararía containerd"
  "podman|SYS-41,SYS-42,SYS-43|skip|Podman rootless necesita user namespaces"
  "podman|FW-02|warn|netavark/CNI añade sus propias reglas nft; los puertos publicados deben permitirse"
  "kubernetes|SYS-20,SYS-21,SYS-26,SYS-27,SYS-32,SYS-33|router|kube-proxy/CNI necesitan ip_forward y rp_filter laxo"
  "kubernetes|FW-02,FW-03|skip|un deny-by-default rompe kubelet (10250), API (6443), etcd, VXLAN/Geneve (8472/6081 udp) y NodePorts entre nodos"
  "kubernetes|FS-02|skip|Services SCTP y algunos CNI necesitan el módulo sctp"
  "kubernetes|SYS-41,SYS-42,SYS-43|skip|pods con user namespaces y runtimes rootless"
  "kubernetes|SVC-05|pkeep|pánico pararía kubelet y todos los pods del nodo"
  "kubernetes|PNC-01|skip|el CNI carga módulos (br_netfilter, overlay, vxlan) dinámicamente"
  "kubernetes|LOG-07|warn|auditar todos los execve en un nodo de Kubernetes genera muchísimo volumen"
  "mysql|FW-02|fwin|clientes remotos de la BD: el puerto en escucha debe seguir abierto también en máximo"
  "mysql|FW-03|fwout:3306/tcp|la salida restringida corta la replicación hacia otros nodos"
  "mysql|UPD-04|skip|aplicar parches ahora reinicia la BD (hágalo en ventana de mantenimiento)"
  "mysql|SVC-05|pkeep|pánico pararía la base de datos"
  "postgresql|FW-02|fwin|clientes remotos de la BD: el puerto en escucha debe seguir abierto también en máximo"
  "postgresql|FW-03|fwout:5432/tcp|la salida restringida corta la replicación/streaming a réplicas"
  "postgresql|UPD-04|skip|aplicar parches ahora reinicia PostgreSQL"
  "postgresql|USR-10|shell:postgres|'su - postgres' y scripts de backup dependen de que la cuenta postgres tenga shell"
  "postgresql|SVC-05|pkeep|pánico pararía PostgreSQL"
  "mongodb|FW-03|fwout:27017/tcp|la salida restringida corta el replica set"
  "mongodb|UPD-04|skip|aplicar parches ahora reinicia MongoDB"
  "mongodb|FW-02|fwin|clientes remotos de la BD"
  "mongodb|SVC-05|pkeep|pánico pararía MongoDB"
  "redis|FW-03|fwout:6379/tcp,26379/tcp|réplicas y Sentinel en otros nodos"
  "redis|FW-02|fwin|clientes remotos de Redis"
  "redis|SVC-05|pkeep|pánico pararía Redis"
  "elastic|FS-05|skip|Elasticsearch/OpenSearch extraen librerías nativas (JNA) en /tmp: noexec impide arrancar"
  "elastic|FW-03|fwout:9300/tcp,9200/tcp|tráfico entre nodos del clúster"
  "elastic|FW-02|fwin|clientes remotos y nodos del clúster"
  "elastic|UPD-04|skip|aplicar parches ahora reinicia el nodo del clúster"
  "elastic|SVC-05|pkeep|pánico pararía el clúster"
  "web|FW-02|fwin|en máximo sólo se permiten SSH y --allow-in: 80/443 quedarían cerrados"
  "web|FW-03|warn|aplicaciones que llaman a APIs, BD o SMTP en puertos distintos de 80/443 (FW_ALLOW_OUT)"
  "web|USR-09,USR-14|warn|umask 027 y homes 750 pueden dejar ficheros/UserDir ilegibles para el usuario del servidor web"
  "web|SVC-05|pkeep|pánico pararía el servidor web"
  "libvirt|SYS-32,SYS-33,SYS-26,SYS-27|router|la red NAT de las VMs necesita reenvío"
  "libvirt|FW-02|warn|libvirt gestiona sus reglas de NAT; con firewalld use la zona libvirt"
  "libvirt|MAC-03,MAC-04|warn|sVirt (AppArmor/SELinux) confina las VMs: discos en rutas no estándar pueden fallar"
  "libvirt|SVC-05|pkeep|pánico pararía libvirt (las VMs siguen corriendo pero sin gestión)"
  "nfs|SVC-03|keep|NFSv3 necesita rpcbind"
  "nfs|FW-02|fwin|clientes NFS remotos (2049, 111 y mountd)"
  "nfs|SVC-05|pkeep|pánico pararía el servidor NFS"
  "samba|FW-02|fwin|clientes SMB remotos (445)"
  "samba|SVC-05|pkeep|pánico pararía Samba"
  "netfs|FW-03|fwout:2049/tcp,111/tcp,111/udp,445/tcp|la salida restringida corta los montajes NFS/SMB activos"
  "netfs|SVC-03|keep|montajes NFSv3 necesitan rpcbind"
  "wireguard|SYS-26,SYS-27,SYS-32,SYS-33|router|un gateway VPN necesita reenvío y rp_filter laxo"
  "wireguard|FW-02|fwin|el puerto UDP de WireGuard debe seguir abierto"
  "wireguard|FW-03|fwout:51820/udp|la salida restringida corta los túneles hacia otros peers"
  "wireguard|PNC-01|skip|el módulo wireguard no podría cargarse"
  "wireguard|FW-04|warn|en pánico, si administra por la VPN use --admin-ip con la IP de la VPN"
  "openvpn|SYS-26,SYS-27,SYS-32,SYS-33|router|un servidor OpenVPN necesita reenvío"
  "openvpn|FW-02|fwin|el puerto de OpenVPN debe seguir abierto"
  "openvpn|FW-03|fwout:1194/udp,1194/tcp|clientes OpenVPN salientes"
  "openvpn|FW-04|warn|en pánico, si administra por la VPN use --admin-ip con la IP de la VPN"
  "ipsec|SYS-26,SYS-27,SYS-32,SYS-33|router|un gateway IPsec necesita reenvío"
  "ipsec|FW-03|fwout:500/udp,4500/udp|la salida restringida corta IKE/NAT-T"
  "overlay|FW-03|fwout:41641/udp,9993/udp,3478/udp|Tailscale/ZeroTier usan UDP saliente (además de 443)"
  "overlay|FW-04|warn|en pánico, si administra por Tailscale/ZeroTier use --admin-ip con esa IP"
  "mail|FW-03|fwout:25/tcp,465/tcp,587/tcp|la salida restringida impide entregar correo"
  "mail|FW-02|fwin|el MTA/IMAP debe seguir recibiendo en máximo"
  "mail|SVC-05|pkeep|pánico pararía el correo"
  "ldap|FW-03|fwout:389/tcp,636/tcp,88/tcp,88/udp,464/tcp,464/udp,3268/tcp,3269/tcp|sin LDAP/Kerberos salientes los usuarios del dominio no pueden iniciar sesión"
  "ldap|USR-07|warn|faillock con SSSD: en RHEL se conserva el perfil authselect actual (sssd); revise que los admins del dominio no queden bloqueados"
  "ldap|SSH-28,FW-04,USR-19|warn|en pánico AllowUsers y el bloqueo sólo contemplan ADMIN_USERS: añada sus admins de dominio"
  "monitor|FW-03|fwout:10051/tcp,9997/tcp,1514/tcp,1515/tcp,4317/tcp|agentes que envían datos a Zabbix/Splunk/Wazuh/OTLP"
  "monitor|FW-02|fwin|el servidor de monitorización debe poder consultar al agente (9100, 10050)"
  "monitor|SYS-36|skip|perf_event_paranoid=3 rompe agentes basados en perf/eBPF (Datadog, Falco, Pixie, APM)"
  "monitor|LOG-03,LOG-04|warn|osquery/Wazuh/algunos EDR usan el socket de auditoría y compiten con auditd"
  "monitor|PNC-01|skip|Falco/EDR pueden necesitar cargar su módulo del kernel"
  "monitor|SVC-05|pkeep|pánico pararía los agentes (perdería visibilidad del incidente)"
  "ports|FW-02|fwin|puertos en escucha que no se permitirían en máximo sin --allow-in"
  "ports|FW-04|warn|el lockdown de pánico cierra todos los puertos salvo SSH desde la IP admin"
)

declare -gA WL_FOUND=() WL_EVID=() WL_UNITS=() WL_LABEL=()
WL_ORDER=()
WL_LISTEN=""          # puertos en escucha (todas las direcciones) "puerto/proto"
WL_LISTEN_EXT=""      # sólo accesibles desde la red
PRECHECK_ROWS=()      # clave|IDs|acción|motivo|aplicado(0/1)|detalle
SAFE_ADJUSTMENTS=()   # descripciones legibles de lo que --safe cambió

_wl_units_on() { # imprime las unidades (admite patrones) habilitadas o activas
  have systemctl || return 0
  local pat
  for pat in $1; do
    case $pat in -) continue ;; *.service|*.socket|*.timer) ;; *) pat="$pat.service" ;; esac
    { systemctl list-unit-files --no-legend --state=enabled "$pat" 2>/dev/null || true
      if (( HAS_SYSTEMD )); then systemctl list-units --no-legend --plain --state=active "$pat" 2>/dev/null || true; fi
    } | awk 'NF{print $1}'
  done | sort -u
}

_wl_listen_scan() {
  have ss || return 0
  WL_LISTEN=$(ss -H -tuln 2>/dev/null | awk '{proto=($1 ~ /tcp/)?"tcp":"udp"; n=split($5,a,":"); if (a[n] ~ /^[0-9]+$/) print a[n]"/"proto}' | sort -u | tr '\n' ' ' || true)
  if declare -F listening_ports >/dev/null; then
    WL_LISTEN_EXT=$(listening_ports | tr '\n' ' ' || true)
  fi
}

detect_workloads() {
  local def key cat label units procs bins paths ports ev p f found
  WL_FOUND=(); WL_EVID=(); WL_UNITS=(); WL_ORDER=()
  _wl_listen_scan
  for def in "${WL_DEFS[@]}"; do
    IFS='|' read -r key cat label units procs bins paths ports <<<"$def"
    ev=""; found=""
    found=$(_wl_units_on "$units" | tr '\n' ' ' || true)
    found=$(trim "$found")
    [[ -n "$found" ]] && ev+="unidades: $found; "
    for p in $procs; do
      [[ "$p" == - ]] && continue
      if have pgrep && pgrep -x "$p" >/dev/null 2>&1; then ev+="proceso $p; "; fi
    done
    for p in $bins; do [[ "$p" != - ]] && have "$p" && ev+="binario $(command -v "$p"); "; done
    for p in $paths; do
      [[ "$p" == - ]] && continue
      for f in $p; do [[ -e "$f" ]] && { ev+="ruta $f; "; break; }; done
    done
    local strong=$ev
    for p in $ports; do
      [[ "$p" == - ]] && continue
      [[ " $WL_LISTEN " == *" $p "* ]] && ev+="escucha $p; "
    done
    # Sólo un puerto conocido en escucha: evidencia débil (otro programa podría usarlo)
    [[ -z "$strong" && -n "$ev" ]] && { ev="posible, sólo por puerto: $ev"; label="$label (posible)"; }
    if [[ "$key" == netfs ]]; then
      f=$(awk '$3 ~ /^(nfs|nfs4|cifs|smb3)$/ {print $2}' /proc/mounts 2>/dev/null | head -n3 | tr '\n' ' ' || true)
      [[ -n "$f" ]] && ev+="montajes remotos: $f; "
    fi
    if [[ "$key" == podman && -n "$ev" ]] && [[ -s /etc/subuid ]]; then ev+="/etc/subuid con rangos (rootless); "; fi
    [[ -n "$ev" ]] || continue
    WL_FOUND[$key]=$cat; WL_EVID[$key]=${ev%; }; WL_UNITS[$key]=$found; WL_LABEL[$key]=$label
    WL_ORDER+=("$key")
  done
  # Puertos accesibles desde la red que ningún perfil explica: también cuentan
  local extra=""
  for p in $WL_LISTEN_EXT; do
    in_list "${p%/*}" "$SSH_PORTS" && [[ "$p" == */tcp ]] && continue
    extra+="$p "
  done
  if [[ -n "$extra" ]]; then
    WL_FOUND[ports]=red; WL_EVID[ports]="escuchando hacia la red: $(trim "$extra")"; WL_LABEL[ports]="Puertos en escucha"
    WL_ORDER+=("ports")
  fi
}

# ¿Alguno de los IDs aplica al nivel elegido? (sin nivel: todos)
_ids_in_level() {
  local id
  for id in ${1//,/ }; do
    [[ -n "${CMETA_LVL[$id]:-}" ]] || continue
    if (( LEVEL_NUM == 0 )) || spec_has_level "${CMETA_LVL[$id]}" "$LEVEL_NUM"; then return 0; fi
  done
  return 1
}

_safe_action_text() {
  case $1 in
    skip)    printf 'omitir' ;;
    router)  printf 'mantener reenvío (modo router)' ;;
    fwin)    printf 'permitir puertos en escucha también en máximo' ;;
    fwout:*) printf 'permitir salida %s' "${1#fwout:}" ;;
    keep)    printf 'no deshabilitar sus servicios' ;;
    pkeep)   printf 'no pararlo en pánico' ;;
    shell:*) printf 'conservar shell de %s' "${1#shell:}" ;;
    *)       printf 'sólo aviso' ;;
  esac
}

# Construye PRECHECK_ROWS y, si SAFE_MODE=1, aplica las adaptaciones.
evaluate_workload_impacts() {
  local imp key ids act why applied det id
  PRECHECK_ROWS=(); SAFE_ADJUSTMENTS=()
  for imp in "${WL_IMPACTS[@]}"; do
    IFS='|' read -r key ids act why <<<"$imp"
    [[ -n "${WL_FOUND[$key]:-}" ]] || continue
    _ids_in_level "$ids" || continue
    applied=0; det=""
    case $act in
      router) if (( ROUTER_DETECTED )); then applied=1; det="ya activo por detección automática"; fi ;;
      warn)   det="" ;;
    esac
    if (( SAFE_MODE )) && [[ "$act" != warn ]] && (( ! applied )); then
      applied=1
      # SAFE_SKIP es asociativo (control.sh); FW_AUTO_ALLOW_MAXLEVEL lo lee 40-firewall.sh
      # shellcheck disable=SC2004,SC2034
      case $act in
        skip)    for id in ${ids//,/ }; do [[ -n "${SAFE_SKIP[$id]:-}" ]] || SAFE_SKIP[$id]="${WL_LABEL[$key]}: $why"; done ;;
        router)  ROUTER_DETECTED=1 ;;
        fwin)    FW_AUTO_ALLOW_MAXLEVEL=3 ;;
        fwout:*) FW_ALLOW_OUT=$(trim "$FW_ALLOW_OUT ${act#fwout:}"); FW_ALLOW_OUT=${FW_ALLOW_OUT//,/ } ;;
        keep)    SERVICES_KEEP=$(trim "$SERVICES_KEEP rpcbind rpcbind.socket ${WL_UNITS[$key]}") ;;
        pkeep)   PANIC_KEEP_SERVICES=$(trim "$PANIC_KEEP_SERVICES ${WL_UNITS[$key]}")
                 [[ -n "${WL_UNITS[$key]}" ]] || det="sin unidad systemd detectada" ;;
        shell:*) KEEP_SHELL_USERS=$(trim "$KEEP_SHELL_USERS ${act#shell:}") ;;
      esac
      SAFE_ADJUSTMENTS+=("${ids} — $(_safe_action_text "$act") (${WL_LABEL[$key]})")
    fi
    PRECHECK_ROWS+=("$key|$ids|$act|$why|$applied|$det")
  done
}

precheck_conflicts() { # número de conflictos accionables (no sólo aviso) sin resolver
  local r n=0 key ids act why applied det
  for r in "${PRECHECK_ROWS[@]}"; do
    IFS='|' read -r key ids act why applied det <<<"$r"
    [[ "$act" != warn ]] && (( ! applied )) && n=$((n+1))
  done
  echo "$n"
}

print_precheck() {
  local key r k ids act why applied det tag
  printf '\n%s=== PRE-CHECK: cargas de trabajo críticas ===%s\n' "$C_BLD" "$C_RST"
  if (( ${#WL_ORDER[@]} == 0 )); then
    printf '  No se detectaron bases de datos, contenedores, VPN, web, virtualización ni agentes.\n'
  fi
  for key in "${WL_ORDER[@]}"; do
    printf '  %s●%s %s%s%s  (%s)\n' "$C_YLW" "$C_RST" "$C_BLD" "${WL_LABEL[$key]}" "$C_RST" "${WL_EVID[$key]}"
    for r in "${PRECHECK_ROWS[@]}"; do
      IFS='|' read -r k ids act why applied det <<<"$r"
      [[ "$k" == "$key" ]] || continue
      if [[ "$act" == warn ]]; then tag="${C_CYN}[aviso]${C_RST}"
      elif (( applied )); then tag="${C_GRN}[--safe: $(_safe_action_text "$act")${det:+, $det}]${C_RST}"
      else tag="${C_RED}[conflicto — con --safe: $(_safe_action_text "$act")]${C_RST}"; fi
      printf '      ↳ %-28s %s %s\n' "${ids//,/, }" "$why" "$tag"
    done
  done
  printf '  Puertos en escucha (todas las direcciones): %s\n' "${WL_LISTEN:-ninguno o sin ss}"
  printf '  Salvaguardas por defecto: SSH nunca se cierra; host enrutador=%s; firewall con reversión automática (%ss)\n' \
    "$( ((ROUTER_DETECTED)) && echo sí || echo no)" "$FW_CONFIRM_TIMEOUT"
  local n; n=$(precheck_conflicts)
  if (( SAFE_MODE )); then
    printf '  %sModo --safe ACTIVO:%s %d adaptaciones (ver reporte).\n' "$C_GRN$C_BLD" "$C_RST" "${#SAFE_ADJUSTMENTS[@]}"
  elif (( n > 0 )); then
    printf '  %s%d conflicto(s) sin resolver.%s Use %s--safe%s para omitir/suavizar esos controles, o --skip-control.\n' \
      "$C_RED$C_BLD" "$n" "$C_RST" "$C_BLD" "$C_RST"
  fi
  printf '\n'
}

# Guarda el pre-check en el directorio de la ejecución (para el reporte)
write_precheck_file() {
  [[ -n "${RUN_DIR:-}" && -d "$RUN_DIR" ]] || return 0
  local key r k ids act why applied det
  {
    for key in "${WL_ORDER[@]}"; do
      for r in "${PRECHECK_ROWS[@]}"; do
        IFS='|' read -r k ids act why applied det <<<"$r"
        [[ "$k" == "$key" ]] || continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "${WL_LABEL[$key]}" "${WL_EVID[$key]}" "$ids" "$act" "$applied" "$why" "$det"
      done
      grep -q "^$key|" < <(printf '%s\n' "${PRECHECK_ROWS[@]}") \
        || printf '%s\t%s\t%s\t-\t-\t0\t-\t-\n' "$key" "${WL_LABEL[$key]}" "${WL_EVID[$key]}"
    done
  } >"$RUN_DIR/precheck.tsv"
}

# Flujo completo del pre-check (detectar, evaluar, mostrar, guardar)
run_precheck() {
  detect_workloads
  evaluate_workload_impacts
  print_precheck
  write_precheck_file
}
