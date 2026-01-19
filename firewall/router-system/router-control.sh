#!/bin/bash
# router-control.sh - Control principal del sistema router

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directorios y archivos
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_DIR="$SCRIPT_DIR"
STATE_FILE="$CONFIG_DIR/router.state"
BACKUP_DIR="$CONFIG_DIR/backups"


# Cargar configuración desde .env del proyecto padre
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
if [ -f "$PARENT_DIR/.env" ]; then
    source "$PARENT_DIR/.env"
fi
LOG_FILE=$ROUTER_LOG

# Crear directorio de logs si no existe
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

# Interfaces (con valores por defecto si no están en .env)
INTERNET_IFACE="${INTERNET_IFACE:-wlp2s0}"  # Interfaz que conecta a internet
AP_IFACE="${AP_IFACE:-wlxc83a35b5a9f5}"     # Interfaz USB para punto de acceso
AP_IP="${AP_GATEWAY:-192.168.50.1}"
AP_SUBNET="${AP_NETWORK:-192.168.50.0/24}"
DHCP_START="${AP_DHCP_START:-192.168.50.10}"
DHCP_END="${AP_DHCP_END:-192.168.50.100}"
DHCP_RANGE="$DHCP_START,$DHCP_END"

# PID files para servicios (en /tmp para evitar problemas de permisos)
FIREWALL_PID="/tmp/firewall_manager.pid"
CAPTURE_PID="/tmp/traffic_capture.pid"
DASHBOARD_PID="/tmp/dashboard.pid"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
    echo ""
}

print_status() {
    if [ -f "$STATE_FILE" ] && [ "$(cat $STATE_FILE)" = "active" ]; then
        echo -e "${GREEN}[ACTIVO]${NC} Modo Router está activado"
        return 0
    else
        echo -e "${YELLOW}[INACTIVO]${NC} Modo Router está desactivado"
        return 1
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}Error: Este script debe ejecutarse como root${NC}"
        exit 1
    fi
}

check_interfaces() {
    if ! ip link show "$INTERNET_IFACE" &> /dev/null; then
        echo -e "${RED}Error: Interfaz $INTERNET_IFACE no encontrada${NC}"
        exit 1
    fi
    
    if ! ip link show "$AP_IFACE" &> /dev/null; then
        echo -e "${RED}Error: Interfaz $AP_IFACE no encontrada${NC}"
        echo "Interfaces disponibles:"
        ip link show | grep -E '^[0-9]+:' | cut -d: -f2
        exit 1
    fi
}

backup_config() {
    log "Creando backup de configuración actual..."
    mkdir -p "$BACKUP_DIR"
    
    # Backup de iptables
    iptables-save > "$BACKUP_DIR/iptables.rules"
    
    # Backup de sysctl (guardar solo el valor)
    cat /proc/sys/net/ipv4/ip_forward > "$BACKUP_DIR/ip_forward.bak" 2>/dev/null || echo "0" > "$BACKUP_DIR/ip_forward.bak"
    
    # Backup de NetworkManager state
    if systemctl is-active --quiet NetworkManager; then
        echo "active" > "$BACKUP_DIR/networkmanager.state"
    else
        echo "inactive" > "$BACKUP_DIR/networkmanager.state"
    fi
    
    # Backup de configuración de interfaces
    if [ -f "/etc/network/interfaces" ]; then
        cp /etc/network/interfaces "$BACKUP_DIR/interfaces.bak"
    fi
    
    log "Backup completado"
}

restore_config() {
    log "Restaurando configuración original..."
    
    # Restaurar iptables
    if [ -f "$BACKUP_DIR/iptables.rules" ]; then
        iptables-restore < "$BACKUP_DIR/iptables.rules"
    else
        # Si no hay backup, limpiar todas las reglas
        iptables -F
        iptables -t nat -F
        iptables -t mangle -F
        iptables -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
    fi
    
    # Restaurar ip_forward
    if [ -f "$BACKUP_DIR/ip_forward.bak" ]; then
        cat "$BACKUP_DIR/ip_forward.bak" > /proc/sys/net/ipv4/ip_forward
    else
        echo 0 > /proc/sys/net/ipv4/ip_forward
    fi
    
    # Restaurar NetworkManager
    if [ -f "$BACKUP_DIR/networkmanager.state" ] && [ "$(cat $BACKUP_DIR/networkmanager.state)" = "active" ]; then
        systemctl start NetworkManager
    fi
    
    log "Configuración restaurada"
}

setup_hostapd() {
    log "Configurando hostapd..."
    
    # Si ya existe hostapd.conf (creado por install.sh), no lo sobrescribimos
    if [ -f "/etc/hostapd/hostapd.conf" ]; then
        log "Usando configuración existente de hostapd"
    else
        log "Creando configuración por defecto de hostapd"
        # Leer valores desde .env del proyecto padre si existe
        PARENT_DIR="$(dirname "$SCRIPT_DIR")"
        if [ -f "$PARENT_DIR/.env" ]; then
            source "$PARENT_DIR/.env"
        fi
        
        # Usar valores de .env o defaults
        WIFI_SSID=${WIFI_SSID:-"RouterFirewall"}
        WIFI_PASSWORD=${WIFI_PASSWORD:-"SecurePass123"}
        
        cat > /etc/hostapd/hostapd.conf <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=$WIFI_SSID
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$WIFI_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
    fi

    # Configurar systemd para que no inicie automáticamente
    systemctl disable hostapd 2>/dev/null || true
}

setup_dnsmasq() {
    log "Configurando dnsmasq..."
    
    # Backup de config original si existe
    if [ -f /etc/dnsmasq.conf ] && [ ! -f "$BACKUP_DIR/dnsmasq.conf.bak" ]; then
        cp /etc/dnsmasq.conf "$BACKUP_DIR/dnsmasq.conf.bak"
    fi
    
    # Asegurar que las variables están definidas
    DHCP_START="${AP_DHCP_START:-192.168.50.10}"
    DHCP_END="${AP_DHCP_END:-192.168.50.100}"
    AP_IP="${AP_GATEWAY:-192.168.50.1}"
    
    cat > /etc/dnsmasq.conf <<EOF
# Router mode configuration
interface=$AP_IFACE
bind-interfaces
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h
dhcp-option=3,$AP_IP
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
EOF

    systemctl disable dnsmasq 2>/dev/null || true
}

start_router_mode() {
    echo ""
    log "=== ACTIVANDO MODO ROUTER ==="
    
    # Verificar que no esté ya activo
    if print_status &>/dev/null; then
        echo -e "${YELLOW}El modo router ya está activo${NC}"
        exit 0
    fi
    
    # Crear backup antes de cualquier cambio
    backup_config
    
    # Desconectar solo la interfaz AP de NetworkManager (NO detener el servicio)
    log "Desconectando interfaz AP de NetworkManager..."
    nmcli device set "$AP_IFACE" managed no 2>/dev/null || true
    
    # Configurar IP estática en interfaz AP
    log "Configurando interfaz AP ($AP_IFACE)..."
    ip link set "$AP_IFACE" down
    ip addr flush dev "$AP_IFACE"
    ip addr add "$AP_IP/24" dev "$AP_IFACE"
    ip link set "$AP_IFACE" up
    
    # Habilitar IP forwarding
    log "Habilitando IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Configurar NAT y forwarding
    log "Configurando iptables (NAT y forwarding)..."
    iptables -t nat -A POSTROUTING -o "$INTERNET_IFACE" -j MASQUERADE
    iptables -A FORWARD -i "$AP_IFACE" -o "$INTERNET_IFACE" -j ACCEPT
    iptables -A FORWARD -i "$INTERNET_IFACE" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # Crear chain para categorías
    iptables -N CATEGORY_FILTER 2>/dev/null || iptables -F CATEGORY_FILTER
    iptables -I FORWARD 1 -j CATEGORY_FILTER
    
    # Iniciar hostapd
    log "Iniciando punto de acceso WiFi..."
    # Desenmascarar servicio si está masked
    systemctl unmask hostapd 2>/dev/null || true
    systemctl start hostapd 2>/dev/null
    sleep 2
    
    if ! systemctl is-active --quiet hostapd; then
        echo -e "${RED}Error: hostapd no pudo iniciarse${NC}"
        echo "Revisa los logs: journalctl -u hostapd -n 50"
        stop_router_mode
        exit 1
    fi
    
    # Iniciar dnsmasq
    log "Iniciando servidor DHCP..."
    # Desenmascarar servicio si está masked
    systemctl unmask dnsmasq 2>/dev/null || true
    systemctl start dnsmasq 2>/dev/null
    sleep 1
    
    if ! systemctl is-active --quiet dnsmasq; then
        echo -e "${RED}Error: dnsmasq no pudo iniciarse${NC}"
        echo "Revisa los logs: journalctl -u dnsmasq -n 50"
        stop_router_mode
        exit 1
    fi
    
    # Nota: Los servicios Python se inician desde quick_start.sh
    # para mayor flexibilidad y no depender de /etc/router-system
    log "Servicios Python deben iniciarse por separado (ver quick_start.sh)"
    
    # Marcar como activo
    echo "active" > "$STATE_FILE"
    
    # Leer configuración real de hostapd
    ACTUAL_SSID=$(grep "^ssid=" /etc/hostapd/hostapd.conf | cut -d= -f2)
    ACTUAL_PASSWORD=$(grep "^wpa_passphrase=" /etc/hostapd/hostapd.conf | cut -d= -f2)
    
    echo -e "${GREEN}=== MODO ROUTER ACTIVADO EXITOSAMENTE ===${NC}"
    echo ""
    echo "Red WiFi: $ACTUAL_SSID"
    echo "Password: $ACTUAL_PASSWORD"
    echo "IP del router: $AP_IP"
    echo "Rango DHCP: $DHCP_RANGE"
    echo ""
    echo "Servicios disponibles:"
    [ -f "$FIREWALL_PID" ] && echo "  - API Firewall: http://$AP_IP:$FIREWALL_PORT"
    [ -f "$DASHBOARD_PID" ] && echo "  - Dashboard: http://$AP_IP:$DASHBOARD_PORT"
    echo ""
    log "Modo router activado correctamente"
}

stop_router_mode() {
    echo ""
    log "=== DESACTIVANDO MODO ROUTER ==="
    
    # Detener servicios Python
    if [ -f "$FIREWALL_PID" ]; then
        log "Deteniendo gestor de firewall..."
        kill $(cat "$FIREWALL_PID") 2>/dev/null || true
        rm -f "$FIREWALL_PID"
    fi
    
    if [ -f "$CAPTURE_PID" ]; then
        log "Deteniendo captura de tráfico..."
        kill $(cat "$CAPTURE_PID") 2>/dev/null || true
        rm -f "$CAPTURE_PID"
    fi
    
    if [ -f "$DASHBOARD_PID" ]; then
        log "Deteniendo dashboard..."
        kill $(cat "$DASHBOARD_PID") 2>/dev/null || true
        rm -f "$DASHBOARD_PID"
    fi
    
    # Detener servicios
    log "Deteniendo servicios..."
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    
    # Restaurar configuración de red
    log "Restaurando configuración de red..."
    ip addr flush dev "$AP_IFACE" 2>/dev/null || true
    ip link set "$AP_IFACE" down 2>/dev/null || true
    
    # Restaurar configuración original
    restore_config
    
    # Restaurar dnsmasq.conf si hay backup
    if [ -f "$BACKUP_DIR/dnsmasq.conf.bak" ]; then
        cp "$BACKUP_DIR/dnsmasq.conf.bak" /etc/dnsmasq.conf
    fi
    
    # Reconectar interfaz AP a NetworkManager
    log "Reconectando interfaz AP a NetworkManager..."
    nmcli device set "$AP_IFACE" managed yes 2>/dev/null || true
    # Dar tiempo a NetworkManager para reconectar
    sleep 2
    
    # Marcar como inactivo
    echo "inactive" > "$STATE_FILE"
    
    echo -e "${GREEN}=== MODO ROUTER DESACTIVADO ===${NC}"
    echo "El sistema ha vuelto a su configuración normal"
    log "Modo router desactivado correctamente"
}

install_dependencies() {
    log "Instalando dependencias..."
    
    apt update
    apt install -y \
        hostapd \
        dnsmasq \
        iptables-persistent \
        python3 \
        python3-pip \
        python3-flask \
        python3-scapy \
        python3-requests \
        iw \
        rfkill
    
    # Instalar dependencias Python
    pip3 install flask scapy requests psutil
    
    log "Dependencias instaladas"
}

setup_system() {
    log "=== CONFIGURACIÓN INICIAL DEL SISTEMA ==="
    
    check_root
    check_interfaces
    
    # Crear directorios
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Instalar dependencias
    install_dependencies
    
    # Configurar servicios
    setup_hostapd
    setup_dnsmasq
    
    # Crear backup inicial
    backup_config
    
    # Marcar como inactivo
    echo "inactive" > "$STATE_FILE"
    
    echo -e "${GREEN}=== CONFIGURACIÓN COMPLETADA ===${NC}"
    echo ""
    echo "Sistema instalado correctamente. Puedes usar:"
    echo "  sudo router-control start   - Activar modo router"
    echo "  sudo router-control stop    - Desactivar modo router"
    echo "  sudo router-control status  - Ver estado actual"
    echo ""
    log "Configuración inicial completada"
}

show_status() {
    echo "=== ESTADO DEL SISTEMA ROUTER ==="
    echo ""
    
    print_status
    echo ""
    
    if [ -f "$STATE_FILE" ] && [ "$(cat $STATE_FILE)" = "active" ]; then
        echo "Servicios:"
        systemctl is-active --quiet hostapd && echo -e "  hostapd: ${GREEN}activo${NC}" || echo -e "  hostapd: ${RED}inactivo${NC}"
        systemctl is-active --quiet dnsmasq && echo -e "  dnsmasq: ${GREEN}activo${NC}" || echo -e "  dnsmasq: ${RED}inactivo${NC}"
        
        echo ""
        echo "Interfaces:"
        echo "  Internet: $INTERNET_IFACE ($(ip -4 addr show $INTERNET_IFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo 'sin IP'))"
        echo "  AP: $AP_IFACE ($AP_IP)"
        
        echo ""
        echo "Clientes conectados:"
        iw dev "$AP_IFACE" station dump 2>/dev/null | grep Station | wc -l | xargs echo "  Total:"
        
        echo ""
        echo "Procesos Python:"
        [ -f "$FIREWALL_PID" ] && ps -p $(cat "$FIREWALL_PID") &>/dev/null && echo -e "  Firewall Manager: ${GREEN}corriendo${NC}" || echo -e "  Firewall Manager: ${RED}detenido${NC}"
        [ -f "$CAPTURE_PID" ] && ps -p $(cat "$CAPTURE_PID") &>/dev/null && echo -e "  Traffic Capture: ${GREEN}corriendo${NC}" || echo -e "  Traffic Capture: ${RED}detenido${NC}"
        [ -f "$DASHBOARD_PID" ] && ps -p $(cat "$DASHBOARD_PID") &>/dev/null && echo -e "  Dashboard: ${GREEN}corriendo${NC}" || echo -e "  Dashboard: ${RED}detenido${NC}"
    fi
}

# Menu principal
case "${1:-}" in
    start)
        check_root
        check_interfaces
        start_router_mode
        ;;
    stop)
        check_root
        stop_router_mode
        ;;
    restart)
        check_root
        check_interfaces
        stop_router_mode
        sleep 2
        start_router_mode
        ;;
    status)
        show_status
        ;;
    setup)
        check_root
        setup_system
        ;;
    *)
        echo "Uso: $0 {setup|start|stop|restart|status}"
        echo ""
        echo "Comandos:"
        echo "  setup   - Configuración inicial (solo primera vez)"
        echo "  start   - Activar modo router"
        echo "  stop    - Desactivar modo router"
        echo "  restart - Reiniciar modo router"
        echo "  status  - Ver estado actual"
        exit 1
        ;;
esac