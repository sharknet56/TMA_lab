#!/bin/bash
# install.sh - Instalación completa del sistema router

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPTS_DIR"
BACKUP_DIR="$CONFIG_DIR/backups"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Sistema Router/Firewall - Instalación Automática      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Este script debe ejecutarse como root (usa sudo)${NC}"
    exit 1
fi

# Función para preguntar al usuario
ask_user() {
    local prompt="$1"
    local var_name="$2"
    local default="$3"
    
    read -p "$prompt [$default]: " user_input
    eval $var_name="${user_input:-$default}"
}

echo -e "${YELLOW}Paso 1: Configuración de interfaces${NC}"
echo "Listando interfaces WiFi disponibles:"
echo ""
ip link show | grep -E '^[0-9]+:.*wl' | cut -d: -f2 | sed 's/^ /  - /'
echo ""

ask_user "Interfaz que conecta a internet" INTERNET_IFACE "wlan0"
ask_user "Interfaz para punto de acceso (USB)" AP_IFACE "wlan1"

# Verificar interfaces
if ! ip link show "$INTERNET_IFACE" &> /dev/null; then
    echo -e "${RED}Error: Interfaz $INTERNET_IFACE no encontrada${NC}"
    exit 1
fi

if ! ip link show "$AP_IFACE" &> /dev/null; then
    echo -e "${RED}Error: Interfaz $AP_IFACE no encontrada${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Interfaces verificadas${NC}"

echo ""
echo -e "${YELLOW}Paso 2: Configuración de red WiFi${NC}"
ask_user "Nombre de la red WiFi (SSID)" WIFI_SSID "RouterFirewall"
ask_user "Contraseña WiFi (mínimo 8 caracteres)" WIFI_PASSWORD "SecurePass123"

if [ ${#WIFI_PASSWORD} -lt 8 ]; then
    echo -e "${RED}Error: La contraseña debe tener al menos 8 caracteres${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Paso 3: Configuración de API del modelo${NC}"
ask_user "URL del modelo para PCAP" MODEL_PCAP_URL "http://localhost:8000/pcap"
ask_user "URL del modelo para Flows" MODEL_FLOWS_URL "http://localhost:8000/flows"

echo ""
echo -e "${YELLOW}Paso 4: Instalando dependencias...${NC}"
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
    python3-psutil \
    iw \
    rfkill \
    curl \
    net-tools

echo -e "${GREEN}✓ Paquetes del sistema instalados${NC}"

echo "Verificando entorno virtual unificado..."
PARENT_DIR="$(dirname "$SCRIPTS_DIR")"
VENV_DIR="$PARENT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creando entorno virtual unificado en $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip -q
    echo -e "${GREEN}✓ Entorno virtual creado${NC}"
fi

echo "Instalando dependencias desde requirements.txt unificado..."
if [ -f "$PARENT_DIR/requirements.txt" ]; then
    "$VENV_DIR/bin/pip" install -r "$PARENT_DIR/requirements.txt" -q
    echo -e "${GREEN}✓ Dependencias Python instaladas desde requirements.txt${NC}"
else
    echo -e "${YELLOW}⚠ No se encontró requirements.txt, instalando dependencias básicas...${NC}"
    "$VENV_DIR/bin/pip" install flask scapy requests psutil -q
    echo -e "${GREEN}✓ Dependencias básicas instaladas${NC}"
fi

echo ""
echo -e "${YELLOW}Paso 5: Creando estructura de directorios...${NC}"
mkdir -p "$BACKUP_DIR"

echo -e "${GREEN}✓ Directorios creados${NC}"

echo ""
echo -e "${YELLOW}Paso 6: Configurando hostapd...${NC}"
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

# Deshabilitar inicio automático
systemctl disable hostapd 2>/dev/null || true
systemctl stop hostapd 2>/dev/null || true

echo -e "${GREEN}✓ hostapd configurado${NC}"

echo ""
echo -e "${YELLOW}Paso 7: Configurando dnsmasq...${NC}"

# Backup de configuración original
if [ -f /etc/dnsmasq.conf ]; then
    cp /etc/dnsmasq.conf "$CONFIG_DIR/backups/dnsmasq.conf.original"
fi

cat > /etc/dnsmasq.conf <<EOF
# Router mode configuration
interface=$AP_IFACE
bind-interfaces
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,24h
dhcp-option=3,192.168.50.1
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
EOF

systemctl disable dnsmasq 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true

echo -e "${GREEN}✓ dnsmasq configurado${NC}"

echo ""
echo -e "${YELLOW}Paso 8: Configurando estado inicial...${NC}"
echo "inactive" > "$CONFIG_DIR/router.state"
echo -e "${GREEN}✓ Estado inicial configurado${NC}"

echo ""
echo -e "${YELLOW}Paso 9: Creando backup de configuración actual...${NC}"
iptables-save > "$BACKUP_DIR/iptables.rules.original"
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward > "$BACKUP_DIR/sysctl.conf.original" || true
echo -e "${GREEN}✓ Backup creado${NC}"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗"
echo "║              INSTALACIÓN COMPLETADA EXITOSAMENTE           ║"
echo "╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Configuración:${NC}"
echo "  - Interfaz Internet: $INTERNET_IFACE"
echo "  - Interfaz AP: $AP_IFACE"
echo "  - SSID: $WIFI_SSID"
echo "  - IP Router: 192.168.50.1"
echo "  - Rango DHCP: 192.168.50.10-100"
echo "  - Directorio: $CONFIG_DIR"
echo ""
echo -e "${BLUE}Para iniciar el sistema:${NC}"
echo "  ${GREEN}cd $SCRIPTS_DIR/..${NC}"
echo "  ${GREEN}sudo ./quick_start.sh${NC}"
echo ""
echo -e "${BLUE}Servicios web (cuando el router esté activo):${NC}"
echo "  - Dashboard: http://192.168.50.1:8081"
echo "  - API Firewall: http://192.168.50.1:5000"
echo ""
