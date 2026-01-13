#!/bin/bash
# install.sh - Instalación completa del sistema router

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CONFIG_DIR="/etc/router-system"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

echo "Instalando dependencias Python..."
python3 -m venv .venv
source .venv/bin/activate
pip3 install --upgrade pip
pip3 install flask scapy requests psutil

echo -e "${GREEN}✓ Dependencias Python instaladas${NC}"

echo ""
echo -e "${YELLOW}Paso 5: Creando estructura de directorios...${NC}"
mkdir -p "$CONFIG_DIR"
mkdir -p "$CONFIG_DIR/backups"
mkdir -p /var/log

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
echo -e "${YELLOW}Paso 8: Creando scripts del sistema...${NC}"

# Script principal de control
cat > "$CONFIG_DIR/router-control.sh" <<'CONTROLSCRIPT'
#!/bin/bash
# Este archivo será reemplazado con el contenido del artifact router_toggle_system
CONTROLSCRIPT

# Copiar el script de control desde el artifact
if [ -f "$SCRIPTS_DIR/router-control.sh" ]; then
    cp "$SCRIPTS_DIR/router-control.sh" "$CONFIG_DIR/router-control.sh"
else
    echo -e "${YELLOW}Advertencia: router-control.sh no encontrado en directorio actual${NC}"
    echo "Deberás copiarlo manualmente a $CONFIG_DIR/"
fi

chmod +x "$CONFIG_DIR/router-control.sh"

# Crear enlace simbólico para usar desde cualquier lugar
ln -sf "$CONFIG_DIR/router-control.sh" /usr/local/bin/router-control

echo -e "${GREEN}✓ Script de control instalado (comando: router-control)${NC}"

# Firewall Manager
cat > "$CONFIG_DIR/firewall_manager.py" <<'FWSCRIPT'
# Este archivo será reemplazado con el contenido del artifact firewall_manager_script
FWSCRIPT

if [ -f "$SCRIPTS_DIR/firewall_manager.py" ]; then
    cp "$SCRIPTS_DIR/firewall_manager.py" "$CONFIG_DIR/firewall_manager.py"
fi

chmod +x "$CONFIG_DIR/firewall_manager.py"
echo -e "${GREEN}✓ Firewall Manager instalado${NC}"

# Traffic Capture
cat > "$CONFIG_DIR/traffic_capture.py" <<'CAPSCRIPT'
# Este archivo será reemplazado con el contenido del artifact traffic_capture_script
CAPSCRIPT

if [ -f "$SCRIPTS_DIR/traffic_capture.py" ]; then
    cp "$SCRIPTS_DIR/traffic_capture.py" "$CONFIG_DIR/traffic_capture.py"
fi

# Configurar URLs del modelo
sed -i "s|MODEL_BASE_URL = .*|MODEL_BASE_URL = os.getenv('MODEL_URL', '${MODEL_PCAP_URL%/*}')|" "$CONFIG_DIR/traffic_capture.py"

chmod +x "$CONFIG_DIR/traffic_capture.py"
echo -e "${GREEN}✓ Traffic Capture instalado${NC}"

# Dashboard
cat > "$CONFIG_DIR/dashboard.py" <<'DASHSCRIPT'
# Este archivo será reemplazado con el contenido del artifact dashboard_web
DASHSCRIPT

if [ -f "$SCRIPTS_DIR/dashboard.py" ]; then
    cp "$SCRIPTS_DIR/dashboard.py" "$CONFIG_DIR/dashboard.py"
fi

chmod +x "$CONFIG_DIR/dashboard.py"
echo -e "${GREEN}✓ Dashboard instalado${NC}"

# Actualizar variables en el script de control
sed -i "s/INTERNET_IFACE=\".*\"/INTERNET_IFACE=\"$INTERNET_IFACE\"/" "$CONFIG_DIR/router-control.sh"
sed -i "s/AP_IFACE=\".*\"/AP_IFACE=\"$AP_IFACE\"/" "$CONFIG_DIR/router-control.sh"

echo ""
echo -e "${YELLOW}Paso 9: Configurando estado inicial...${NC}"
echo "inactive" > "$CONFIG_DIR/router.state"
echo -e "${GREEN}✓ Estado inicial configurado${NC}"

echo ""
echo -e "${YELLOW}Paso 10: Creando backup de configuración actual...${NC}"
iptables-save > "$CONFIG_DIR/backups/iptables.rules.original"
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward > "$CONFIG_DIR/backups/sysctl.conf.original" || true
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
echo ""
echo -e "${BLUE}Comandos disponibles:${NC}"
echo "  ${GREEN}router-control start${NC}   - Activar modo router"
echo "  ${GREEN}router-control stop${NC}    - Desactivar modo router"
echo "  ${GREEN}router-control status${NC}  - Ver estado actual"
echo "  ${GREEN}router-control restart${NC} - Reiniciar modo router"
echo ""
echo -e "${BLUE}Servicios web (cuando el router esté activo):${NC}"
echo "  - Dashboard: http://192.168.50.1:8080"
echo "  - API Firewall: http://192.168.50.1:5000"
echo ""
echo -e "${YELLOW}Para activar el modo router ahora, ejecuta:${NC}"
echo "  ${GREEN}sudo router-control start${NC}"
echo ""
echo -e "${BLUE}Documentación completa en: $CONFIG_DIR/README.md${NC}"
echo ""

# Crear README
cat > "$CONFIG_DIR/README.md" <<'README'
# Sistema Router/Firewall con Categorización Dinámica

## Descripción
Sistema que convierte tu Ubuntu en un router WiFi con firewall dinámico controlado por ML.

## Comandos Principales

### Activar modo router
```bash
sudo router-control start
```

### Desactivar modo router
```bash
sudo router-control stop
```

### Ver estado
```bash
sudo router-control status
```

## API del Firewall

### Actualizar categorías
```bash
curl -X POST http://192.168.50.1:5000/update_categories \
  -H "Content-Type: application/json" \
  -d '{
    "categories": {
      "malware": ["192.168.50.15", "192.168.50.23"],
      "suspicious": ["192.168.50.8"]
    }
  }'
```

### Añadir IPs a categoría
```bash
curl -X POST http://192.168.50.1:5000/add_to_category \
  -H "Content-Type: application/json" \
  -d '{
    "category": "malware",
    "ips": ["192.168.50.99"]
  }'
```

### Eliminar IPs de categoría
```bash
curl -X POST http://192.168.50.1:5000/remove_from_category \
  -H "Content-Type: application/json" \
  -d '{
    "category": "malware",
    "ips": ["192.168.50.99"]
  }'
```

### Ver categorías actuales
```bash
curl http://192.168.50.1:5000/get_categories
```

### Ver estadísticas
```bash
curl http://192.168.50.1:5000/stats
```

### Limpiar todas las categorías
```bash
curl -X POST http://192.168.50.1:5000/clear_all
```

## Integración con tu Modelo

Tu modelo debe:
1. Recibir tráfico (PCAP y flows) en los endpoints configurados
2. Analizar el tráfico
3. Enviar categorías al firewall

Ejemplo de envío desde tu modelo:
```python
import requests

# Categorizar IPs basándose en análisis
categories = {
    "malware": ["192.168.50.15"],
    "suspicious": ["192.168.50.8", "192.168.50.12"]
}

# Enviar al firewall
response = requests.post(
    'http://192.168.50.1:5000/update_categories',
    json={'categories': categories}
)
```

## Archivos y Logs

- Configuración: `/etc/router-system/`
- Logs: `/var/log/router-system.log`
- Logs individuales:
  - `/var/log/firewall_manager.log`
  - `/var/log/traffic_capture.log`
  - `/var/log/dashboard.log`

## Troubleshooting

### El AP no inicia
```bash
# Ver logs de hostapd
journalctl -u hostapd -n 50

# Verificar que el adaptador USB soporta modo AP
iw list | grep "Supported interface modes" -A 10
```

### Clientes no obtienen IP
```bash
# Ver logs de dnsmasq
journalctl -u dnsmasq -n 50
```

### Verificar reglas de firewall
```bash
# Ver reglas actuales
sudo iptables -L CATEGORY_FILTER -n -v

# Ver todas las reglas
sudo iptables -L -n -v
```

## Personalización

Editar `/etc/router-system/router-control.sh` para cambiar:
- Rango de IPs
- Canal WiFi
- Configuración de DHCP
README

chmod 644 "$CONFIG_DIR/README.md"

echo -e "${GREEN}✓ README creado en $CONFIG_DIR/README.md${NC}"
