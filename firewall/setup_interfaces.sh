#!/bin/bash
# ============================================
# Script de Configuración de Interfaces de Red
# Para el Sistema de Router/Firewall con ML
# ============================================

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funciones de utilidad
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Verificar privilegios de root
if [ "$EUID" -ne 0 ]; then 
    print_error "Este script requiere privilegios de root"
    echo "Por favor, ejecuta: sudo $0"
    exit 1
fi

echo "============================================"
echo "   Configuración de Interfaces de Red"
echo "============================================"
echo ""

# ============================================
# 1. DETECCIÓN AUTOMÁTICA DE INTERFACES
# ============================================

print_info "Detectando interfaces de red disponibles..."
echo ""

# Detectar interfaz con conexión a Internet
INTERNET_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$INTERNET_IFACE" ]; then
    print_error "No se pudo detectar la interfaz con acceso a Internet"
    print_info "Interfaces disponibles:"
    ip link show | grep -E "^[0-9]+" | awk '{print "  - " $2}' | sed 's/:$//'
    exit 1
fi
print_success "Interfaz con Internet detectada: $INTERNET_IFACE"

# Detectar adaptadores WiFi
print_info "Detectando adaptadores WiFi..."
WIFI_ADAPTERS=$(iw dev | grep Interface | awk '{print $2}')
WIFI_COUNT=$(echo "$WIFI_ADAPTERS" | wc -l)

if [ $WIFI_COUNT -eq 0 ]; then
    print_error "No se encontraron adaptadores WiFi"
    exit 1
fi

echo "Adaptadores WiFi encontrados:"
echo "$WIFI_ADAPTERS" | while read adapter; do
    ADAPTER_INFO=$(iw dev $adapter info 2>/dev/null)
    ADAPTER_TYPE=$(echo "$ADAPTER_INFO" | grep "type" | awk '{print $2}')
    echo "  - $adapter (Tipo: $ADAPTER_TYPE)"
done
echo ""

# Seleccionar el adaptador WiFi USB para AP
AP_IFACE=$(echo "$WIFI_ADAPTERS" | head -1)
print_success "Adaptador WiFi para AP seleccionado: $AP_IFACE"

echo ""
echo "============================================"
echo "   Resumen de Configuración"
echo "============================================"
echo -e "  ${BLUE}Interfaz Internet:${NC} $INTERNET_IFACE"
echo -e "  ${BLUE}Interfaz Access Point:${NC} $AP_IFACE"
echo ""

# ============================================
# 2. CREAR/ACTUALIZAR ARCHIVO .env
# ============================================

print_info "Configurando archivo .env..."

ENV_FILE="$(dirname "$0")/.env"
ENV_EXAMPLE="$(dirname "$0")/.env.example"

# Si no existe .env, crear desde .env.example
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        print_success "Archivo .env creado desde .env.example"
    else
        print_error "No se encontró .env.example"
        exit 1
    fi
fi

# Actualizar interfaces en .env
sed -i "s/^AP_IFACE=.*/AP_IFACE=$AP_IFACE/" "$ENV_FILE"
sed -i "s/^INTERNET_IFACE=.*/INTERNET_IFACE=$INTERNET_IFACE/" "$ENV_FILE"

print_success "Archivo .env actualizado con las interfaces correctas"

# ============================================
# 3. VERIFICAR Y DETENER SERVICIOS CONFLICTIVOS
# ============================================

print_info "Verificando servicios que podrían interferir..."

# NetworkManager podría interferir con hostapd
if systemctl is-active --quiet NetworkManager; then
    print_warning "NetworkManager está activo"
    print_info "Añadiendo $AP_IFACE a la lista de dispositivos no administrados"
    
    # Crear archivo de configuración para NetworkManager
    NM_CONF_DIR="/etc/NetworkManager/conf.d"
    NM_CONF_FILE="$NM_CONF_DIR/unmanaged-devices.conf"
    
    mkdir -p "$NM_CONF_DIR"
    
    if ! grep -q "$AP_IFACE" "$NM_CONF_FILE" 2>/dev/null; then
        cat >> "$NM_CONF_FILE" << EOF
[keyfile]
unmanaged-devices=interface-name:$AP_IFACE
EOF
        systemctl restart NetworkManager
        print_success "NetworkManager configurado para ignorar $AP_IFACE"
    else
        print_success "$AP_IFACE ya está configurado en NetworkManager"
    fi
fi

# Detener wpa_supplicant en la interfaz AP si está corriendo
if pgrep -f "wpa_supplicant.*$AP_IFACE" > /dev/null; then
    print_info "Deteniendo wpa_supplicant en $AP_IFACE..."
    pkill -f "wpa_supplicant.*$AP_IFACE"
    sleep 1
    print_success "wpa_supplicant detenido"
fi

# ============================================
# 4. CONFIGURAR INTERFAZ DE ACCESS POINT
# ============================================

print_info "Configurando interfaz de Access Point ($AP_IFACE)..."

# Bajar la interfaz
ip link set $AP_IFACE down 2>/dev/null

# Limpiar configuraciones previas
ip addr flush dev $AP_IFACE 2>/dev/null

# Configurar en modo managed (hostapd lo cambiará a AP después)
iw dev $AP_IFACE set type managed 2>/dev/null

# Subir la interfaz
ip link set $AP_IFACE up

# Asignar IP estática al AP
AP_GATEWAY="192.168.50.1"
ip addr add $AP_GATEWAY/24 dev $AP_IFACE 2>/dev/null

print_success "Interfaz $AP_IFACE configurada con IP $AP_GATEWAY"

# ============================================
# 5. HABILITAR IP FORWARDING
# ============================================

print_info "Habilitando IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1

# Hacer permanente
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

print_success "IP forwarding habilitado"

# ============================================
# 6. CONFIGURAR NAT/MASQUERADING
# ============================================

print_info "Configurando NAT (iptables)..."

# Limpiar reglas existentes para NAT
iptables -t nat -F POSTROUTING 2>/dev/null

# Configurar NAT/Masquerading
iptables -t nat -A POSTROUTING -o $INTERNET_IFACE -j MASQUERADE

# Configurar forwarding entre interfaces
iptables -A FORWARD -i $AP_IFACE -o $INTERNET_IFACE -j ACCEPT
iptables -A FORWARD -i $INTERNET_IFACE -o $AP_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

print_success "NAT configurado correctamente"

# ============================================
# 7. VERIFICAR CONECTIVIDAD
# ============================================

echo ""
echo "============================================"
echo "   Verificación de Configuración"
echo "============================================"

# Verificar interfaz de Internet
INTERNET_IP=$(ip addr show $INTERNET_IFACE | grep "inet " | awk '{print $2}' | cut -d/ -f1)
if [ -n "$INTERNET_IP" ]; then
    print_success "Interfaz Internet ($INTERNET_IFACE): $INTERNET_IP"
else
    print_warning "Interfaz Internet ($INTERNET_IFACE): Sin IP asignada"
fi

# Verificar interfaz AP
AP_IP=$(ip addr show $AP_IFACE | grep "inet " | awk '{print $2}' | cut -d/ -f1)
if [ -n "$AP_IP" ]; then
    print_success "Interfaz AP ($AP_IFACE): $AP_IP"
else
    print_warning "Interfaz AP ($AP_IFACE): Sin IP asignada"
fi

# Verificar IP forwarding
IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$IP_FORWARD" = "1" ]; then
    print_success "IP Forwarding: Habilitado"
else
    print_warning "IP Forwarding: Deshabilitado"
fi

# Verificar reglas NAT
NAT_RULES=$(iptables -t nat -L POSTROUTING -n | grep -c MASQUERADE)
if [ "$NAT_RULES" -gt 0 ]; then
    print_success "Reglas NAT: Configuradas ($NAT_RULES reglas)"
else
    print_warning "Reglas NAT: No configuradas"
fi

# Verificar conectividad a Internet
print_info "Verificando conectividad a Internet..."
if ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1; then
    print_success "Conectividad a Internet: OK"
else
    print_warning "Conectividad a Internet: No disponible"
fi

# ============================================
# 8. RESUMEN Y SIGUIENTES PASOS
# ============================================

echo ""
echo "============================================"
echo "   Configuración Completada"
echo "============================================"
echo ""
echo "Las interfaces están configuradas correctamente:"
echo ""
echo "  1. Interfaz con Internet: $INTERNET_IFACE"
echo "  2. Interfaz Access Point: $AP_IFACE (IP: $AP_GATEWAY)"
echo "  3. IP Forwarding: Habilitado"
echo "  4. NAT: Configurado"
echo ""
echo "Archivo .env actualizado en:"
echo "  $ENV_FILE"
echo ""
echo "============================================"
echo "   Siguientes Pasos"
echo "============================================"
echo ""
echo "Para iniciar el sistema completo, ejecuta:"
echo ""
echo "  ${GREEN}sudo ./init_all.sh${NC}"
echo ""
echo "O para uso diario:"
echo ""
echo "  ${GREEN}sudo ./quick_start.sh${NC}"
echo ""
echo "Para el dashboard web, visita:"
echo ""
echo "  ${BLUE}http://localhost:8081${NC}"
echo ""
