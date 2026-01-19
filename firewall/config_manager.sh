#!/bin/bash
# Script para actualizar variables en el archivo .env

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ENV_FILE="$SCRIPT_DIR/.env"

# Verificar que existe el archivo .env
if [ ! -f "$ENV_FILE" ]; then
    echo " Archivo .env no encontrado"
    echo "   Copiando desde .env.example..."
    echo ""
    if [ -f "$SCRIPT_DIR/.env.example" ]; then
        cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
        echo "✓ Archivo .env creado"
        echo ""
    else
        echo " No se encontró .env.example"
        echo ""
        exit 1
    fi
fi

# Función para actualizar una variable
update_env_var() {
    local key="$1"
    local value="$2"
    
    if grep -q "^${key}=" "$ENV_FILE"; then
        # La variable existe, actualizarla
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
        echo "✓ ${key} actualizado a: ${value}"
    else
        # La variable no existe, agregarla
        echo "${key}=${value}" >> "$ENV_FILE"
        echo "✓ ${key} agregado con valor: ${value}"
    fi
}

# Si se proporcionan argumentos, actualizar directamente
if [ $# -eq 2 ]; then
    update_env_var "$1" "$2"
    exit 0
fi

# Modo interactivo
echo "╔════════════════════════════════════════════╗"
echo "║    Configuración del Sistema Router        ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Mostrar configuración actual
echo " Configuración actual:"
echo ""
cat "$ENV_FILE" | grep -v "^#" | grep -v "^$" | while read line; do
    echo "  $line"
done
echo ""

# Menú de opciones
echo "¿Qué deseas configurar?"
echo ""
echo "1) Modo de captura de tráfico (flows/packets)"
echo "2) Interfaces de red"
echo "3) Configuración WiFi"
echo "4) Configuración de red AP"
echo "5) Tamaños de buffer y tiempos"
echo "6) Ver configuración completa"
echo "0) Salir"
echo ""

read -p "Selecciona una opción [0-6]: " option

case $option in
    1)
        echo ""
        echo "Modo de captura actual: $(grep "^TRAFFIC_CAPTURE_MODE=" "$ENV_FILE" | cut -d'=' -f2)"
        echo ""
        echo "Modos disponibles:"
        echo "  - flows: Captura estadísticas agregadas de flujos de red (más eficiente)"
        echo "  - packets: Captura paquetes completos en formato PCAP (más detalle)"
        echo ""
        read -p "Nuevo modo [flows/packets]: " mode
        if [ "$mode" = "flows" ] || [ "$mode" = "packets" ]; then
            update_env_var "TRAFFIC_CAPTURE_MODE" "$mode"
        else
            echo " Modo inválido"
        fi
        ;;
    
    2)
        echo ""
        echo "Interfaces actuales:"
        echo "  AP: $(grep "^AP_IFACE=" "$ENV_FILE" | cut -d'=' -f2)"
        echo "  Internet: $(grep "^INTERNET_IFACE=" "$ENV_FILE" | cut -d'=' -f2)"
        echo ""
        echo "Interfaces disponibles:"
        ip link show | grep -E '^[0-9]+:.*wl' | cut -d: -f2 | sed 's/^ /  - /'
        echo ""
        read -p "Interfaz AP (USB WiFi) [actual: $(grep "^AP_IFACE=" "$ENV_FILE" | cut -d'=' -f2)]: " ap_iface
        read -p "Interfaz Internet [actual: $(grep "^INTERNET_IFACE=" "$ENV_FILE" | cut -d'=' -f2)]: " internet_iface
        
        [ -n "$ap_iface" ] && update_env_var "AP_IFACE" "$ap_iface"
        [ -n "$internet_iface" ] && update_env_var "INTERNET_IFACE" "$internet_iface"
        ;;
    
    3)
        echo ""
        echo "WiFi actual:"
        echo "  SSID: $(grep "^WIFI_SSID=" "$ENV_FILE" | cut -d'=' -f2)"
        echo "  Canal: $(grep "^WIFI_CHANNEL=" "$ENV_FILE" | cut -d'=' -f2)"
        echo ""
        read -p "SSID [actual: $(grep "^WIFI_SSID=" "$ENV_FILE" | cut -d'=' -f2)]: " ssid
        read -p "Contraseña [dejar en blanco para no cambiar]: " password
        read -p "Canal [actual: $(grep "^WIFI_CHANNEL=" "$ENV_FILE" | cut -d'=' -f2)]: " channel
        
        [ -n "$ssid" ] && update_env_var "WIFI_SSID" "$ssid"
        [ -n "$password" ] && update_env_var "WIFI_PASSWORD" "$password"
        [ -n "$channel" ] && update_env_var "WIFI_CHANNEL" "$channel"
        ;;
    
    4)
        echo ""
        echo "Red AP actual:"
        echo "  Red: $(grep "^AP_NETWORK=" "$ENV_FILE" | cut -d'=' -f2)"
        echo "  Gateway: $(grep "^AP_GATEWAY=" "$ENV_FILE" | cut -d'=' -f2)"
        echo "  DHCP: $(grep "^AP_DHCP_START=" "$ENV_FILE" | cut -d'=' -f2) - $(grep "^AP_DHCP_END=" "$ENV_FILE" | cut -d'=' -f2)"
        echo ""
        read -p "Red (ej: 192.168.50.0/24) [actual: $(grep "^AP_NETWORK=" "$ENV_FILE" | cut -d'=' -f2)]: " network
        read -p "Gateway (ej: 192.168.50.1) [actual: $(grep "^AP_GATEWAY=" "$ENV_FILE" | cut -d'=' -f2)]: " gateway
        read -p "DHCP inicio [actual: $(grep "^AP_DHCP_START=" "$ENV_FILE" | cut -d'=' -f2)]: " dhcp_start
        read -p "DHCP fin [actual: $(grep "^AP_DHCP_END=" "$ENV_FILE" | cut -d'=' -f2)]: " dhcp_end
        
        [ -n "$network" ] && update_env_var "AP_NETWORK" "$network"
        [ -n "$gateway" ] && update_env_var "AP_GATEWAY" "$gateway"
        [ -n "$dhcp_start" ] && update_env_var "AP_DHCP_START" "$dhcp_start"
        [ -n "$dhcp_end" ] && update_env_var "AP_DHCP_END" "$dhcp_end"
        ;;
    
    5)
        echo ""
        echo "Configuración de buffers:"
        echo "  Flow buffer: $(grep "^FLOW_BUFFER_SIZE=" "$ENV_FILE" | cut -d'=' -f2)"
        echo "  Flow interval: $(grep "^FLOW_SEND_INTERVAL=" "$ENV_FILE" | cut -d'=' -f2)s"
        echo "  PCAP buffer: $(grep "^PCAP_BUFFER_SIZE=" "$ENV_FILE" | cut -d'=' -f2)"
        echo "  PCAP interval: $(grep "^PCAP_SEND_INTERVAL=" "$ENV_FILE" | cut -d'=' -f2)s"
        echo ""
        read -p "Flow buffer size [actual: $(grep "^FLOW_BUFFER_SIZE=" "$ENV_FILE" | cut -d'=' -f2)]: " flow_buffer
        read -p "Flow send interval (seg) [actual: $(grep "^FLOW_SEND_INTERVAL=" "$ENV_FILE" | cut -d'=' -f2)]: " flow_interval
        read -p "PCAP buffer size [actual: $(grep "^PCAP_BUFFER_SIZE=" "$ENV_FILE" | cut -d'=' -f2)]: " pcap_buffer
        read -p "PCAP send interval (seg) [actual: $(grep "^PCAP_SEND_INTERVAL=" "$ENV_FILE" | cut -d'=' -f2)]: " pcap_interval
        
        [ -n "$flow_buffer" ] && update_env_var "FLOW_BUFFER_SIZE" "$flow_buffer"
        [ -n "$flow_interval" ] && update_env_var "FLOW_SEND_INTERVAL" "$flow_interval"
        [ -n "$pcap_buffer" ] && update_env_var "PCAP_BUFFER_SIZE" "$pcap_buffer"
        [ -n "$pcap_interval" ] && update_env_var "PCAP_SEND_INTERVAL" "$pcap_interval"
        ;;
    
    6)
        echo ""
        echo "════════════════════════════════════════════"
        cat "$ENV_FILE"
        echo "════════════════════════════════════════════"
        ;;
    
    0)
        echo " Saliendo..."
        exit 0
        ;;
    
    *)
        echo " Opción inválida"
        ;;
esac

echo ""
echo "✓ Configuración actualizada"
echo ""
echo " Reinicia los servicios para aplicar los cambios:"
echo "   sudo ./restart_all.sh"
