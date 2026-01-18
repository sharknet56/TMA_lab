# 🛡️ Sistema Router/Firewall con ML - Versión Final

Sistema completo de router WiFi con firewall dinámico controlado por Machine Learning para detección y bloqueo automático de amenazas de red.

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso Rápido](#-uso-rápido)
- [Interfaces Web](#-interfaces-web)
- [API del Firewall](#-api-del-firewall)
- [Gestión de Categorías](#-gestión-de-categorías)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Características

### Router WiFi
- ✅ Punto de acceso WiFi configurable (WPA2)
- ✅ Servidor DHCP automático
- ✅ NAT/Routing hacia internet
- ✅ Sin pérdida de conexión en la máquina host

### Firewall Dinámico
- ✅ Bloqueo por categorías (malware, phishing, etc.)
- ✅ Actualización en tiempo real vía API REST
- ✅ Control granular por IP
- ✅ Activar/Desactivar categorías sin perder IPs
- ✅ Soporte CORS para interfaces web

### Captura de Tráfico
- ✅ Captura de paquetes en formato PCAP
- ✅ Análisis de flows de red
- ✅ Envío automático al modelo ML

### Dashboard Web
- ✅ Monitorización en tiempo real
- ✅ Visualización de clientes conectados (IP + MAC)
- ✅ Control de categorías (activar/desactivar)
- ✅ Estadísticas del sistema

### Modelo ML Simulado
- ✅ Interfaz web para bloqueo manual de IPs
- ✅ Visualización de últimos 20 flows
- ✅ Gestión de categorías
- ✅ Actualización automática del firewall

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                    DISPOSITIVOS CLIENTES                     │
│              (Móviles, Tablets, Laptops, IoT)                │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              PUNTO DE ACCESO WiFi (wlxc83a35b5a9f5)         │
│                    192.168.50.1/24                           │
│                SSID: RouterFirewall                          │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    TRAFFIC CAPTURE                           │
│              Captura paquetes y flows                        │
│            Envía cada 30s PCAP y 10s flows                   │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   MODELO ML (localhost:8000)                 │
│              - Analiza tráfico (simulado)                    │
│              - Interfaz web de control                       │
│              - Visualización de flows                        │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              FIREWALL MANAGER (192.168.50.1:5000)            │
│              - API REST con CORS                             │
│              - Gestión de categorías                         │
│              - Aplicación de reglas iptables                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     IPTABLES CHAINS                          │
│              CATEGORY_FILTER → DROP bloqueadas               │
│              FORWARD → ACCEPT permitidas                     │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                NAT → INTERNET (wlp2s0)                       │
│              Mantiene conectividad del host                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│            DASHBOARD (192.168.50.1:8081)                     │
│           - Monitorización en tiempo real                    │
│           - Control de categorías                            │
│           - Clientes conectados (IP + MAC)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Requisitos

### Hardware
- **2 interfaces WiFi:**
  - `wlp2s0`: Conexión a internet (integrada)
  - `wlxc83a35b5a9f5`: USB WiFi con soporte modo AP

### Software
```bash
# Paquetes del sistema
sudo apt-get install -y \
  hostapd \
  dnsmasq \
  iptables \
  iproute2 \
  net-tools \
  wireless-tools \
  python3 \
  python3-pip \
  python3-flask \
  python3-flask-cors \
  python3-scapy \
  python3-requests \
  python3-psutil

# Verificar que el adaptador USB soporta modo AP
iw list | grep -A 10 "Supported interface modes"
# Debe aparecer "AP" en la lista
```

---

## 🚀 Instalación

### 1. Clonar o descargar el proyecto

```bash
cd ~/Documentos/UPC/TMA/project
```

### 2. Configurar permisos

```bash
cd router-system
chmod +x router-control.sh install.sh
```

### 3. Instalar (opcional - solo primera vez)

```bash
sudo ./install.sh
```

El script de instalación:
- Copia archivos a `/etc/router-system/`
- Configura hostapd y dnsmasq
- Crea archivos de configuración

**Nota:** Ya está todo configurado, puedes saltar este paso.

---

## 🎮 Uso Rápido

### Iniciar Todo el Sistema

#### 1. Iniciar el Modelo ML Simulado

```bash
cd ~/Documentos/UPC/TMA/project/simulated-model
python3 model_server.py &
```

**Salida esperada:**
```
=== Modelo ML Simulado Iniciado ===
Interfaz web disponible en: http://localhost:8000
API escuchando en: http://0.0.0.0:8000
Esperando tráfico del router...
```

#### 2. Iniciar el Router/Firewall

```bash
cd ~/Documentos/UPC/TMA/project/router-system
sudo ./router-control.sh start
```

**Salida esperada:**
```
=== INICIANDO MODO ROUTER ===
✓ Configurando interfaz AP (192.168.50.1)
✓ Iniciando punto de acceso WiFi
  SSID: RouterFirewall
  Password: tma12345
✓ Iniciando servidor DHCP
✓ Configurando NAT y routing
✓ Iniciando firewall manager (puerto 5000)
✓ Iniciando captura de tráfico
✓ Iniciando dashboard web (puerto 8081)

=== MODO ROUTER ACTIVO ===

Conecta tus dispositivos a:
  Red WiFi: RouterFirewall
  Contraseña: tma12345

Accede al dashboard en:
  http://192.168.50.1:8081
```

### Verificar que Todo Funciona

```bash
# Ver estado
sudo ./router-control.sh status

# Verificar procesos
ps aux | grep -E "firewall_manager|traffic_capture|dashboard|model_server" | grep -v grep

# Probar APIs
curl http://localhost:8000/health
curl http://192.168.50.1:5000/stats
curl http://192.168.50.1:8081/api/status
```

### Detener Todo el Sistema

```bash
# Detener router/firewall
cd ~/Documentos/UPC/TMA/project/router-system
sudo ./router-control.sh stop

# Detener modelo simulado
pkill -f "python3 model_server.py"
```

---

## 🌐 Interfaces Web

### 1. Panel de Control del Modelo ML
**URL:** `http://localhost:8000`

**Funcionalidades:**
- ➕ **Bloquear IPs manualmente**: Añade IPs a categorías específicas
- 📋 **Ver categorías**: Todas las IPs bloqueadas por categoría
- 🗑️ **Eliminar IPs**: Quita IPs de las categorías
- 🔄 **Ver flows**: Últimos 20 flows capturados en tiempo real
- 🔥 **Acciones rápidas**: Enviar actualizaciones al firewall
- 📊 **Estadísticas**: PCAPs recibidos, flows procesados

**Ejemplo de uso:**
1. Abre `http://localhost:8000` en tu navegador
2. En "Bloquear IP manualmente":
   - IP: `192.168.50.39`
   - Categoría: `malware` (o crea una nueva)
3. Click en "Bloquear IP"
4. La IP se bloquea inmediatamente en el firewall

### 2. Dashboard del Router
**URL:** `http://192.168.50.1:8081`

**Muestra:**
- 📊 **Estadísticas del Sistema**: CPU, Memoria, Uptime
- 🌐 **Red**: Clientes conectados, IP del router, interfaz AP
- 🔥 **Firewall**: IPs bloqueadas, categorías activas
- 🚫 **Categorías de Bloqueo**:
  - Ver todas las categorías e IPs
  - Botón "Desactivar/Activar" por categoría
  - Botón "Limpiar" para eliminar todas las IPs
- 👥 **Clientes Conectados**: IP, MAC, señal WiFi
- 📈 **Tráfico**: Bytes enviados/recibidos, paquetes

**Gestión de categorías desde el dashboard:**
- **Desactivar categoría**: Las IPs se mantienen pero no se bloquean
- **Activar categoría**: Vuelve a aplicar las reglas de bloqueo
- **Limpiar categoría**: Elimina todas las IPs de esa categoría

---

## 🔌 API del Firewall

Base URL: `http://192.168.50.1:5000`

### Endpoints Principales

#### GET /get_categories
Obtiene todas las categorías y sus IPs

```bash
curl http://192.168.50.1:5000/get_categories
```

**Respuesta:**
```json
{
  "categories": {
    "malware": ["192.168.50.15", "192.168.50.23"],
    "phishing": ["192.168.50.8"]
  },
  "active_categories": ["malware", "phishing"],
  "stats": {
    "total_updates": 42,
    "total_blocked_ips": 3,
    "last_update": "2026-01-13T18:20:15.123456"
  }
}
```

#### POST /update_categories
Actualiza categorías completas (reemplaza)

```bash
curl -X POST http://192.168.50.1:5000/update_categories \
  -H "Content-Type: application/json" \
  -d '{
    "categories": {
      "malware": ["192.168.50.10", "192.168.50.11"],
      "ddos": ["192.168.50.99"]
    }
  }'
```

#### POST /add_to_category
Añade IPs a una categoría existente

```bash
curl -X POST http://192.168.50.1:5000/add_to_category \
  -H "Content-Type: application/json" \
  -d '{
    "category": "malware",
    "ips": ["192.168.50.50"]
  }'
```

#### POST /remove_from_category
Elimina IPs de una categoría

```bash
curl -X POST http://192.168.50.1:5000/remove_from_category \
  -H "Content-Type: application/json" \
  -d '{
    "category": "malware",
    "ips": ["192.168.50.50"]
  }'
```

#### POST /toggle_category
Activa o desactiva una categoría (mantiene las IPs)

```bash
# Desactivar categoría
curl -X POST http://192.168.50.1:5000/toggle_category \
  -H "Content-Type: application/json" \
  -d '{
    "category": "malware",
    "enabled": false
  }'

# Activar categoría
curl -X POST http://192.168.50.1:5000/toggle_category \
  -H "Content-Type: application/json" \
  -d '{
    "category": "malware",
    "enabled": true
  }'
```

#### POST /clear_category
Elimina todas las IPs de una categoría

```bash
curl -X POST http://192.168.50.1:5000/clear_category \
  -H "Content-Type: application/json" \
  -d '{"category": "malware"}'
```

#### POST /clear_all
Elimina todas las categorías

```bash
curl -X POST http://192.168.50.1:5000/clear_all
```

#### GET /stats
Obtiene estadísticas del firewall

```bash
curl http://192.168.50.1:5000/stats
```

---

## 🎯 Gestión de Categorías

### Flujo de Trabajo Típico

#### 1. Bloquear un Dispositivo Problemático

**Opción A: Desde el Panel ML (localhost:8000)**
1. Identifica la IP del cliente en el dashboard
2. Abre `http://localhost:8000`
3. Ingresa la IP y selecciona categoría
4. Click "Bloquear IP"

**Opción B: Desde la API**
```bash
curl -X POST http://192.168.50.1:5000/update_categories \
  -H "Content-Type: application/json" \
  -d '{
    "categories": {
      "blocked": ["192.168.50.39"]
    }
  }'
```

#### 2. Desactivar Temporalmente una Categoría

**Desde el Dashboard (192.168.50.1:8081):**
- Encuentra la categoría en la sección "Categorías de Bloqueo"
- Click en el botón "🔴 Desactivar"
- Las IPs se mantienen pero dejan de bloquearse

**Desde la API:**
```bash
curl -X POST http://192.168.50.1:5000/toggle_category \
  -H "Content-Type: application/json" \
  -d '{"category": "malware", "enabled": false}'
```

#### 3. Reactivar una Categoría

**Desde el Dashboard:**
- Click en el botón "🟢 Activar"

**Desde la API:**
```bash
curl -X POST http://192.168.50.1:5000/toggle_category \
  -H "Content-Type: application/json" \
  -d '{"category": "malware", "enabled": true}'
```

#### 4. Limpiar una Categoría Completa

**Desde el Dashboard:**
- Click en el botón "🗑️ Limpiar"

**Desde la API:**
```bash
curl -X POST http://192.168.50.1:5000/clear_category \
  -H "Content-Type: application/json" \
  -d '{"category": "malware"}'
```

---

## 🧪 Casos de Uso y Ejemplos

### Caso 1: Bloquear un Cliente Específico

```bash
# 1. Ver clientes conectados
curl http://192.168.50.1:8081/api/status | python3 -c "import json,sys; [print(f\"{c['ip']} - {c['mac']}\") for c in json.load(sys.stdin)['network']['client_details']]"

# 2. Bloquear cliente
curl -X POST http://192.168.50.1:5000/update_categories \
  -H "Content-Type: application/json" \
  -d '{"categories": {"blocked": ["192.168.50.39"]}}'

# 3. Verificar bloqueo
curl http://192.168.50.1:5000/get_categories
```

### Caso 2: Simular Detección de Malware

```bash
# 1. Configurar IPs sospechosas en el modelo
curl -X POST http://localhost:8000/configure \
  -H "Content-Type: application/json" \
  -d '{
    "categories": {
      "malware": ["192.168.50.10", "192.168.50.11"],
      "phishing": ["192.168.50.20"]
    }
  }'

# 2. Disparar actualización del firewall
curl -X POST http://localhost:8000/trigger

# 3. Ver en el dashboard (192.168.50.1:8081)
```

### Caso 3: Control Parental Temporal

```bash
# Bloquear dispositivo de niño
curl -X POST http://192.168.50.1:5000/update_categories \
  -H "Content-Type: application/json" \
  -d '{"categories": {"parental": ["192.168.50.45"]}}'

# Más tarde, desbloquear temporalmente (mantener la IP)
curl -X POST http://192.168.50.1:5000/toggle_category \
  -H "Content-Type: application/json" \
  -d '{"category": "parental", "enabled": false}'

# Volver a bloquear
curl -X POST http://192.168.50.1:5000/toggle_category \
  -H "Content-Type: application/json" \
  -d '{"category": "parental", "enabled": true}'
```

---

## 🔍 Monitorización y Logs

### Ver Logs en Tiempo Real

```bash
# Firewall Manager
tail -f /tmp/firewall.log

# Dashboard
tail -f /tmp/dashboard.log

# Traffic Capture
tail -f /var/log/router-system.log

# Modelo ML (si lo iniciaste en background)
tail -f nohup.out
```

### Ver Reglas de iptables

```bash
# Ver chain de categorías
sudo iptables -L CATEGORY_FILTER -n -v

# Ver NAT
sudo iptables -t nat -L -n -v

# Ver FORWARD chain completo
sudo iptables -L FORWARD -n -v
```

### Ver Clientes Conectados

```bash
# Desde iw
sudo iw dev wlxc83a35b5a9f5 station dump

# Desde leases DHCP
sudo cat /var/lib/misc/dnsmasq.leases

# Desde la API
curl -s http://192.168.50.1:8081/api/status | python3 -m json.tool
```

---

## 🛠️ Troubleshooting

### Problema: Dashboard muestra "Error al cambiar estado de categoría"

**Causa:** Problemas CORS entre puertos 8081 (dashboard) y 5000 (firewall)

**Solución:**
```bash
# Verificar que flask-cors está instalado
sudo apt-get install python3-flask-cors

# Reiniciar firewall manager
sudo pkill -f firewall_manager
cd ~/Documentos/UPC/TMA/project/router-system
sudo python3 firewall_manager.py &
```

### Problema: No se detectan clientes conectados

**Solución:**
```bash
# Verificar interfaz correcta en dashboard
grep "ap_interface" router-system/dashboard.py
# Debe ser: 'ap_interface': 'wlxc83a35b5a9f5'

# Verificar que hay clientes
sudo iw dev wlxc83a35b5a9f5 station dump

# Reiniciar dashboard
sudo pkill -f dashboard.py
cd ~/Documentos/UPC/TMA/project/router-system
sudo python3 dashboard.py &
```

### Problema: Modelo no actualiza el firewall

**Solución:**
```bash
# Verificar que el firewall está corriendo
curl http://192.168.50.1:5000/stats

# Verificar conectividad desde el modelo
curl -X POST http://192.168.50.1:5000/update_categories \
  -H "Content-Type: application/json" \
  -d '{"categories": {"test": ["192.168.50.99"]}}'

# Si falla, asegurarse de estar en modo router
sudo ./router-control.sh status
```

### Problema: Se pierde internet al activar el router

**Solución:**
```bash
# Verificar que wlp2s0 sigue conectado
nmcli device status

# Verificar NAT
sudo iptables -t nat -L -n -v | grep MASQUERADE

# Verificar IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Debe ser 1
```

### Problema: No se pueden conectar clientes al WiFi

**Solución:**
```bash
# Ver estado de hostapd
sudo systemctl status hostapd
sudo journalctl -u hostapd -n 50

# Verificar configuración
sudo cat /etc/hostapd/hostapd.conf

# Probar hostapd en modo debug
sudo hostapd -dd /etc/hostapd/hostapd.conf
```

### Resetear Todo

```bash
# 1. Detener router
sudo ./router-control.sh stop

# 2. Limpiar iptables
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X

# 3. Reiniciar NetworkManager
sudo systemctl restart NetworkManager

# 4. Volver a empezar
sudo ./router-control.sh start
```

---

## 📊 Configuración

### Cambiar SSID y Contraseña

```bash
sudo nano /etc/hostapd/hostapd.conf
```

Editar:
```
ssid=TuNombreDeRed
wpa_passphrase=TuNuevaPassword
```

Reiniciar:
```bash
sudo ./router-control.sh restart
```

### Cambiar Rango de IPs

```bash
sudo nano /etc/dnsmasq.conf
```

Editar:
```
dhcp-range=192.168.50.10,192.168.50.100,24h
```

### Cambiar Puerto del Dashboard

Editar `router-system/dashboard.py`:
```python
app.run(host='0.0.0.0', port=8081, debug=False)  # Cambiar 8081
```

---

## 📁 Estructura del Proyecto

```
project/
├── README.md                    # Este archivo
├── router-system/
│   ├── router-control.sh        # Script principal de control
│   ├── firewall_manager.py      # Gestión del firewall (API)
│   ├── traffic_capture.py       # Captura de tráfico
│   ├── dashboard.py             # Dashboard web
│   └── install.sh               # Script de instalación
├── simulated-model/
│   ├── model_server.py          # Modelo ML simulado
│   ├── test_client.py           # Cliente de pruebas
│   └── README.md                # Documentación del modelo
└── usage_guide.md               # Guía detallada (legacy)
```

---

## 🔐 Seguridad

### Mejores Prácticas

1. **Cambiar la contraseña WiFi por defecto**
2. **Usar WPA3 si tu hardware lo soporta**
3. **Limitar el rango DHCP** al número de dispositivos necesarios
4. **Monitorizar los logs** regularmente
5. **Actualizar las categorías** de bloqueo frecuentemente

### Añadir Autenticación a la API

Editar `firewall_manager.py`:

```python
from functools import wraps

API_KEY = "tu-clave-secreta-aqui"

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if key != API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/update_categories', methods=['POST'])
@require_api_key
def update_categories():
    # ...
```

---

## 🎓 Información del Proyecto

**Asignatura:** TMA - Técnicas de Machine Learning Avanzadas  
**Universidad:** UPC (Universitat Politècnica de Catalunya)  
**Año:** 2026

### Componentes Principales

1. **Router/Firewall**: Sistema base de routing y NAT
2. **Firewall Dinámico**: Bloqueo por categorías con API REST
3. **Traffic Capture**: Captura y análisis de tráfico de red
4. **Dashboard**: Interfaz web de monitorización
5. **Modelo ML**: Detección simulada de amenazas

### Características Técnicas

- **Lenguaje:** Python 3.12
- **Framework Web:** Flask + Flask-CORS
- **Captura de Red:** Scapy
- **Firewall:** iptables
- **WiFi AP:** hostapd
- **DHCP:** dnsmasq

---

## 📞 Soporte

### URLs Útiles

| Servicio | URL | Descripción |
|----------|-----|-------------|
| Dashboard Router | http://192.168.50.1:8081 | Monitorización y control |
| API Firewall | http://192.168.50.1:5000 | REST API del firewall |
| Panel ML | http://localhost:8000 | Control del modelo ML |
| Stats Firewall | http://192.168.50.1:5000/stats | Estadísticas JSON |

### Comandos Rápidos

```bash
# Iniciar todo
cd simulated-model && python3 model_server.py &
cd ../router-system && sudo ./router-control.sh start

# Estado
sudo ./router-control.sh status

# Detener todo
sudo ./router-control.sh stop
pkill -f model_server.py

# Ver logs
tail -f /tmp/firewall.log
tail -f /tmp/dashboard.log

# Ver clientes
curl -s http://192.168.50.1:8081/api/status | python3 -m json.tool

# Ver categorías
curl -s http://192.168.50.1:5000/get_categories | python3 -m json.tool
```

---

## ✅ Checklist de Verificación

Después de iniciar el sistema, verifica:

- [ ] El modelo ML responde: `curl http://localhost:8000/health`
- [ ] El router está activo: `sudo ./router-control.sh status`
- [ ] El firewall responde: `curl http://192.168.50.1:5000/stats`
- [ ] El dashboard carga: Abre `http://192.168.50.1:8081`
- [ ] Puedes conectarte al WiFi: SSID "RouterFirewall"
- [ ] Los clientes obtienen IP: Verifica en el dashboard
- [ ] El tráfico se captura: Ver logs del traffic_capture
- [ ] El modelo recibe flows: `curl http://localhost:8000/stats`

---

## 🎉 ¡Sistema Listo!

El sistema está completamente funcional y probado. Todos los componentes están integrados y comunicándose correctamente.

**¡Disfruta tu router/firewall con ML!** 🚀
