# 🛡️ Sistema Router/Firewall con ML

Sistema completo de router WiFi con firewall dinámico controlado por Machine Learning para detección y clasificación de dispositivos IoT.

## 📋 Características

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

### Captura de Tráfico
- ✅ Captura de paquetes (PCAP) o flows (CICFlowMeter)
- ✅ Envío automático al modelo ML
- ✅ Modo configurable desde dashboard o .env

### Modelos ML
- ✅ **ml_flows**: Random Forest con flows (puerto 5001)
- ✅ **simulated_flows**: Modelo simulado con flows (puerto 8000)
- ✅ **dl_packets**: Deep Learning con packets (puerto 5002)

### Dashboard Web
- ✅ Monitorización en tiempo real
- ✅ Visualización de clientes conectados
- ✅ Control de categorías y configuración
- ✅ Estadísticas del sistema

---

## 🚀 Inicio Rápido

### Instalación Completa (primera vez)
```bash
# 1. Copiar configuración de ejemplo
cp .env.example .env

# 2. Editar configuración (opcional)
nano .env

# 3. Inicializar sistema
sudo ./init_all.sh
```

### Uso Diario
```bash
# Iniciar sistema
sudo ./quick_start.sh

# Detener sistema
./stop_all.sh

# Reiniciar sistema
./restart_all.sh
```

---

## ⚙️ Configuración

### Archivo .env

Todas las variables del sistema están centralizadas en `.env`:

```bash
# Interfaces
AP_IFACE=wlxc83a35b5a9f5          # WiFi USB para AP
INTERNET_IFACE=wlp2s0              # Conexión a internet

# WiFi
WIFI_SSID=RouterFirewall           # Nombre de la red
WIFI_PASSWORD=SecurePass123        # Contraseña (mín 8 caracteres)
WIFI_CHANNEL=6                     # Canal WiFi (1-11)

# Red
AP_NETWORK=192.168.50.0/24
AP_GATEWAY=192.168.50.1
AP_DHCP_START=192.168.50.20
AP_DHCP_END=192.168.50.100

# Modelo
MODEL_TYPE=ml_flows                # ml_flows | simulated_flows | dl_packets

# Captura de tráfico (automático según MODEL_TYPE)
FLOW_BUFFER_SIZE=100
FLOW_SEND_INTERVAL=10
PCAP_BUFFER_SIZE=1000
PCAP_SEND_INTERVAL=30
```

### Tipos de Modelos

#### 1. ml_flows (Random Forest + Flows)
```bash
MODEL_TYPE=ml_flows
```
- Puerto: 5001
- Script: `traffic_capture.py`
- Datos: 79 features CICFlowMeter
- Directorio: `model_ml/`

#### 2. simulated_flows (Testing + Flows)
```bash
MODEL_TYPE=simulated_flows
```
- Puerto: 8000
- Script: `traffic_capture.py`
- Datos: 79 features CICFlowMeter
- Directorio: `simulated-model/`

#### 3. dl_packets (Deep Learning + Packets)
```bash
MODEL_TYPE=dl_packets
```
- Puerto: 5002
- Script: `traffic_capture_packets.py`
- Datos: Archivos PCAP completos
- Directorio: `model_dl/`

### Cambiar Configuración

#### Método 1: Editor de texto
```bash
nano .env
# Modificar variables
sudo ./restart_all.sh
```

#### Método 2: Dashboard Web
1. Abrir `http://192.168.50.1:8081`
2. Sección "⚙️ Configuración"
3. Cambiar modo de captura
4. Clic en "Aplicar Cambio"

#### Método 3: Script interactivo
```bash
./config_manager.sh
```

---

## 📜 Scripts Disponibles

### `init_all.sh` - Instalación completa
Instala y configura todo el sistema desde cero.

```bash
sudo ./init_all.sh              # Usar model_ml
sudo ./init_all.sh simulated    # Usar simulated-model
sudo ./init_all.sh --reinstall  # Forzar reinstalación del router
```

**Incluye:**
- Limpieza de instalaciones previas
- Instalación de dependencias
- Configuración del router
- Copia de `.env.example` a `.env`
- Inicio de todos los servicios

### `quick_start.sh` - Inicio rápido
Inicia el sistema sin reinstalar (más rápido).

```bash
sudo ./quick_start.sh           # Usar configuración de .env
```

**Requisitos:**
- Router ya instalado
- Archivo `.env` configurado

### `restart_all.sh` - Reinicio completo
Reinicia todos los servicios manteniendo configuración.

```bash
./restart_all.sh                # Reiniciar sistema
```

**Nota:** Llama internamente a `stop_all.sh` para evitar duplicar código.

### `stop_all.sh` - Detener todo
Detiene todos los servicios y limpia recursos.

```bash
./stop_all.sh
```

**Acciones:**
- Detiene procesos Python (dashboard, firewall, modelo, captura)
- Detiene router (hostapd, dnsmasq)
- Limpia PIDs y logs

### `config_manager.sh` - Gestor de configuración
Herramienta interactiva para modificar `.env`.

```bash
./config_manager.sh                           # Modo interactivo
./config_manager.sh VARIABLE valor            # Modo directo
```

**Opciones:**
1. Cambiar modo de captura
2. Configurar interfaces
3. Configurar WiFi
4. Configurar red AP
5. Ajustar buffers y tiempos

---

## 🌐 URLs de Acceso

Una vez iniciado el sistema:

| Servicio | URL |
|----------|-----|
| Dashboard Router | http://192.168.50.1:8081 |
| Firewall API | http://192.168.50.1:5000/health |
| Modelo ML | http://localhost:5001 |
| Modelo Simulado | http://localhost:8000 |
| Dashboard Modelo | http://localhost:5001/ |

---

## 📊 API del Firewall

### Obtener estado
```bash
GET http://192.168.50.1:5000/health
```

### Bloquear IP
```bash
POST http://192.168.50.1:5000/block
Content-Type: application/json

{
  "ip": "192.168.50.25",
  "category": "malware"
}
```

### Desbloquear IP
```bash
POST http://192.168.50.1:5000/unblock
Content-Type: application/json

{
  "ip": "192.168.50.25"
}
```

### Listar IPs bloqueadas
```bash
GET http://192.168.50.1:5000/blocked
```

### Activar/Desactivar categoría
```bash
POST http://192.168.50.1:5000/category/malware/activate
POST http://192.168.50.1:5000/category/malware/deactivate
```

---

## 🔧 Troubleshooting

### El sistema no inicia
```bash
# Ver logs
tail -f /tmp/model_server.log
tail -f /tmp/firewall.log
tail -f /tmp/dashboard.log
tail -f /tmp/traffic_capture.log

# Verificar procesos
ps aux | grep python3 | grep -E "model_server|firewall|dashboard|traffic_capture"
```

### Interfaces no detectadas
```bash
# Listar interfaces disponibles
ip link show

# Editar .env con interfaces correctas
nano .env

# Reiniciar
sudo ./restart_all.sh
```

### Modelo no carga
```bash
# Verificar archivos del modelo
ls -la model_ml/*.pkl

# Para model_ml: verificar entorno virtual
ls -la model_ml/ml/

# Para simulated-model: verificar dependencias
pip3 install -r simulated-model/requirements.txt
```

### Cambios en .env no se aplican
```bash
# Verificar configuración actual
python3 router-system/config.py

# Reiniciar sistema
sudo ./restart_all.sh
```

### Error "Model not loaded"
```bash
# Para model_ml
cd model_ml
./ml/bin/pip install -r requirements.txt

# Verificar archivos
ls -la *.pkl
```

### Puerto ocupado
```bash
# Ver qué proceso usa el puerto
sudo lsof -i :5001
sudo lsof -i :8000
sudo lsof -i :5002

# Detener todo y reiniciar
./stop_all.sh
sudo ./quick_start.sh
```

---

## 📁 Estructura del Proyecto

```
firewall/
├── .env                        # Configuración principal
├── .env.example                # Plantilla de configuración
├── README.md                   # Este archivo
├── init_all.sh                 # Instalación completa
├── quick_start.sh              # Inicio rápido
├── restart_all.sh              # Reinicio
├── stop_all.sh                 # Detener todo
├── config_manager.sh           # Gestor de configuración
│
├── router-system/              # Sistema de router
│   ├── config.py              # Carga de configuración
│   ├── dashboard.py           # Dashboard web
│   ├── firewall_manager.py    # Gestión del firewall
│   ├── traffic_capture.py     # Captura de flows
│   ├── traffic_capture_packets.py  # Captura de packets
│   ├── router-control.sh      # Control del router
│   └── install.sh             # Instalador del router
│
├── model_ml/                   # Modelo Random Forest
│   ├── model_server.py        # Servidor del modelo
│   ├── requirements.txt       # Dependencias
│   ├── *.pkl                  # Archivos del modelo
│   └── ml/                    # Entorno virtual
│
├── simulated-model/            # Modelo simulado
│   ├── model_server.py        # Servidor simulado
│   └── requirements.txt       # Dependencias
│
└── model_dl/                   # Modelo Deep Learning (futuro)
    └── ...
```

---

## 📝 Notas Importantes

### Diferencias entre Scripts de Captura

**traffic_capture.py (FLOWS)**
- Calcula 79 features por flow (CICFlowMeter)
- Envía estadísticas agregadas
- Menor uso de ancho de banda
- Compatible con: ml_flows, simulated_flows

**traffic_capture_packets.py (PACKETS)**
- Envía archivos PCAP completos
- Mayor detalle de información
- Mayor uso de ancho de banda
- Compatible con: dl_packets

### Compatibilidad con Modelos

El sistema detecta automáticamente qué script usar según `MODEL_TYPE`:
- `ml_flows` → usa `traffic_capture.py`
- `simulated_flows` → usa `traffic_capture.py`
- `dl_packets` → usa `traffic_capture_packets.py`

### Logs

Todos los logs se guardan en `/tmp/`:
```bash
/tmp/model_server.log      # Modelo ML
/tmp/model.log             # Modelo simulado
/tmp/firewall.log          # Firewall manager
/tmp/dashboard.log         # Dashboard
/tmp/traffic_capture.log   # Captura de tráfico
```

---

## 🔐 Seguridad

- El archivo `.env` contiene información sensible y está excluido de git
- Usa `.env.example` como plantilla
- Cambia `WIFI_PASSWORD` por defecto
- Las contraseñas deben tener mínimo 8 caracteres

---

## 📄 Licencia

Este proyecto es parte del laboratorio TMA - UPC.
