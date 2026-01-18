# Scripts de Gestión del Sistema

Este directorio contiene varios scripts para gestionar el sistema router/firewall con clasificación IoT.

## 📜 Scripts Disponibles

### 🚀 `quick_start.sh` (RECOMENDADO)
**Inicio rápido sin instalación**

Inicia los servicios del sistema (modelo + router) sin ejecutar el proceso de instalación interactivo.

```bash
# Iniciar con model_ml (por defecto)
sudo ./quick_start.sh

# Iniciar con simulated-model
sudo ./quick_start.sh simulated
```

**Requisitos previos:**
- El router debe estar instalado (`/etc/router-system` debe existir)
- El entorno virtual del modelo debe estar creado
- Los archivos del modelo deben existir (`model.pkl`, `encoder.pkl`)

**Ventajas:**
- ✅ No requiere interacción del usuario
- ✅ Rápido (solo arranca servicios)
- ✅ Verifica que todo esté instalado antes de iniciar

---

### 🏗️ `init_all.sh`
**Inicialización completa desde cero**

Realiza una instalación y configuración completa del sistema, incluyendo la instalación del router.

```bash
# Instalación completa con model_ml
sudo ./init_all.sh

# Instalación completa con simulated-model
sudo ./init_all.sh simulated

# Forzar reinstalación del router
sudo ./init_all.sh --reinstall
```

**Características:**
1. Limpia servicios anteriores
2. Instala dependencias del modelo
3. Instala/verifica router-system (automático si ya existe)
4. Inicia el modelo
5. Inicia router-system

**Nota:** Si el router ya está instalado, salta la instalación automáticamente. Usa `--reinstall` para forzar reinstalación.

---

### 🔄 `restart_all.sh`
**Reinicio rápido de todos los servicios**

Detiene y reinicia todos los servicios manteniendo la configuración existente.

```bash
# Reiniciar con model_ml
./restart_all.sh

# Reiniciar con simulated-model
./restart_all.sh simulated
```

**Útil para:**
- Aplicar cambios en el código
- Reiniciar después de un crash
- Cambiar entre modelos

---

### 🛑 `stop_all.sh`
**Detener todos los servicios**

Detiene completamente el sistema y limpia recursos.

```bash
./stop_all.sh
```

**Acciones:**
- Detiene todos los procesos Python
- Detiene router y servicios de red
- Limpia archivos PID
- Limpia logs

---

## 🎯 Flujo de Trabajo Recomendado

### Primera vez (instalación completa):
```bash
# 1. Instalar todo desde cero
sudo ./init_all.sh

# 2. Verificar que todo funciona
curl http://localhost:5001/health
curl http://192.168.50.1:5000/health
```

### Uso diario:
```bash
# Iniciar el sistema
sudo ./quick_start.sh

# Detener el sistema
./stop_all.sh

# Reiniciar después de cambios
./restart_all.sh
```

### Desarrollo:
```bash
# Detener todo
./stop_all.sh

# Hacer cambios en el código...

# Reiniciar para probar
./restart_all.sh
```

---

## 🔧 Configuración de Modelos

### Model ML (por defecto)
- **Puerto:** 5001
- **Archivos requeridos:**
  - `model_ml/model.pkl` (o `iot_device_classifier_rf.pkl`)
  - `model_ml/encoder.pkl` (o `label_encoder.pkl`)
  - `model_ml/ml/` (entorno virtual)
- **Log:** `/tmp/model_server.log`

### Simulated Model
- **Puerto:** 8000
- **Archivos requeridos:**
  - `simulated-model/model_server.py`
- **Log:** `/tmp/model.log`

---

## 📊 URLs del Sistema

Después de iniciar el sistema:

| Servicio | URL |
|----------|-----|
| Modelo ML | http://localhost:5001 |
| Dashboard Modelo | http://localhost:5001/ |
| Dashboard Router | http://192.168.50.1:8081 |
| Firewall API | http://192.168.50.1:5000/health |
| Modelo Simulado | http://localhost:8000 |

---

## 🐛 Troubleshooting

### El router no está instalado
```bash
# Error: /etc/router-system no existe
cd router-system
sudo ./install.sh
```

### El modelo no carga
```bash
# Verificar archivos
ls -la model_ml/*.pkl

# Ver log
tail -f /tmp/model_server.log
```

### El entorno virtual no existe
```bash
cd model_ml
python3 -m venv ml
./ml/bin/pip install -r requirements.txt
```

### Problema con interfaces de red
```bash
# Listar interfaces
ip link show

# Reinstalar router con nuevas interfaces
sudo ./init_all.sh --reinstall
```

---

## 📝 Logs

Todos los logs están en `/tmp/`:
- `/tmp/model_server.log` - Modelo ML
- `/tmp/model.log` - Modelo simulado
- `/tmp/firewall.log` - Firewall manager
- `/tmp/dashboard.log` - Dashboard

```bash
# Ver logs en tiempo real
tail -f /tmp/model_server.log
tail -f /tmp/firewall.log
```

---

## ⚙️ Variables de Entorno

Los scripts detectan automáticamente:
- **Interfaz AP:** Primera interfaz `wlx*` encontrada
- **Interfaz Internet:** Primera interfaz `wlp*` encontrada
- **Puerto del modelo:** 5001 (ML) o 8000 (simulado)
- **Red local:** Detectada dinámicamente por el modelo

---

## 🔐 Configuración por Defecto

Cuando se usa instalación automática:
- **SSID:** RouterFirewall
- **Password:** SecurePass123
- **Red:** 192.168.50.0/24
- **Gateway:** 192.168.50.1

Para cambiar estos valores, edita el router manualmente o usa `--reinstall`.
