# 🛡️ ARES AEGIS - GUÍA DE INSTALACIÓN Y USO COMPLETA

## 📋 **RESUMEN EJECUTIVO**

Ares Aegis es un **escáner de seguridad avanzado** diseñado específicamente para **Kali Linux**, que proporciona capacidades completas de:

- ✅ **Escaneo de vulnerabilidades** (Red y Sistema)
- ✅ **Monitoreo de integridad de archivos (FIM)**
- ✅ **Sistema de eventos de seguridad (SIEM)**
- ✅ **Auditoría de seguridad automatizada**
- ✅ **Cuarentena automática de amenazas**
- ✅ **Interfaz gráfica tema Burp Suite**

---

## 🚀 **INSTALACIÓN RÁPIDA**

### **Paso 1: Clonar/Descargar Ares Aegis**
```bash
# Si tienes git
git clone <repositorio-ares-aegis>
cd ares-aegis

# O descomprimir si tienes el archivo
tar -xzf ares-aegis-data.tar.gz
cd Ares-Aegis
```

### **Paso 2: Configurar Kali Linux**
```bash
# Ejecutar configuración automatizada
sudo chmod +x configurar_kali.sh
sudo ./configurar_kali.sh
```

### **Paso 3: Instalar Dependencias Python**
```bash
# Crear entorno virtual
python3 -m venv venv_ares_aegis
source venv_ares_aegis/bin/activate

# Instalar dependencias mínimas
pip install -r requirements.txt
```

### **Paso 4: Ejecutar Ares Aegis**
```bash
# Login y verificación de permisos
python3 login.py

# O ejecutar directamente
sudo python3 main.py
```

---

## 🔧 **CONFIGURACIÓN AVANZADA**

### **Verificar Instalación**
```bash
# Verificar herramientas instaladas
python3 verificar.py

# Auditoría de seguridad
python3 auditoria_seguridad.py

# Suite de tests
python3 test_suite_completo.py
```

### **Configuración de Permisos**
```bash
# Configurar sudo sin contraseña para herramientas específicas
sudo ./configurar_kali.sh

# Verificar permisos manualmente
python3 verificacion_permisos.py
```

---

## 📖 **GUÍA DE USO**

### **1. Escaneo de Red**
```python
# Desde la interfaz gráfica
# 1. Ejecutar: python3 main.py
# 2. Ir a "Escáner" > "Escaneo de Red"
# 3. Introducir objetivo: 192.168.1.0/24
# 4. Seleccionar tipo de escaneo
# 5. Ejecutar
```

### **2. Auditoría de Sistema**
```python
# Auditoría completa con Lynis + rkhunter
# 1. "Auditoría" > "Auditoría Completa"
# 2. Revisar resultados en tiempo real
# 3. Exportar reporte
```

### **3. Monitoreo FIM**
```python
# Monitoreo de integridad de archivos
# 1. "FIM" > "Iniciar Monitoreo"
# 2. Agregar rutas críticas
# 3. Ver alertas en tiempo real
```

### **4. Sistema SIEM**
```python
# Análisis de logs y eventos
# 1. "SIEM" > "Iniciar Monitoreo"
# 2. Configurar fuentes de logs
# 3. Ver correlación de eventos
```

---

## 🛠️ **CARACTERÍSTICAS TÉCNICAS**

### **Arquitectura**
- **Patrón MVC**: Modelo-Vista-Controlador
- **Asíncrono**: Threading para operaciones concurrentes
- **Modular**: Componentes intercambiables
- **Seguro**: Validación robusta de entrada

### **Dependencias**
- **Python 3.8+**: Lenguaje principal
- **tkinter**: Interfaz gráfica nativa
- **psutil**: Información del sistema
- **watchdog**: Monitoreo de archivos
- **Herramientas Kali**: nmap, lynis, rkhunter, etc.

### **Seguridad**
- ✅ **Validación de entrada** robusta
- ✅ **Sanitización** de comandos
- ✅ **Whitelist** de herramientas permitidas
- ✅ **Prevención** de inyección de comandos
- ✅ **Auditoría** automatizada de seguridad

---

## 📁 **ESTRUCTURA DEL PROYECTO**

```
Ares-Aegis/
├── 🐍 main.py                    # Punto de entrada principal
├── 🔐 login.py                   # Sistema de autenticación
├── 📋 requirements.txt           # Dependencias Python
├── ⚙️ configurar_kali.sh         # Configuración Kali
│
├── 🧠 ares_aegis/                # Código principal
│   ├── 🎮 controlador/           # Lógica de control
│   │   ├── controlador_principal.py
│   │   ├── controlador_escaneador.py
│   │   ├── controlador_auditoria.py
│   │   ├── controlador_fim.py
│   │   └── controlador_siem.py
│   │
│   ├── 🏗️ modelo/                # Lógica de negocio
│   │   ├── escaneador.py
│   │   ├── cuarentena.py
│   │   ├── fim.py
│   │   └── siem.py
│   │
│   ├── 🎨 vista/                 # Interfaz gráfica
│   │   ├── interfaz_principal.py
│   │   ├── componentes_ui/
│   │   └── vistas/
│   │
│   └── 🔧 utils/                 # Utilidades
│       ├── gestor_permisos.py
│       └── temas_kali.py
│
├── ⚙️ configuracion/             # Archivos de configuración
├── 📊 data/                      # Datos y wordlists
├── 🗂️ recursos/                 # Recursos gráficos
├── 📋 docs/                      # Documentación
└── 🧪 tests/                     # Tests automatizados
```

---

## 🔍 **CASOS DE USO**

### **Pentester Profesional**
```bash
# Auditoría completa de red corporativa
1. Escaneo de red: 10.0.0.0/8
2. Auditoría de sistemas críticos
3. Monitoreo FIM en servidores
4. Análisis SIEM de logs
5. Reporte ejecutivo automatizado
```

### **Administrador de Sistemas**
```bash
# Monitoreo continuo de seguridad
1. FIM en archivos críticos (/etc/)
2. SIEM para logs de autenticación
3. Auditoría programada diaria
4. Alertas automáticas
```

### **Investigador de Seguridad**
```bash
# Análisis forense
1. Escaneo de vulnerabilidades
2. Análisis de malware (cuarentena)
3. Correlación de eventos SIEM
4. Auditoría post-incidente
```

---

## 🚨 **RESOLUCIÓN DE PROBLEMAS**

### **Error: "Herramientas no encontradas"**
```bash
# Instalar herramientas faltantes
sudo apt update
sudo apt install nmap lynis rkhunter chkrootkit

# Verificar instalación
which nmap lynis rkhunter
```

### **Error: "Permisos insuficientes"**
```bash
# Configurar permisos sudo
sudo ./configurar_kali.sh

# Verificar permisos
sudo -l | grep nmap
```

### **Error: "Módulo no encontrado"**
```bash
# Activar entorno virtual
source venv_ares_aegis/bin/activate

# Reinstalar dependencias
pip install -r requirements.txt
```

### **Error: "Interfaz no se muestra"**
```bash
# Verificar X11
echo $DISPLAY

# Instalar tkinter si falta
sudo apt install python3-tk
```

---

## 🔐 **CONFIGURACIÓN DE SEGURIDAD**

### **Permisos Recomendados**
```bash
# Archivos Python
chmod 644 ares_aegis/*.py

# Scripts ejecutables
chmod 755 *.sh

# Configuraciones sensibles
chmod 600 configuracion/*.json

# Directorios
chmod 755 ares_aegis/ data/ recursos/
```

### **Configuración Firewall**
```bash
# Permitir solo lo necesario
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -j DROP
```

---

## 📈 **MONITOREO Y LOGS**

### **Ubicaciones de Logs**
```bash
# Logs de aplicación
/var/log/ares_aegis/

# Logs del sistema (monitoreados por SIEM)
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
```

### **Comandos de Monitoreo**
```bash
# Ver logs en tiempo real
tail -f /var/log/ares_aegis/aplicacion.log

# Buscar eventos críticos
grep "CRITICO" /var/log/ares_aegis/*.log

# Estadísticas SIEM
grep "SIEM" /var/log/ares_aegis/eventos.log | wc -l
```

---

## 🤝 **SOPORTE Y CONTRIBUCIÓN**

### **Reportar Bugs**
1. Ejecutar auditoría: `python3 auditoria_seguridad.py`
2. Ejecutar tests: `python3 test_suite_completo.py`
3. Recopilar logs relevantes
4. Crear issue con detalles completos

### **Contribuir**
1. Fork del proyecto
2. Crear rama feature: `git checkout -b feature/nueva-funcionalidad`
3. Ejecutar tests: `python3 test_suite_completo.py`
4. Crear pull request

### **Documentación**
- **Código**: Comentarios inline en español
- **API**: Docstrings detallados
- **Arquitectura**: Diagramas en `docs/`

---

## 📜 **LICENCIA Y CRÉDITOS**

**Ares Aegis** - Escáner de Seguridad para Kali Linux
- **Autor**: DogSoulDev
- **Fecha**: 15 de Agosto de 2025
- **Versión**: 1.0
- **Licencia**: [Especificar licencia]

### **Herramientas Integradas**
- **nmap**: Escaneo de red
- **lynis**: Auditoría de sistema
- **rkhunter**: Detección de rootkits
- **ClamAV**: Antivirus
- **Python**: Desarrollo principal

---

## 🎯 **ROADMAP FUTURO**

### **Versión 1.1**
- [ ] **API REST** para integración
- [ ] **Base de datos** PostgreSQL
- [ ] **Dashboard web** avanzado
- [ ] **Machine Learning** para detección

### **Versión 1.2**
- [ ] **Integración** con MISP
- [ ] **Plugins** personalizados
- [ ] **Reportes** automatizados
- [ ] **Clusters** distribuidos

---

## ⚡ **COMANDOS RÁPIDOS**

```bash
# Instalación completa
sudo ./configurar_kali.sh && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt

# Ejecutar con todos los checks
python3 verificar.py && python3 auditoria_seguridad.py && python3 main.py

# Auditoría rápida
python3 -c "from ares_aegis.controlador.controlador_auditoria import ControladorAuditoria; print(ControladorAuditoria(None).ejecutar_auditoria_completa())"

# Test rápido
python3 test_suite_completo.py

# Limpieza
deactivate && rm -rf venv_ares_aegis __pycache__ *.pyc
```

---

## 📞 **CONTACTO**

- **GitHub**: [Repositorio del proyecto]
- **Email**: [Contacto de soporte]
- **Documentación**: `docs/`
- **Wiki**: [URL del wiki]

---

**¡Bienvenido a Ares Aegis - Tu escudo de seguridad en Kali Linux! 🛡️**
