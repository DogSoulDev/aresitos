# -*- coding: utf-8 -*-
"""
ARESITOS - Definiciones de Herramientas Kali Linux 2025
======================================================

Definiciones de todas las herramientas de Kali Linux categorizadas
por módulo ARESITOS y funcionalidad específica.

Cada herramienta incluye:
- descripcion: Descripción técnica
- paquete: Nombre del paquete para instalación
- esencial: Si es crítica para ARESITOS
- uso_aresitos: Cómo se integra específicamente en ARESITOS
- modulo_aresitos: En qué módulo de ARESITOS se usa
- instalacion_especial: Método de instalación (apt, snap, go, github)

Autor: DogSoulDev
Fecha: 18 de Agosto de 2025
"""

def get_herramientas_kali_2025():
    """
    Retorna el diccionario completo de herramientas categorizadas
    para ARESITOS con integración específica por módulo.
    """
    return {
        "📡 Escaneo y Reconocimiento": {
            # MOTOR PRINCIPAL DEL ESCANEADOR ARESITOS
            "nmap": {
                "descripcion": "Network exploration tool and security/port scanner",
                "paquete": "nmap",
                "esencial": True,
                "uso_aresitos": "Motor principal del escaneador ARESITOS - detección de servicios, OS fingerprinting",
                "modulo_aresitos": "escaneador",
                "integracion": "Ejecuta escaneos automáticos programados, genera reportes para SIEM"
            },
            
            # ESCANEO RÁPIDO PARA REDES GRANDES
            "masscan": {
                "descripcion": "TCP port scanner, spews SYN packets asynchronously",
                "paquete": "masscan",
                "esencial": True,
                "uso_aresitos": "Escaneo inicial rápido para reconocimiento de redes grandes",
                "modulo_aresitos": "escaneador",
                "integracion": "Pre-escaneo para identificar hosts activos antes de nmap detallado"
            },
            
            # NUEVO 2025: SCANNER MODERNO EN RUST
            "rustscan": {
                "descripcion": "Modern port scanner built in Rust (faster than nmap)",
                "paquete": "rustscan",
                "esencial": True,
                "uso_aresitos": "Escaneo ultra-rápido para networks grandes - complementa a masscan",
                "modulo_aresitos": "escaneador",
                "instalacion_especial": "snap",
                "integracion": "Scanner primario para entornos de alta velocidad, feed a nmap para detalles"
            },
            
            # DESCUBRIMIENTO WEB MODERNO
            "gobuster": {
                "descripcion": "Directory/File, DNS and VHost busting tool",
                "paquete": "gobuster",
                "esencial": True,
                "uso_aresitos": "Enumeración de directorios web integrada en escaneador automático",
                "modulo_aresitos": "escaneador",
                "integracion": "Ejecuta automáticamente cuando detecta servicios HTTP/HTTPS"
            },
            
            # NUEVO 2025: FEROXBUSTER - MÁS RÁPIDO QUE GOBUSTER
            "feroxbuster": {
                "descripcion": "Fast content discovery tool written in Rust",
                "paquete": "feroxbuster",
                "esencial": True,
                "uso_aresitos": "Descubrimiento de contenido web moderno - más rápido que gobuster",
                "modulo_aresitos": "escaneador",
                "integracion": "Alternativa de alta velocidad a gobuster para aplicaciones web grandes"
            },
            
            # ANÁLISIS WEB CLÁSICO
            "nikto": {
                "descripcion": "Web server scanner",
                "paquete": "nikto",
                "esencial": True,
                "uso_aresitos": "Análisis de vulnerabilidades web - integrado en escaneos automáticos",
                "modulo_aresitos": "escaneador",
                "integracion": "Ejecuta automáticamente en servicios web detectados, reporta a SIEM"
            },
            
            # MOTOR DE VULNERABILIDADES MODERNO
            "nuclei": {
                "descripcion": "Fast and customizable vulnerability scanner",
                "paquete": "nuclei",
                "esencial": True,
                "uso_aresitos": "Motor principal de detección de vulnerabilidades con templates actualizados",
                "modulo_aresitos": "escaneador",
                "integracion": "Escaneo continuo con templates community, alertas automáticas a SIEM"
            },
            
            # NUEVO 2025: CRAWLING AVANZADO
            "katana": {
                "descripcion": "Next-generation crawling and spidering framework",
                "paquete": "katana",
                "esencial": True,
                "uso_aresitos": "Crawling web moderno para mapeo completo de aplicaciones",
                "modulo_aresitos": "escaneador",
                "instalacion_especial": "go",
                "integracion": "Mapea aplicaciones web antes de análisis de vulnerabilidades"
            },
            
            # ENUMERACIÓN DE SUBDOMINIOS
            "subfinder": {
                "descripcion": "Fast subdomains enumeration tool",
                "paquete": "subfinder",
                "esencial": True,
                "uso_aresitos": "Enumeración de subdominios para reconnaissance completo",
                "modulo_aresitos": "escaneador",
                "integracion": "Expande superficie de ataque automáticamente"
            },
            
            # NUEVO 2025: VERIFICACIÓN HTTP RÁPIDA
            "httpx": {
                "descripcion": "Fast and multi-purpose HTTP toolkit",
                "paquete": "httpx",
                "esencial": True,
                "uso_aresitos": "Verificación y análisis HTTP rápido de dominios encontrados",
                "modulo_aresitos": "escaneador",
                "instalacion_especial": "go",
                "integracion": "Valida servicios web activos antes de análisis profundo"
            },
            
            # FUZZING WEB MODERNO
            "ffuf": {
                "descripcion": "Fast web fuzzer written in Go",
                "paquete": "ffuf",
                "esencial": True,
                "uso_aresitos": "Fuzzing web moderno integrado en pipeline de escaneador",
                "modulo_aresitos": "escaneador",
                "integracion": "Fuzzing automático de parámetros y endpoints"
            }
        },
        
        "⚔️ Explotación": {
            # FRAMEWORK PRINCIPAL
            "metasploit-framework": {
                "descripcion": "Penetration testing framework",
                "paquete": "metasploit-framework",
                "esencial": True,
                "uso_aresitos": "Framework principal de explotación - validación de vulnerabilidades",
                "modulo_aresitos": "escaneador",
                "integracion": "Valida vulnerabilidades encontradas por nuclei/nmap"
            },
            
            # INYECCIONES SQL
            "sqlmap": {
                "descripcion": "Automatic SQL injection and database takeover tool",
                "paquete": "sqlmap",
                "esencial": True,
                "uso_aresitos": "Testing automático de inyecciones SQL en aplicaciones web",
                "modulo_aresitos": "escaneador",
                "integracion": "Ejecuta automáticamente en formularios web detectados"
            },
            
            # FUERZA BRUTA
            "hydra": {
                "descripcion": "Very fast network logon cracker",
                "paquete": "hydra",
                "esencial": True,
                "uso_aresitos": "Ataques de fuerza bruta para validación de credenciales débiles",
                "modulo_aresitos": "escaneador",
                "integracion": "Testing automático de credenciales por defecto"
            },
            
            # CRACKING DE PASSWORDS
            "john": {
                "descripcion": "John the Ripper password cracker",
                "paquete": "john",
                "esencial": True,
                "uso_aresitos": "Análisis de passwords en archivos encontrados en cuarentena",
                "modulo_aresitos": "cuarentena",
                "integracion": "Analiza archivos de passwords en cuarentena automáticamente"
            },
            
            "hashcat": {
                "descripcion": "Advanced password recovery",
                "paquete": "hashcat",
                "esencial": True,
                "uso_aresitos": "Cracking GPU de hashes para análisis forense",
                "modulo_aresitos": "cuarentena",
                "integracion": "Procesa hashes encontrados en malware análisis"
            },
            
            # PENTESTING DE REDES
            "crackmapexec": {
                "descripcion": "Swiss army knife for pentesting networks",
                "paquete": "crackmapexec",
                "esencial": True,
                "uso_aresitos": "Pentesting automático de redes Windows/Linux detectadas",
                "modulo_aresitos": "escaneador",
                "integracion": "Testing automático de dominios Windows detectados"
            },
            
            # SCRIPTS DE RED
            "impacket-scripts": {
                "descripcion": "Collection of Python classes for working with network protocols",
                "paquete": "impacket-scripts",
                "esencial": True,
                "uso_aresitos": "Scripts de red y Active Directory para pentesting automático",
                "modulo_aresitos": "escaneador",
                "integracion": "Enumeración automática de servicios Windows"
            },
            
            # NUEVO 2025: ANÁLISIS DE AD
            "bloodhound": {
                "descripcion": "Six Degrees of Domain Admin",
                "paquete": "bloodhound",
                "esencial": True,
                "uso_aresitos": "Análisis de Active Directory para detección de privilege escalation",
                "modulo_aresitos": "escaneador",
                "integracion": "Mapea automáticamente dominios Windows para vulnerabilidades"
            },
            
            # NUEVO 2025: SHELL WINDOWS
            "evil-winrm": {
                "descripcion": "Windows Remote Management shell",
                "paquete": "evil-winrm",
                "esencial": True,
                "uso_aresitos": "Shell remoto para Windows en testing de seguridad",
                "modulo_aresitos": "escaneador",
                "integracion": "Testing de WinRM en hosts Windows detectados"
            }
        },
        
        "🔗 Post-Explotación": {
            "netcat-openbsd": {
                "descripcion": "TCP/IP swiss army knife - OpenBSD variant",
                "paquete": "netcat-openbsd",
                "esencial": True,
                "uso_aresitos": "Conexiones de red para testing y debugging del escaneador",
                "modulo_aresitos": "escaneador",
                "integracion": "Herramienta de debugging para conexiones de red"
            },
            
            "socat": {
                "descripcion": "Multipurpose relay",
                "paquete": "socat",
                "esencial": True,
                "uso_aresitos": "Tunneling y redirección para testing complejo",
                "modulo_aresitos": "escaneador",
                "integracion": "Proxy para testing de servicios internos"
            },
            
            "proxychains4": {
                "descripcion": "Proxy chains - redirect connections through proxy servers",
                "paquete": "proxychains4",
                "esencial": True,
                "uso_aresitos": "Anonimización de conexiones del escaneador",
                "modulo_aresitos": "escaneador",
                "integracion": "Escaneos anónimos a través de proxies"
            },
            
            "chisel": {
                "descripcion": "Fast TCP/UDP tunnel over HTTP",
                "paquete": "chisel",
                "esencial": True,
                "uso_aresitos": "Tunneling HTTP para acceso a redes internas",
                "modulo_aresitos": "escaneador",
                "integracion": "Acceso a servicios internos durante pentesting"
            },
            
            # NUEVO 2025: TUNNELING AVANZADO
            "ligolo-ng": {
                "descripcion": "Advanced tunneling tool that uses TUN interfaces",
                "paquete": "ligolo-ng",
                "esencial": True,
                "uso_aresitos": "Tunneling avanzado con interfaces TUN para redes complejas",
                "modulo_aresitos": "escaneador",
                "instalacion_especial": "github",
                "integracion": "Pivoting avanzado en redes multi-segmento"
            },
            
            # NUEVO 2025: C2 FRAMEWORK MODERNO
            "sliver": {
                "descripcion": "Adversary emulation framework",
                "paquete": "sliver",
                "esencial": True,
                "uso_aresitos": "C2 framework moderno para testing avanzado de detección",
                "modulo_aresitos": "escaneador",
                "instalacion_especial": "github",
                "integracion": "Testing de capacidades de detección del SIEM"
            }
        },
        
        "🔍 Análisis Forense": {
            "binwalk": {
                "descripcion": "Tool for analyzing binary images",
                "paquete": "binwalk",
                "esencial": False,
                "uso_aresitos": "Análisis de archivos binarios sospechosos en cuarentena",
                "modulo_aresitos": "cuarentena",
                "integracion": "Análisis automático de binarios en cuarentena"
            },
            
            "volatility3": {
                "descripcion": "Memory forensics framework (Python 3 version)",
                "paquete": "volatility3",
                "esencial": True,
                "uso_aresitos": "Análisis de memoria para detección de malware avanzado",
                "modulo_aresitos": "cuarentena",
                "integracion": "Análisis de dumps de memoria en incidentes"
            },
            
            # NUEVO 2025: DETECCIÓN DE PATRONES
            "yara": {
                "descripcion": "Pattern matching engine for malware research",
                "paquete": "yara",
                "esencial": True,
                "uso_aresitos": "Motor de detección de patrones de malware en cuarentena",
                "modulo_aresitos": "cuarentena",
                "integracion": "Escaneo automático con reglas YARA actualizadas"
            },
            
            # NUEVO 2025: ANÁLISIS DE METADATOS
            "exiftool": {
                "descripcion": "Tool for reading and writing meta information in files",
                "paquete": "exiftool",
                "esencial": True,
                "uso_aresitos": "Análisis de metadatos en archivos sospechosos para forensics",
                "modulo_aresitos": "cuarentena",
                "integracion": "Extracción automática de metadatos de archivos en cuarentena"
            }
        },
        
        "📊 SIEM y Monitoreo": {
            "auditd": {
                "descripcion": "Linux Audit Framework",
                "paquete": "auditd",
                "esencial": True,
                "uso_aresitos": "Motor de auditoría principal para SIEM ARESITOS",
                "modulo_aresitos": "siem",
                "integracion": "Genera eventos para correlación en SIEM"
            },
            
            "rsyslog": {
                "descripcion": "Reliable system log daemon",
                "paquete": "rsyslog",
                "esencial": True,
                "uso_aresitos": "Gestión centralizada de logs para SIEM",
                "modulo_aresitos": "siem",
                "integracion": "Centraliza todos los logs del sistema para análisis"
            },
            
            "fail2ban": {
                "descripcion": "Ban hosts that cause multiple authentication errors",
                "paquete": "fail2ban",
                "esencial": True,
                "uso_aresitos": "Protección automática contra ataques - integrado con SIEM",
                "modulo_aresitos": "siem",
                "integracion": "Respuesta automática a eventos del SIEM"
            },
            
            # NUEVO 2025: CONSULTAS SQL DEL SISTEMA
            "osquery": {
                "descripcion": "SQL powered operating system instrumentation framework",
                "paquete": "osquery",
                "esencial": True,
                "uso_aresitos": "Consultas SQL sobre el sistema para SIEM avanzado",
                "modulo_aresitos": "siem",
                "integracion": "Queries automatizadas para detección de anomalías"
            },
            
            # NUEVO 2025: ENVÍO DE LOGS
            "filebeat": {
                "descripcion": "Lightweight shipper for forwarding and centralizing log data",
                "paquete": "filebeat",
                "esencial": True,
                "uso_aresitos": "Envío eficiente de logs al SIEM ARESITOS",
                "modulo_aresitos": "siem",
                "integracion": "Pipeline optimizado de logs hacia SIEM central"
            },
            
            # NUEVO 2025: IDS/IPS MODERNO
            "suricata": {
                "descripcion": "Network threat detection engine",
                "paquete": "suricata",
                "esencial": True,
                "uso_aresitos": "IDS/IPS para detección de amenazas de red en tiempo real",
                "modulo_aresitos": "siem",
                "integracion": "Detección de red complementaria al escaneador"
            }
        },
        
        "🛡️ FIM y Sistema": {
            "inotify-tools": {
                "descripcion": "Command-line programs providing a simple interface to inotify",
                "paquete": "inotify-tools",
                "esencial": True,
                "uso_aresitos": "Motor principal de monitoreo de archivos FIM ARESITOS",
                "modulo_aresitos": "fim",
                "integracion": "Monitoreo en tiempo real de cambios en archivos críticos"
            },
            
            "aide": {
                "descripcion": "Advanced Intrusion Detection Environment",
                "paquete": "aide",
                "esencial": True,
                "uso_aresitos": "Sistema de detección de cambios integrado en FIM",
                "modulo_aresitos": "fim",
                "integracion": "Verificación de integridad programada complementaria"
            },
            
            "chkrootkit": {
                "descripcion": "Rootkit detector",
                "paquete": "chkrootkit",
                "esencial": True,
                "uso_aresitos": "Detección de rootkits integrada en FIM y SIEM",
                "modulo_aresitos": "fim",
                "integracion": "Escaneos automáticos programados, alertas a SIEM"
            },
            
            "rkhunter": {
                "descripcion": "Rootkit scanner",
                "paquete": "rkhunter",
                "esencial": True,
                "uso_aresitos": "Búsqueda de rootkits y backdoors en FIM",
                "modulo_aresitos": "fim",
                "integracion": "Complementa chkrootkit con diferentes técnicas de detección"
            },
            
            "clamav": {
                "descripcion": "Antivirus scanner for Unix",
                "paquete": "clamav clamav-daemon clamav-freshclam",
                "esencial": True,
                "uso_aresitos": "Motor antivirus principal para cuarentena ARESITOS",
                "modulo_aresitos": "cuarentena",
                "integracion": "Escaneo en tiempo real de archivos, cuarentena automática"
            },
            
            "lynis": {
                "descripcion": "Security auditing tool for Linux/Unix systems",
                "paquete": "lynis",
                "esencial": True,
                "uso_aresitos": "Auditoría completa de seguridad del sistema para SIEM",
                "modulo_aresitos": "siem",
                "integracion": "Auditorías programadas, reportes automáticos al SIEM"
            }
        },
        
        "🛠️ Herramientas del Sistema": {
            "curl": {
                "descripcion": "Command line tool for transferring data",
                "paquete": "curl",
                "esencial": True,
                "uso_aresitos": "Transferencia de datos y testing web en escaneador",
                "modulo_aresitos": "escaneador",
                "integracion": "Testing de endpoints HTTP en escaneos"
            },
            
            "wget": {
                "descripcion": "Network downloader",
                "paquete": "wget",
                "esencial": True,
                "uso_aresitos": "Descarga de actualizaciones y recursos",
                "modulo_aresitos": "sistema",
                "integracion": "Actualizaciones automáticas de reglas y definiciones"
            },
            
            "git": {
                "descripcion": "Fast, scalable, distributed revision control system",
                "paquete": "git",
                "esencial": True,
                "uso_aresitos": "Control de versiones y actualizaciones de ARESITOS",
                "modulo_aresitos": "sistema",
                "integracion": "Actualizaciones automáticas del código y reglas"
            },
            
            "python3-pip": {
                "descripcion": "Python package installer",
                "paquete": "python3-pip",
                "esencial": True,
                "uso_aresitos": "Instalación de dependencias Python de ARESITOS",
                "modulo_aresitos": "sistema",
                "integracion": "Gestión automática de dependencias"
            },
            
            "jq": {
                "descripcion": "Command-line JSON processor",
                "paquete": "jq",
                "esencial": True,
                "uso_aresitos": "Procesamiento de JSON en reportes y configuraciones",
                "modulo_aresitos": "sistema",
                "integracion": "Parsing de respuestas API y configuraciones"
            },
            
            "tmux": {
                "descripcion": "Terminal multiplexer",
                "paquete": "tmux",
                "esencial": True,
                "uso_aresitos": "Multiplexor de terminal para sesiones de escaneo",
                "modulo_aresitos": "escaneador",
                "integracion": "Gestión de sesiones de escaneo de larga duración"
            },
            
            "vim": {
                "descripcion": "Vi IMproved - enhanced vi editor",
                "paquete": "vim",
                "esencial": True,
                "uso_aresitos": "Editor para configuraciones y análisis de logs",
                "modulo_aresitos": "sistema",
                "integracion": "Edición de configuraciones y reglas"
            }
        }
    }
